"""Build or verify a small M7 holdout whose labels have observable source evidence."""

import argparse
import hashlib
import json
import tempfile
from collections import Counter
from itertools import pairwise, product, zip_longest
from pathlib import Path

from pydantic import Field

from scripts import evaluate_m6 as m6
from scripts import prepare_m7 as m7
from scripts import prepare_m7_holdout as holdout

PILOT = Path("infra/m7/pilot")
PRIOR = Path("runtime/m7/final-holdout")
LOCAL = Path("runtime/m7/local-oidc-evaluation/observations.jsonl")
REVIEW = Path("runtime/m6/openai-dev-24-hd29g1fr/source-review.json")
MAX_EVENTS = 8
QUESTION = (m6.M7_ENRICHED_QUESTION
            + " Requester and target are observed aliases scoped to this session.")
ACTION_STAGES = {
    "auth_user_deletion_request": "account_management",
    "auth_user_deletion_failed_admin": "account_management",
    "auth_password_change_request": "account_management",
    "auth_password_change_success": "account_management",
    "rp_unregistration": "client_management",
    "rp_unregistration_failed": "client_management",
    "rp_oidc_logout": "logout",
    "op_end_session": "logout",
    "op_session_cleared": "logout",
}


class EvidenceEvent(m7.EnrichedEvent):
    requester: str | None
    target: str | None


class EvidenceSession(m7.EnrichedSession):
    events: list[EvidenceEvent] = Field(min_length=1, max_length=MAX_EVENTS)


def payload(row):
    return row["payload"] or {}


def client_key(row):
    if row["ref"] and row["ref_id"]:
        return "client", row["ref"], row["ref_id"]
    return None


def account_key(value):
    return ("account", value) if value else None


def relations(row):
    kind = row["event_type"]
    actor = account_key(row["action_by"] or row["user_id"])
    if kind.startswith(("auth_user_deletion_", "auth_password_change_")):
        return actor, account_key(row["user_id"])
    return actor, client_key(row)


def ordered_matches(rows, events, *, exact=False):
    groups = [[index for index, row in enumerate(rows)
               if (row["event_type"], row["http_status"]) == event] for event in events]
    if exact and any(len(group) != 1 for group in groups):
        return
    for indices in product(*groups):
        if all(first < second for first, second in pairwise(indices)):
            yield indices


def matching(rows, events, *, exact=False):
    for indices in ordered_matches(rows, events, exact=exact):
        matched = [rows[index] for index in indices]
        actor, target = relations(matched[0])
        if actor and target and all(relations(row) == (actor, target) for row in matched):
            yield indices, matched, actor, target


def source_evidence(rows):
    """Return the first complete operation chain, without reading publisher labels."""
    kinds = {row["event_type"] for row in rows}
    rules = (
        ("protected_admin_deletion", "threat",
         (("auth_user_deletion_request", 200), ("auth_user_deletion_failed_admin", 403)),
         "auth_user_deletion_success"),
        ("protected_client_removal", "threat",
         (("rp_unregistration", 200), ("rp_unregistration_failed", 403)),
         "rp_unregistration_success"),
    )
    for name, label, steps, competing in rules:
        if competing in kinds:
            continue
        for indices, (request, outcome), actor, target in matching(rows, steps, exact=True):
            if request["uri"] != outcome["uri"] or request["client_ip"] != outcome["client_ip"]:
                continue
            if name == "protected_admin_deletion":
                if not request["action_by"] or not outcome["action_by"] or actor == target:
                    continue
            elif (payload(request).get("client_id") != request["ref"]
                  or payload(outcome).get("error") != "protected_client"):
                continue
            return name, label, indices, actor, target

    if any(row["http_status"] >= 400 or row["action_by"] for row in rows):
        return None
    normal = (
        ("oidc_login", (("auth_login_success", 200), ("op_token_request", 200),
                        ("rp_oidc_finalize_success", 302))),
        ("saml_login", (("auth_login_success", 200), ("idp_samlresponse_created", 200),
                        ("sp_login_by_idp", 302))),
        ("oidc_logout", (("rp_oidc_logout", 302), ("op_end_session", 302),
                         ("op_session_cleared", 200))),
        ("self_password_change", (("auth_password_change_request", 200),
                                  ("auth_password_change_success", 200))),
    )
    for name, steps in normal:
        for indices, matched, actor, target in matching(rows, steps, exact=True):
            if name in {"oidc_login", "saml_login"}:
                first = matched[0]
                username = payload(first).get("username")
                attempts = [
                    index for index, row in enumerate(rows[:indices[0]])
                    if row["event_type"] == "auth_login_attempt" and row["http_status"] == 200
                    and payload(row).get("username") == username and client_key(row) == target
                ]
                if not username or len(attempts) != 1:
                    continue
                if name == "oidc_login" and payload(matched[1]).get("grant_type") != "authorization_code":
                    continue
                if name == "saml_login" and (
                    payload(matched[1]).get("entityID") != matched[1]["ref"]
                    or payload(matched[-1]).get("ref_id") != matched[-1]["ref_id"]
                ):
                    continue
                indices = (attempts[0], *indices)
            return name, "normal", indices, actor, target
    return None


def project(session, rows):
    aliases = {}
    counters = Counter()

    def alias(key):
        if key is None:
            return None
        if key not in aliases:
            counters[key[0]] += 1
            aliases[key] = f"{key[0]}-{counters[key[0]]}"
        return aliases[key]

    events = []
    for event, raw in zip(session.events, rows, strict=True):
        actor, target = relations(raw)
        events.append(EvidenceEvent.model_validate(event.model_dump() | {
            "auth_stage": ACTION_STAGES.get(raw["event_type"], event.auth_stage),
            "requester": alias(actor),
            "target": alias(target),
        }))
    return EvidenceSession(session_id=session.session_id, events=events), aliases


def source_rows(source, contract, selected_lines):
    rows = {}
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for line, raw in enumerate(stream, 1):
            digest.update(raw)
            if line in selected_lines:
                if m7.sha(raw.rstrip(b"\r\n")) != selected_lines[line]:
                    raise ValueError("source_record_changed")
                rows[line] = json.loads(raw)
    if digest.hexdigest() != contract["sha256"] or rows.keys() != selected_lines.keys():
        raise ValueError("source_changed")
    return rows


def prior_cohorts(contract):
    m7.verify(PILOT, contract)
    manifest_data = (PRIOR / "manifest.json").read_bytes()
    manifest = json.loads(manifest_data)
    if (manifest["source_sha256"] != contract["sha256"]
            or any(m7.sha((PRIOR / name).read_bytes()) != digest
                   for name, digest in manifest["files"].items())):
        raise ValueError("prior_public_holdout_changed")

    labels = m7.read_rows((PILOT / "labels.jsonl").read_bytes(), m7.Label)
    prior = {}
    for split in m7.SPLITS:
        data = m7.read_rows((PILOT / f"{split}.jsonl").read_bytes(), m7.Session)
        by_id = {label.session_id: label for label in labels if label.split == split}
        prior[split] = holdout.cohort_fingerprints((session, by_id[session.session_id]) for session in data)
    data = m7.read_rows((PRIOR / "observations.jsonl").read_bytes(), m7.EnrichedSession)
    by_id = {label.session_id: label for label in m7.read_rows(
        (PRIOR / "scoring-labels.jsonl").read_bytes(), m7.Label,
    )}
    prior["prior_public_holdout"] = holdout.cohort_fingerprints(
        (session, by_id[session.session_id]) for session in data
    )
    local_data = LOCAL.read_bytes()
    local_manifest = (LOCAL.parent / "manifest.json").read_bytes()
    if m7.sha(local_data) != json.loads(local_manifest)["files"][LOCAL.name]:
        raise ValueError("prior_local_observations_changed")
    local = m7.read_rows(local_data, m7.EnrichedSession)
    prior["local_oidc"] = {
        "sessions": {session.session_id for session in local},
        "evidence_ids": {event.evidence_id for session in local for event in session.events},
    }
    review_data = REVIEW.read_bytes()
    review = json.loads(review_data)
    deferred = [case["source_review"] for case in review["cases"]
                if case["source_review"]["source_assessment"] == "indeterminate"]
    held = {case["session_id"] for case in deferred}
    if (len(held) != len(deferred) or len(held) != 17
            or {case["case_id"] for case in review["cases"]} != prior["development"]["sessions"]
            or not held <= prior["development"]["sessions"]
            or review["source_sha256"] != contract["sha256"]
            or review["model_report_sha256"] != m7.sha(REVIEW.with_name("report.json").read_bytes())):
        raise ValueError("unexpected_development_review")
    prior["indeterminate_development"] = {"sessions": held}
    return prior, deferred, {
        "pilot_manifest_sha256": m7.sha((PILOT / "manifest.json").read_bytes()),
        "public_holdout_manifest_sha256": m7.sha(manifest_data),
        "local_oidc_manifest_sha256": m7.sha(local_manifest),
        "development_review_sha256": m7.sha(review_data),
    }


def build(source, contract):
    groups = m7.read_source(source, contract)
    prior, deferred, prior_digests = prior_cohorts(contract)
    blocked_keys = ("sessions", "evidence_ids", "record_lines", "record_hashes", "signal_patterns")
    blocked = {key: set().union(*(group.get(key, set()) for group in prior.values()))
               for key in blocked_keys}
    cutoff = m7.timestamp(contract["pilot"]["evaluation_start"])
    candidates = []
    for trace, group in sorted(groups.items(), key=lambda item: m7.session_id_for(item[0])):
        if group[0][3][0] not in m7.LABELS or len(group) > MAX_EVENTS:
            continue
        ordered = sorted(group, key=lambda row: (row[0], row[2].line))
        if ordered[0][0] < cutoff:
            continue
        pair = m7.session_pair(trace, ordered, "evaluation")
        keys = holdout.fingerprints(*pair)
        if not any(keys[key] & blocked[key] for key in blocked_keys):
            candidates.append(pair)
    raw = source_rows(source, contract, {record.line: record.sha256 for _, label in candidates
                                        for record in label.records})
    eligible = {"normal": [], "threat": []}
    for session, label in candidates:
        rows = [raw[record.line] for record in label.records]
        evidence = source_evidence(rows)
        if evidence and evidence[1] == label.expected_label:
            eligible[evidence[1]].append((session, label, rows, evidence))

    selected = {"normal": [], "threat": []}
    for label in ("threat", "normal"):
        by_basis = {}
        for item in eligible[label]:
            by_basis.setdefault(item[3][0], []).append(item)
        for item in (row for round_ in zip_longest(*by_basis.values()) for row in round_ if row is not None):
            pattern = m7.pattern(item[0].events)
            if pattern in blocked["signal_patterns"]:
                continue
            if label == "normal" and len(selected[label]) == len(selected["threat"]):
                break
            selected[label].append(item)
            blocked["signal_patterns"].add(pattern)
    if not selected["threat"] or len(selected["normal"]) != len(selected["threat"]):
        raise ValueError("insufficient_balanced_source_evidence")
    chosen = sorted(selected["normal"] + selected["threat"], key=lambda row: row[0].session_id)
    enriched = m7.enrich_sessions(source, [row[0] for row in chosen], [row[1] for row in chosen], contract)
    limits = m6.Limits.model_validate(json.loads(m6.CONTRACT.read_bytes())["budget_proposal"])
    observations, scoring, requests = [], [], []
    for session, (_, label, raw_rows, evidence) in zip(enriched, chosen, strict=True):
        name, _, indices, actor, target = evidence
        projected, aliases = project(session, raw_rows)
        observations.append(projected)
        body = m6.m7_request(projected, QUESTION)
        encoded = m6.canonical(body)
        if (set(body) != {"case_id", "events", "evidence_ids", "question", "labels"}
                or tuple(body["labels"]) != m6.LABELS
                or any(set(event) != holdout.INPUT_FIELDS | {"requester", "target"}
                       for event in body["events"])
                or len(encoded) > limits.max_input_tokens_per_provider):
            raise ValueError("unexpected_model_input")
        requests.append(encoded + b"\n")
        scoring.append({
            "session_id": session.session_id, "expected_label": label.expected_label,
            "publisher_label": label.source_label, "evidence_basis": name,
            "requester": aliases[actor], "target": aliases[target],
            "outcome_http_status": raw_rows[indices[-1]]["http_status"],
            "outcome_event_type": raw_rows[indices[-1]]["event_type"],
            "evidence_records": [label.records[index].model_dump() for index in indices],
            "input_sha256": m7.sha(encoded),
        })
    cohort = holdout.cohort_fingerprints((row[0], row[1]) for row in chosen)
    overlap = {split: {key: len(cohort[key] & values) for key, values in previous.items()}
               for split, previous in prior.items()}
    if any(group.get(key) for group in overlap.values() for key in blocked_keys):
        raise ValueError("prior_overlap")
    files = {
        "observations.jsonl": m7.jsonl(observations),
        "model-requests.jsonl": b"".join(requests),
        "private/scoring-labels.jsonl": b"".join(m7.canonical(row) + b"\n" for row in scoring),
        "private/deferred-development.jsonl": b"".join(m7.canonical(row) + b"\n" for row in deferred),
        "NOTICE.md": (f"# 공개 원본 출처\n\n{contract['name']} ({contract['publisher']}). "
                      f"{contract['copyright']}. [CC BY 4.0]({contract['license_url']}).\n\n"
                      f"[고정 원본]({contract['source_url']})에서 행위가 연결되는 사례를 골랐습니다. "
                      "모델 입력은 관측 필드를 정규화하고 세션 안에서만 통하는 별칭을 사용합니다.\n\n"
                      "공개 원본은 합성 인증 로그입니다. 위협 사례는 보호 정책이 거부한 요청으로 제한되며 "
                      "같은 작업의 정상 대조군이 없습니다. 최종 HTTP 결과와 클래스도 함께 달라집니다. "
                      "이 묶음은 정책 거부 식별을 검증하는 보강분입니다. 원본 계정과 IP의 중복 개수는 "
                      "매니페스트에 기록했습니다.\n"
                      ).encode(),
    }
    manifest = {
        "schema": "m7-evidence-holdout-1", "source_sha256": contract["sha256"],
        "source_revision": contract["revision"], "prior_artifacts": prior_digests,
        "excluded_indeterminate_development_sessions": len(prior["indeterminate_development"]["sessions"]),
        "files": {name: m7.sha(data) for name, data in files.items()},
        "eligible_before_signal_pattern_dedup": {label: len(rows) for label, rows in eligible.items()},
        "selection": {"minimum_session_start": cutoff.isoformat(), "max_events": MAX_EVENTS,
                      "within_cohort_signal_pattern_overlap": 0,
                      "publisher_label_used_for_cross_check": True},
        "sessions": len(chosen), "events": sum(len(row.events) for row in observations),
        "labels": dict(Counter(row["expected_label"] for row in scoring)),
        "evidence_basis": dict(Counter(row["evidence_basis"] for row in scoring)),
        "outcomes_by_label": {label: dict(Counter(str(row["outcome_http_status"]) for row in scoring
                                                  if row["expected_label"] == label)) for label in selected},
        "overlap_with_prior": overlap,
        "request_check": {"sessions": len(requests), "max_bytes": max(len(row) - 1 for row in requests),
                          "answer_fields": 0, "identifier_scope": "session"},
        "actual_model_calls": 0,
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    files, manifest = build(args.source, json.loads(m7.SOURCE.read_bytes()))
    if args.mode == "verify":
        if any((args.directory / name).read_bytes() != data for name, data in files.items()):
            parser.error("bundle does not reproduce from the pinned source")
    else:
        args.directory.parent.mkdir(parents=True, exist_ok=True)
        if args.directory.exists():
            parser.error("choose a new output directory")
        with tempfile.TemporaryDirectory(dir=args.directory.parent) as temporary:
            stage = Path(temporary) / "bundle"
            (stage / "private").mkdir(parents=True, mode=0o700)
            stage.chmod(0o700)
            for name, data in files.items():
                path = stage / name
                path.write_bytes(data)
                if path.parent.name == "private":
                    path.chmod(0o600)
            stage.rename(args.directory)
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
