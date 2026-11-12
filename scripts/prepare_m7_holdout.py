"""Prepare a fresh enriched M7 holdout from the pinned public source."""

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path

from scripts import evaluate_m6 as m6
from scripts import prepare_m7 as m7

MAX_EVENTS = 8
INPUT_FIELDS = {
    "evidence_id", "module", "http_method", "http_status", "level", "duration_ms",
    "auth_stage", "failure_reason", "since_previous_ms",
}
DISJOINT = ("sessions", "evidence_ids", "record_lines", "record_hashes", "subjects", "clients",
            "signal_patterns")


def fingerprints(data, label):
    return {
        "sessions": {data.session_id},
        "evidence_ids": {record.evidence_id for record in label.records},
        "record_lines": {record.line for record in label.records},
        "record_hashes": {record.sha256 for record in label.records},
        "subjects": set(label.subjects),
        "clients": set(label.clients),
        "signal_patterns": {m7.pattern(data.events)},
        "families": {(label.source_label, label.category, label.subcategory)},
    }


def cohort_fingerprints(pairs):
    combined = {key: set() for key in (*DISJOINT, "families")}
    for pair in pairs:
        for key, values in fingerprints(*pair).items():
            combined[key].update(values)
    return combined


def select_holdout(source_sessions, prior_pairs, contract):
    """Select a balanced cohort in stable session ID order under the declared exclusions."""
    cutoff = m7.timestamp(contract["pilot"]["evaluation_start"])
    count = contract["pilot"]["sessions_per_label_per_split"]
    prior = cohort_fingerprints(pair for pairs in prior_pairs.values() for pair in pairs)
    candidates = sorted(source_sessions, key=m7.session_id_for)
    selected = []
    for publisher_label in m7.LABELS:
        added = 0
        for trace in candidates:
            rows = source_sessions[trace]
            if rows[0][3][0] != publisher_label or len(rows) > MAX_EVENTS:
                continue
            if publisher_label == "attack" and rows[0][3] in prior["families"]:
                continue
            ordered = sorted(rows, key=lambda row: (row[0], row[2].line))
            if ordered[0][0] < cutoff or m7.session_id_for(trace) in prior["sessions"]:
                continue
            pair = m7.session_pair(trace, ordered, "evaluation")
            keys = fingerprints(*pair)
            if any(keys[name] & prior[name] for name in DISJOINT):
                continue
            for name in DISJOINT:
                prior[name].update(keys[name])
            selected.append(pair)
            added += 1
            if added == count:
                break
        if added != count:
            raise ValueError("m7_holdout_insufficient_disjoint_sessions")
    return sorted(selected, key=lambda pair: pair[0].session_id)


def verify_requests(observations):
    """Verify the same request projection used by the M6 runner without dispatching it."""
    limits = m6.Limits.model_validate(json.loads(m6.CONTRACT.read_bytes())["budget_proposal"])
    stages = set(m7.AUTH_STAGES.values()) | {"unknown"}
    reasons = set(m7.FAILURE_REASONS.values()) | {"protected_client", None}
    sizes = []
    for session in m7.read_rows(observations, m7.EnrichedSession):
        payload = m7.canonical(m6.m7_request(session, m6.M7_ENRICHED_QUESTION))
        request = json.loads(payload)
        if (set(request) != {"case_id", "events", "evidence_ids", "question", "labels"}
                or request["labels"] != list(m6.LABELS)
                or not all(event.keys() == INPUT_FIELDS for event in request["events"])):
            raise ValueError("m7_holdout_request_fields")
        if any(event["auth_stage"] not in stages or event["failure_reason"] not in reasons
               for event in request["events"]):
            raise ValueError("m7_holdout_request_values")
        if len(payload) > limits.max_input_tokens_per_provider:
            raise ValueError("m7_holdout_request_size")
        sizes.append(len(payload))
    return {"sessions": len(sizes), "max_bytes": max(sizes), "mock_byte_limit":
            limits.max_input_tokens_per_provider, "answer_fields": 0}


def build_holdout(source, pilot, contract):
    source_sessions = m7.read_source(source, contract)
    prior_pairs = m7.select_sessions(source_sessions, contract["pilot"])
    prior_files, prior_manifest = m7.pilot_bundle(prior_pairs, contract)
    if any((pilot / name).read_bytes() != data for name, data in prior_files.items()):
        raise ValueError("m7_holdout_prior_pilot_mismatch")

    selected = select_holdout(source_sessions, prior_pairs, contract)
    sessions, labels = zip(*selected, strict=True)
    observations = m7.jsonl(m7.enrich_sessions(source, sessions, labels, contract))
    request_check = verify_requests(observations)
    holdout = cohort_fingerprints(selected)
    overlaps = {}
    for split, pairs in prior_pairs.items():
        previous = cohort_fingerprints(pairs)
        overlaps[split] = {key: len(values & previous[key]) for key, values in holdout.items()}

    notice = (
        "# M7 평가 자료 출처\n\n"
        f"{contract['name']} ({contract['publisher']}). {contract['copyright']}.\n\n"
        f"이 자료는 [{contract['license']}]({contract['license_url']}) 조건으로 제공됩니다. "
        f"[게시자 라이선스]({contract['publisher_license_url']})\n\n"
        f"[게시자 원본]({contract['source_url']})의 리비전 {contract['revision']}에서 "
        "인증 세션을 추렸습니다. 식별자를 지문으로 바꾸고 관측값을 표준화했습니다. "
        "게시자 라벨과 원본 행 정보는 채점 파일에 따로 기록했습니다.\n"
    )
    files = {
        "observations.jsonl": observations,
        "scoring-labels.jsonl": m7.jsonl(labels),
        "NOTICE.md": notice.encode("utf-8"),
    }
    manifest = {
        "schema": "m7-auth-holdout-1",
        "source_sha256": contract["sha256"],
        "source_revision": contract["revision"],
        "source_contract_sha256": prior_manifest["source_contract_sha256"],
        "prior_pilot_files": prior_manifest["files"],
        "prior_pilot_manifest_sha256": m7.sha(prior_files["manifest.json"]),
        "files": {name: m7.sha(data) for name, data in files.items()},
        "selection": {
            "earliest_session_start": contract["pilot"]["evaluation_start"],
            "max_events_per_session": MAX_EVENTS,
            "order": "session_id",
            "exclude_prior_threat_families": True,
        },
        "cohort": {
            "sessions": len(sessions),
            "events": sum(len(session.events) for session in sessions),
            "labels": dict(Counter(label.expected_label for label in labels)),
        },
        "overlap_with_prior": overlaps,
        "request_check": request_check,
        "label_review": "publisher_labels_pending_self_review",
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def verify_holdout(source, pilot, directory, contract):
    files, manifest = build_holdout(source, pilot, contract)
    if any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("m7_holdout_reproduction_mismatch")
    return manifest


def prepare_holdout(source, pilot, directory, contract):
    if directory.exists():
        raise ValueError("m7_holdout_output_requires_fresh_directory")
    files, manifest = build_holdout(source, pilot, contract)
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".m7-holdout-", dir=directory.parent) as temporary:
        stage = Path(temporary) / "holdout"
        stage.mkdir(mode=0o700)
        for name, data in files.items():
            (stage / name).write_bytes(data)
        (stage / "scoring-labels.jsonl").chmod(0o600)
        stage.rename(directory)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--source", type=Path, required=True, help="Local pinned publisher JSONL")
    parser.add_argument("--pilot", type=Path, required=True, help="Previously prepared M7 pilot")
    parser.add_argument("--directory", type=Path, required=True, help="Holdout bundle directory")
    args = parser.parse_args()
    try:
        contract = json.loads(m7.SOURCE.read_bytes())
        operation = prepare_holdout if args.mode == "prepare" else verify_holdout
        manifest = operation(args.source, args.pilot, args.directory, contract)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"m7 holdout rejected: {type(exc).__name__}\n")
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
