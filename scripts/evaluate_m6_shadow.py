"""Compare rule output and observation-only LLM assistance on a frozen local holdout."""

import argparse
import asyncio
import json
import tempfile
from collections import Counter
from decimal import Decimal
from pathlib import Path

import httpx

from app.services.detection_benchmark import confusion, metrics
from scripts import evaluate_m6 as m6
from scripts import m6_shadow_assist as assist
from scripts import m7_shadow_capture as capture
from scripts.evaluate_m6_proof_policy import VerifiedEvidence, assess
from scripts.m7_shadow_overlap import verify_overlap
from scripts.prepare_m7_local import jsonl

SCORES = "private/scoring-plan.jsonl"
CAPTURES = "private/local-capture.jsonl"
REQUESTS = "model-requests.jsonl"
MAX_SESSIONS = 24
MAX_USD = Decimal("0.16")
WALL_SECONDS = 240
PRIORITY = {"continue_policy_checks": "low", "revalidate": "medium", "restrict": "high"}
SCORING_FIELDS = {"expected_label", "expected_priority", "required_kinds"}
PRIORITIES = {"low", "medium", "high"}
RUBRIC = (
    "High: active serious harm or confirmed compromise or misuse targeting a sensitive resource. "
    "Medium: contained ordinary-scope finding or unresolved evidence needing review. "
    "Low: routine approved activity or irrelevant benign activity."
)


def read_rows(data):
    return [json.loads(line, object_pairs_hook=m6.unique_fields) for line in data.splitlines()]


def capture_inputs(plan):
    return [{key: value for key, value in row.items() if key not in SCORING_FIELDS} for row in plan]


def rule_answer(observed):
    verdict, next_check, reason = assess(VerifiedEvidence.model_validate(observed["rule_evidence"]))
    if verdict == "normal":
        kinds = {"proof_requirement", "proof_state", "identity_binding", "endpoint_scope"}
    elif reason == "verified_device_compromise":
        kinds = {"observation", "source_validation"}
    elif reason in {"scope_mismatch", "nonce_reuse", "unauthorized_key_rotation"}:
        kinds = {"verified_violation"}
    elif reason in {"required_proof_absent", "proof_expired", "proof_unverifiable"}:
        kinds = {"proof_requirement", "proof_state"}
    elif reason == "proof_requirement_unknown":
        kinds = {"proof_requirement"}
    elif reason in {"endpoint_scope_unconfirmed", "verified_use_outside_scope"}:
        kinds = {"endpoint_scope", "identity_binding"}
    else:
        kinds = {"identity_binding"}
    claims = [
        {"evidence_id": row["id"], "fact_code": row["kind"]}
        for row in observed["evidence"] if row["kind"] in kinds
    ]
    return {"verdict": verdict, "reason": reason, "next_check": next_check,
            "priority": PRIORITY[next_check], "claims": claims}


def prepare_rows(plan, captures):
    if not 0 < len(plan) <= MAX_SESSIONS or len(captures) != len(plan):
        raise ValueError("shadow_case_count")
    by_id = {row["case_id"]: row for row in captures}
    case_ids = {row["case_id"] for row in plan}
    if len(case_ids) != len(plan) or len(by_id) != len(captures) or case_ids != by_id.keys():
        raise ValueError("shadow_case_identity")
    if len({row["session_id"] for row in plan}) != len(plan):
        raise ValueError("shadow_session_identity")
    result = []
    for score in sorted(plan, key=lambda row: row["case_id"]):
        observed = by_id[score["case_id"]]
        if observed["session_id"] != score["session_id"]:
            raise ValueError("shadow_capture_session")
        rule = rule_answer(observed)
        evidence = sorted(observed["evidence"], key=lambda fact: fact["id"])
        request = assist.make_request(score["case_id"], rule["verdict"], evidence)
        required = score["required_kinds"]
        if (score["expected_label"] not in m6.LABELS or score["expected_priority"] not in PRIORITIES
                or not required or len(set(required)) != len(required)
                or not set(required) <= {item["kind"] for item in evidence}):
            raise ValueError("shadow_scoring_reference")
        result.append((score, request, rule))
    ids = [item["id"] for _, request, _ in result for item in request["evidence"]]
    facts = {
        m6.canonical(sorted((item["kind"], item["detail"]) for item in request["evidence"]))
        for _, request, _ in result
    }
    if len(ids) != len(set(ids)) or len(facts) != len(result):
        raise ValueError("shadow_duplicate_evidence")
    return result


def bundle(plan, captures, rows):
    requests = [request for _, request, _ in rows]
    hashes = [m6.digest(m6.canonical(request)) for request in requests]
    overlap = verify_overlap(
        [row["session_id"] for row in plan],
        [item["id"] for request in requests for item in request["evidence"]],
        hashes,
        new_related_ids=[row["case_id"] for row in plan],
        new_source_hashes=[m6.digest(m6.canonical(row)) for row in captures],
    )
    files = {SCORES: jsonl(plan), CAPTURES: jsonl(captures), REQUESTS: jsonl(requests)}
    manifest = {
        "schema": "m7-shadow-evaluation-1",
        "scope": capture.SCOPE,
        "sessions": len(plan),
        "families": dict(Counter(row["family"] for row in plan)),
        "reference_detection": dict(Counter(row["expected_label"] for row in plan)),
        "reference_priority": dict(Counter(row["expected_priority"] for row in plan)),
        "priority_rubric": RUBRIC,
        "rule_priority_mapping": PRIORITY,
        "rule_output_sha256": m6.digest(jsonl([
            {"case_id": request["case_id"], "rule": rule} for _, request, rule in rows
        ])),
        "instructions_sha256": m6.digest(assist.INSTRUCTIONS.encode()),
        "response_schema_sha256": m6.digest(m6.canonical(assist.SCHEMA)),
        "model": assist.MODEL,
        "files": {name: m6.digest(contents) for name, contents in files.items()},
        "prior_overlap": overlap,
    }
    return files, manifest


def prepare(directory):
    if directory.exists():
        raise ValueError("shadow_bundle_exists")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".m7-shadow-") as tmp:
        stage = Path(tmp) / "bundle"
        (stage / "private").mkdir(parents=True, mode=0o700)
        plan = capture.create_plan()
        frozen_plan = jsonl(plan)
        (stage / SCORES).write_bytes(frozen_plan)
        observations = capture.capture_cases(capture_inputs(plan), Path(tmp))
        rows = prepare_rows(plan, observations)
        files, manifest = bundle(plan, observations, rows)
        if files[SCORES] != frozen_plan:
            raise ValueError("shadow_scoring_plan_changed")
        for name, contents in files.items():
            path = stage / name
            path.write_bytes(contents)
            if path.parent.name == "private":
                path.chmod(0o600)
        m6.write_report(stage / "manifest.json", manifest)
        stage.rename(directory)
    return manifest


def verified_bundle(directory):
    plan = read_rows((directory / SCORES).read_bytes())
    observations = read_rows((directory / CAPTURES).read_bytes())
    rows = prepare_rows(plan, observations)
    files, manifest = bundle(plan, observations, rows)
    saved = json.loads((directory / "manifest.json").read_bytes(), object_pairs_hook=m6.unique_fields)
    if saved != manifest or any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("shadow_bundle_changed")
    return rows, manifest


def score_explanation(answer, request, required_kinds):
    available = {item["id"]: item for item in request["evidence"]}
    rendered, unsupported = [], []
    seen = set()
    for claim in answer.get("claims", []):
        evidence = available.get(claim["evidence_id"])
        if (evidence is None or evidence["kind"] != claim["fact_code"]
                or claim["evidence_id"] in seen):
            unsupported.append(claim)
            continue
        rendered.append(evidence)
        seen.add(evidence["id"])
    missing = sorted(set(required_kinds) - {item["kind"] for item in rendered})
    return {"grounded": bool(rendered) and not unsupported, "rendered": rendered,
            "unsupported": unsupported, "missing_key_evidence": missing}


def detection_summary(rows):
    known = [row for row in rows if row["expected_label"] != "unknown"]
    covered = [row for row in known if row["rule_verdict"] != "unknown"]
    counts = confusion([row["expected_label"] == "threat" for row in covered],
                       [row["rule_verdict"] == "threat" for row in covered])
    held = Counter(row["expected_label"] for row in known if row["rule_verdict"] == "unknown")
    threats = counts["tp"] + counts["fn"] + held["threat"]
    normals = counts["tn"] + counts["fp"] + held["normal"]
    conservative = metrics(counts | {"fn": counts["fn"] + held["threat"]})
    return {
        "known_threats": threats, "known_normals": normals,
        "classified_coverage": len(covered) / len(known) if known else None,
        "conditional_confusion": counts, "conditional_metrics": metrics(counts),
        "missed_threats": counts["fn"] + held["threat"], "false_alarms": counts["fp"],
        "held_known_by_label": dict(held),
        "conservative_recall": conservative["recall"], "conservative_f1": conservative["f1"],
        "false_positive_rate_all_normals": counts["fp"] / normals if normals else None,
        "intentional_unknown": len(rows) - len(known),
        "intentional_unknown_kept_held": sum(
            row["expected_label"] == row["rule_verdict"] == "unknown" for row in rows
        ),
    }


def assist_summary(rows, arm):
    explanations = [row[arm]["explanation"] for row in rows]
    priority = {
        expected: dict(Counter(row[arm]["priority"] or "no_answer" for row in rows
                               if row["expected_priority"] == expected))
        for expected in sorted(PRIORITIES)
    }
    return {
        "sessions": len(rows),
        "response_status": dict(Counter(row[arm]["status"] for row in rows)),
        "explanation_all_claims_grounded": sum(row["grounded"] for row in explanations),
        "explanation_all_key_evidence": sum(not row["missing_key_evidence"] for row in explanations),
        "explanation_grounded_and_complete": sum(
            row["grounded"] and not row["missing_key_evidence"] for row in explanations
        ),
        "grounded_claims": sum(len(row["rendered"]) for row in explanations),
        "unsupported_claims": sum(len(row["unsupported"]) for row in explanations),
        "priority_correct": sum(row["expected_priority"] == row[arm]["priority"] for row in rows),
        "expected_high_not_ranked_high": sum(
            row["expected_priority"] == "high" and row[arm]["priority"] != "high" for row in rows
        ),
        "over_ranked_high": sum(
            row["expected_priority"] != "high" and row[arm]["priority"] == "high" for row in rows
        ),
        "priority_expected_by_actual": priority,
    }


def compare(prepared, receipts):
    rows = []
    for score, request, rule in prepared:
        response = receipts.get(request["case_id"], {"status": "not_run"})
        answer = response.get("answer") or {}
        required = score["required_kinds"]
        rows.append({
            "case_id": request["case_id"], "family": score["family"],
            "expected_label": score["expected_label"], "expected_priority": score["expected_priority"],
            "rule_verdict": rule["verdict"], "rule_reason": rule["reason"],
            "input_sha256": m6.digest(m6.canonical(request)),
            "rules": {"status": "ok", "priority": rule["priority"],
                      "explanation": score_explanation(rule, request, required)},
            "assisted": {"status": response["status"], "priority": answer.get("priority"),
                         "explanation": score_explanation(answer, request, required)},
        })
    return {
        "detection_both_arms": detection_summary(rows),
        "rule_verdict_changes": 0,
        "rules": assist_summary(rows, "rules"),
        "assisted": assist_summary(rows, "assisted"),
        "rows": rows,
    }


class WireAudit:
    def __init__(self, prepared):
        self.allowed = {}
        for _, request, _ in prepared:
            for count in (True, False):
                body = assist.request_body(request, count=count)
                self.allowed[count, m6.digest(m6.canonical(body))] = request["case_id"]
        self.sent = {}
        self.blocked = 0

    async def check(self, outgoing):
        url = str(outgoing.url)
        if outgoing.method != "POST" or url not in {assist.OPENAI_URL, assist.COUNT_URL}:
            self.blocked += 1
            raise ValueError("shadow_wire_endpoint")
        count = url == assist.COUNT_URL
        payload = json.loads(outgoing.content, object_pairs_hook=m6.unique_fields)
        fingerprint = m6.digest(m6.canonical(payload))
        key = (count, fingerprint)
        case_id = self.allowed.get(key)
        if case_id is None or key in self.sent:
            self.blocked += 1
            raise ValueError("shadow_wire_unapproved_or_duplicate_body")
        if not count and case_id not in self.sent.values():
            self.blocked += 1
            raise ValueError("shadow_wire_preflight_required")
        self.sent[key] = case_id

    def summary(self):
        return {
            "verified_token_count_requests": sum(count for count, _ in self.sent),
            "verified_generation_requests": sum(not count for count, _ in self.sent),
            "unapproved_request_bodies_blocked": self.blocked,
        }


async def run_provider(prepared, key, *, transport=None):
    audit = WireAudit(prepared)
    reserved = assist.cost(2 * assist.INPUT_LIMIT, assist.OUTPUT_LIMIT) * len(prepared)
    if reserved > MAX_USD:
        raise ValueError("shadow_request_cost_limit")
    receipts = {}
    stop_reason = None
    async with httpx.AsyncClient(
        transport=transport, timeout=assist.REQUEST_SECONDS, trust_env=False,
        event_hooks={"request": [audit.check]},
    ) as client:
        try:
            async with asyncio.timeout(WALL_SECONDS):
                for _, request, _ in prepared:
                    try:
                        count = await assist.count_input(client, key, request)
                    except assist.ProviderError as exc:
                        receipts[request["case_id"]] = {"status": str(exc), "stage": "token_preflight"}
                        stop_reason = "token_preflight_failed"
                        break
                    if not isinstance(count, int) or not 0 < count <= assist.INPUT_LIMIT:
                        stop_reason = "token_preflight_failed"
                        break
                    receipt = await assist.infer(client, key, request)
                    receipts[request["case_id"]] = receipt | {"preflight_input_tokens": count}
                    used_in, used_out = receipt.get("input_tokens"), receipt.get("output_tokens")
                    if ((used_in is not None and used_in > assist.INPUT_LIMIT)
                            or (used_out is not None and used_out > assist.OUTPUT_LIMIT)):
                        stop_reason = "provider_usage_limit"
                        break
                    if receipt.get("http_status") in {400, 401, 402, 403, 404, 422, 429}:
                        stop_reason = "provider_rejected_request"
                        break
        except TimeoutError:
            stop_reason = "wall_time_limit"
    accounted = [
        receipt for receipt in receipts.values()
        if isinstance(receipt.get("input_tokens"), int) and isinstance(receipt.get("output_tokens"), int)
    ]
    usage = {
        "generation_input_tokens": sum(receipt["input_tokens"] for receipt in accounted),
        "generation_output_tokens": sum(receipt["output_tokens"] for receipt in accounted),
    }
    audit_summary = audit.summary()
    return receipts, {
        "wire": audit_summary, "stop_reason": stop_reason, "max_usd": str(MAX_USD),
        "reserved_worst_case_usd": str(reserved), **usage,
        "estimated_generation_usd": str(assist.cost(
            usage["generation_input_tokens"], usage["generation_output_tokens"],
        )),
        "generation_usage_unconfirmed": audit_summary["verified_generation_requests"] - len(accounted),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify", "live"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        report = prepare(args.directory)
    else:
        rows, manifest = verified_bundle(args.directory)
        if args.mode == "verify":
            report = manifest
        else:
            if args.output is None or args.output.exists():
                parser.error("live requires an unused --output")
            receipts, execution = asyncio.run(run_provider(rows, assist.configured_key()))
            report = compare(rows, receipts) | {
                "schema": "m6-shadow-assistance-report-1", "mode": "live", "execution": execution,
                "dataset_manifest_sha256": m6.digest((args.directory / "manifest.json").read_bytes()),
                "model": assist.MODEL, "receipts": receipts,
            }
            m6.write_report(args.output, report)
            print(json.dumps({name: report[name] for name in (
                "detection_both_arms", "rules", "assisted", "execution",
            )}, ensure_ascii=False))
            return int(execution["stop_reason"] is not None)
    print(json.dumps({key: report[key] for key in (
        "schema", "sessions", "families", "reference_detection", "reference_priority",
    )}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
