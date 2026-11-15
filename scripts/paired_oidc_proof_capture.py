"""Generate and reverify signed fixture evidence for harder matched OIDC pairs."""

import re
import secrets
from collections import Counter

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from scripts import prepare_m7_paired as paired
from scripts.evaluate_m6 import canonical

PROOF_VARIANTS = ("stale_proof", "scope_binding", "nonce_replay", "rotation_chain")
PAIRS_PER_VARIANT = 10
QUESTION_SUFFIX = (
    " Compare the current signed device proof with the challenge scope, nonce and observation time. "
    "Prior proof nonces have already been used. A changed key needs a rotation signed by the enrolled key. "
    "The collector verifies each signature against its named public key; verify scope and authority separately."
)
OBSERVED_AT = 1000
PROOF_LIFETIME = 120
KEY_NAMES = ("collector", "enrolled", "candidate", "other")


def _plan_case(pair_id, case_id, proof_variant, variant, label):
    family = tuple(paired.FLOWS)[(variant - 1) % len(paired.FLOWS)]
    # JWT and workstation observations identify the same account in both pair members.
    case = paired.plan_case(pair_id, case_id, family, variant, "normal")
    return case | {"expected_label": label, "proof_variant": proof_variant}


def create_plan():
    plan = []
    for proof_variant in PROOF_VARIANTS:
        for variant in range(1, PAIRS_PER_VARIANT + 1):
            pair_id = "pair-" + secrets.token_hex(12)
            for label in ("normal", "threat"):
                case_id = "oidc-" + secrets.token_hex(12)
                plan.append(_plan_case(pair_id, case_id, proof_variant, variant, label))
    return sorted(plan, key=lambda case: case["session_id"])


def verify_plan(plan):
    expected = Counter(
        (proof_variant, variant, label)
        for proof_variant in PROOF_VARIANTS
        for variant in range(1, PAIRS_PER_VARIANT + 1)
        for label in ("normal", "threat")
    )
    actual = Counter((case["proof_variant"], case["variant"], case["expected_label"]) for case in plan)
    if actual != expected or len({case["case_id"] for case in plan}) != len(plan):
        raise ValueError("proof_plan_coverage")
    for case in plan:
        if (not re.fullmatch(r"oidc-[0-9a-f]{24}", case["case_id"])
                or not re.fullmatch(r"pair-[0-9a-f]{24}", case["pair_id"])
                or case != _plan_case(case["pair_id"], case["case_id"], case["proof_variant"],
                                      case["variant"], case["expected_label"])):
            raise ValueError("proof_plan_mismatch")


def _scope(case):
    return {
        "session_id": case["session_id"],
        "resource": case["resource_id"],
        "action": case["action"],
    }


def _nonce(case, sequence):
    return f"{case['case_id']}-nonce-{sequence}"


def _proof(case, sequence, issued_at, key, phase):
    return _scope(case) | {
        "kind": "device_proof", "phase": phase, "nonce": _nonce(case, sequence),
        "issued_at_s": issued_at, "expires_at_s": issued_at + PROOF_LIFETIME, "key": key,
    }


def _planned_statements(case):
    proof_variant = case["proof_variant"]
    threat = case["expected_label"] == "threat"
    challenge = _scope(case) | {
        "kind": "challenge", "nonce": _nonce(case, 2), "enrolled_key": "enrolled",
        "observed_at_s": OBSERVED_AT, "key": "collector",
    }
    prior = _proof(case, 1, 700 if proof_variant == "stale_proof" else 950, "enrolled", "prior")
    current = _proof(case, 2, 980, "enrolled", "current")
    records = [challenge, prior]
    if proof_variant == "stale_proof" and threat:
        current.update(issued_at_s=850, expires_at_s=850 + PROOF_LIFETIME)
    elif proof_variant == "scope_binding" and threat:
        if case["variant"] % 2:
            current["session_id"] += "-different"
        else:
            current["action"] = "DOWNLOAD" if case["action"] == "READ" else "READ"
    elif proof_variant == "nonce_replay" and threat:
        current["nonce"] = prior["nonce"]
    elif proof_variant == "rotation_chain":
        records.append({
            "kind": "rotation", "session_id": case["session_id"],
            "from_key": "enrolled", "to_key": "candidate", "issued_at_s": 970,
            "key": "other" if threat else "enrolled",
        })
        current["key"] = "candidate"
    return records + [current]


def capture_proofs(plan):
    """Sign a challenge and device statements before any model request is built."""
    captures = {}
    for case in plan:
        keys = {name: Ed25519PrivateKey.generate() for name in KEY_NAMES}
        statements = [
            {"body": body, "signature": keys[body["key"]].sign(canonical(body)).hex()}
            for body in _planned_statements(case)
        ]
        captures[case["case_id"]] = {
            "public_keys": {name: key.public_key().public_bytes_raw().hex() for name, key in keys.items()},
            "statements": statements,
        }
    return captures


def _verified_statements(case, capture):
    if set(capture) != {"public_keys", "statements"} or set(capture["public_keys"]) != set(KEY_NAMES):
        raise ValueError("proof_capture_keyring")
    keys = {
        name: Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
        for name, value in capture["public_keys"].items()
    }
    bodies = []
    for record in capture["statements"]:
        if set(record) != {"body", "signature"}:
            raise ValueError("proof_capture_record")
        body = record["body"]
        try:
            keys[body["key"]].verify(bytes.fromhex(record["signature"]), canonical(body))
        except (InvalidSignature, ValueError, KeyError) as exc:
            raise ValueError("proof_signature_invalid") from exc
        bodies.append(body)
    expected_challenge = _scope(case) | {
        "kind": "challenge", "nonce": _nonce(case, 2), "enrolled_key": "enrolled",
        "observed_at_s": OBSERVED_AT, "key": "collector",
    }
    kinds = tuple(body["kind"] for body in bodies)
    if (kinds not in {
        ("challenge", "device_proof", "device_proof"),
        ("challenge", "device_proof", "rotation", "device_proof"),
    } or bodies[0] != expected_challenge
            or (bodies[1]["phase"], bodies[-1]["phase"]) != ("prior", "current")):
        raise ValueError("proof_challenge_or_order")
    return bodies


def _observations(bodies):
    challenge, *records = bodies
    sessions = {challenge["session_id"]: "session-1"}
    nonces = {challenge["nonce"]: "nonce-1"}
    key_aliases = {"collector": "key-0", "enrolled": "key-1", "candidate": "key-2", "other": "key-3"}
    statements = []
    for record in records:
        statement = dict(record)
        session_id = statement.pop("session_id")
        statement["session"] = sessions.setdefault(session_id, f"session-{len(sessions) + 1}")
        for field in ("key", "from_key", "to_key"):
            if field in statement:
                statement[field] = key_aliases[statement[field]]
        if "nonce" in statement:
            nonce = statement["nonce"]
            statement["nonce"] = nonces.setdefault(nonce, f"nonce-{len(nonces) + 1}")
        statements.append(statement)
    return {
        "expected_session": "session-1", "expected_nonce": "nonce-1",
        "enrolled_key": key_aliases[challenge["enrolled_key"]],
        "observed_at_s": challenge["observed_at_s"], "statements": statements,
    }


def proof_observations(case, capture):
    """Verify signatures and challenge independently of the private scoring label."""
    return _observations(_verified_statements(case, capture))


def _violation(bodies):
    challenge, prior, *remaining = bodies
    current = remaining[-1]
    if current["nonce"] == prior["nonce"]:
        return "nonce_reuse"
    if any(current[field] != challenge[field] for field in ("session_id", "resource", "action", "nonce")):
        return "scope_mismatch"
    if not current["issued_at_s"] <= challenge["observed_at_s"] < current["expires_at_s"]:
        return "proof_expired"
    authorized_key = challenge["enrolled_key"]
    if len(remaining) == 2:
        rotation = remaining[0]
        if (rotation["key"] == rotation["from_key"] == authorized_key
                and rotation["session_id"] == challenge["session_id"]
                and prior["issued_at_s"] <= rotation["issued_at_s"] <= current["issued_at_s"]):
            authorized_key = rotation["to_key"]
    return None if current["key"] == authorized_key else "unauthorized_key_rotation"


def verified_violation(case, capture):
    """Verify the fixture's signed proof and classify a violation without reading its label."""
    return _violation(_verified_statements(case, capture))


def verify_proof(case, capture):
    """Check the frozen scenario and independently compute whether the active proof binds."""
    bodies = _verified_statements(case, capture)
    if bodies != _planned_statements(case):
        raise ValueError("proof_capture_scenario")
    binds = _violation(bodies) is None
    if binds != (case["expected_label"] == "normal"):
        raise ValueError("proof_capture_ground_truth")
    return _observations(bodies)
