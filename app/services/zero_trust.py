"""Local PE/PA/PEP demonstration. Submitted signals are simulated, not attested identity."""

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import ResourceContext
from app.security import Principal
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import get_sigma_engine
from app.services.trusted_signals import SignalVerifier, VerifiedSignal
from app.zero_trust_models import (
    ProtectedAccessRequest,
    ProtectedAccessResult,
    SessionDecision,
    SessionEvaluationRequest,
    SessionEvaluationResult,
    SessionRevocationRequest,
    SignedSessionSignal,
    ZeroTrustPolicyBundle,
)

POLICY_PATH = Path(__file__).parents[1] / "data" / "zero-trust-policies.json"


class SessionConflict(ValueError):
    pass


class SessionMissing(LookupError):
    pass


class JournalUnavailable(RuntimeError):
    pass


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ZeroTrustOperations:
    """SQLite transactions serialize decisions, revocations and single-use resource access.

    The journal is the sole source of state. Each operation verifies its bounded chain
    before deriving sessions/grants, so there is no unverified mutable projection.
    """

    def __init__(self, path: Path, policy_path: Path = POLICY_PATH,
                 signal_verifier: SignalVerifier | None = None) -> None:
        self.path = path
        self.signal_verifier = signal_verifier or SignalVerifier()
        self.policy = ZeroTrustPolicyBundle.model_validate_json(policy_path.read_text("utf-8"))
        self.policy_digest = _digest(self.policy.model_dump_json())
        self.resources = {item.resource_id: item for item in self.policy.resources}
        if len(self.resources) != len(self.policy.resources):
            raise ValueError("duplicate resource policy")
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS journal ("
                "seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, "
                "previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL)"
            )

    @contextmanager
    def _transaction(self):
        try:
            with sqlite3.connect(self.path, timeout=5) as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT seq,payload,previous_hash,record_hash FROM journal ORDER BY seq"
                ).fetchall()
                if len(rows) >= 10000:
                    raise JournalUnavailable("local journal capacity reached")
                previous = "0" * 64
                entries = []
                for index, (seq, payload, prior, digest) in enumerate(rows, 1):
                    if seq != index or prior != previous or not hmac.compare_digest(
                        digest, _digest(prior + "." + payload)
                    ):
                        raise JournalUnavailable("zero trust journal integrity failed")
                    entry = json.loads(payload)
                    if entry["kind"] == "decision":
                        SessionDecision.model_validate(entry["session"])
                    elif entry["kind"] != "access":
                        raise JournalUnavailable("unknown journal entry")
                    entries.append(entry)
                    previous = digest
                yield connection, entries, previous
        except (sqlite3.Error, OSError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, SessionConflict):
                raise
            raise JournalUnavailable("zero trust journal is unavailable") from exc

    @staticmethod
    def _append(transaction, entry):
        connection, entries, previous = transaction
        payload = _canonical(entry)
        connection.execute(
            "INSERT INTO journal VALUES (?,?,?,?)",
            (len(entries) + 1, payload, previous, _digest(previous + "." + payload)),
        )

    @staticmethod
    def _latest(entries, tenant_id, session_id):
        return next(
            (entry for entry in reversed(entries) if entry["kind"] == "decision"
             and entry["session"]["tenant_id"] == tenant_id
             and entry["session"]["session_id"] == session_id),
            None,
        )

    def integrity(self):
        try:
            with self._transaction() as transaction:
                signals = self.signal_verifier.readiness()
                return {"ok": signals["ok"], "verified_entries": len(transaction[1]),
                        "trusted_signals": signals,
                        "mode": "local_simulation", "policy_version": self.policy.version,
                        "policy_digest_sha256": self.policy_digest}
        except JournalUnavailable:
            return {"ok": False, "mode": "local_simulation"}

    def sessions(self, principal: Principal) -> list[SessionDecision]:
        with self._transaction() as (_, entries, _):
            latest = {}
            for entry in entries:
                if entry["kind"] == "decision" and entry["session"]["tenant_id"] == principal.tenant_id:
                    latest[entry["session"]["session_id"]] = entry["session"]
            return sorted(
                (SessionDecision.model_validate(value) for value in latest.values()),
                key=lambda value: value.evaluated_at, reverse=True,
            )[:100]

    def history(self, session_id: str, principal: Principal) -> list[SessionDecision]:
        with self._transaction() as (_, entries, _):
            history = [SessionDecision.model_validate(entry["session"]) for entry in entries
                       if entry["kind"] == "decision"
                       and entry["session"]["tenant_id"] == principal.tenant_id
                       and entry["session"]["session_id"] == session_id]
            if not history:
                raise SessionMissing(session_id)
            return history

    def evaluate(
        self, request: SessionEvaluationRequest, principal: Principal,
        *, now: datetime | None = None,
    ) -> SessionEvaluationResult:
        return self._evaluate(request, principal, now=now or datetime.now(UTC))

    def evaluate_signed(self, signal: SignedSessionSignal, principal: Principal,
                        *, now: datetime | None = None) -> SessionEvaluationResult:
        now = now or datetime.now(UTC)
        proof = self.signal_verifier.verify(signal, principal, now)
        request = SessionEvaluationRequest(session_id=signal.session_id,
                                           expected_version=signal.expected_version,
                                           event=signal.event)
        return self._evaluate(request, principal, now=now, proof=proof)

    def _evaluate(self, request: SessionEvaluationRequest, principal: Principal,
                  *, now: datetime, proof: VerifiedSignal | None = None) -> SessionEvaluationResult:
        now = now or datetime.now(UTC)
        event = request.event
        digest = proof.input_digest if proof else _digest(_canonical(event.analysis_payload()))
        with self._transaction() as transaction:
            _, entries, _ = transaction
            existing = self._latest(entries, principal.tenant_id, request.session_id)
            previous = SessionDecision.model_validate(existing["session"]) if existing else None
            if previous and previous.operator_id != principal.subject:
                raise SessionConflict("session belongs to another simulation operator")
            trust = "verified_source" if proof else "demo"
            if previous and (previous.signal_trust != trust or (
                proof is not None and previous.signal_source_id != proof.source_id
            )):
                raise SessionConflict("session signal trust or source cannot change")
            duplicate = next((entry for entry in entries if entry["kind"] == "decision"
                              and entry["session"]["tenant_id"] == principal.tenant_id
                              and entry["session"]["event_id"] == event.event_id), None)
            if duplicate:
                prior = duplicate["session"]
                if prior["session_id"] != request.session_id or prior["input_digest_sha256"] != digest:
                    raise SessionConflict("event identifier reused with different input or session")
                return SessionEvaluationResult(session=previous, duplicate=True)
            expected = previous.version if previous else 0
            if request.expected_version != expected or expected >= 200:
                raise SessionConflict("session version conflict or history capacity reached")
            if previous and (previous.user_id != event.user.user_id
                             or previous.device_id != event.device.device_id):
                raise SessionConflict("session user and device binding cannot change")
            if previous and event.timestamp <= previous.observed_at:
                raise SessionConflict("out-of-order event requires explicit replay reconciliation")
            resource = self.resources.get(event.resource.resource_id)
            reasons = []
            evidence = []
            matched = []
            risk = 0
            deny = False
            hold = False
            step_up = False
            if previous and previous.status == "REVOKED":
                deny = True
                reasons.append("SESSION_ALREADY_REVOKED")
            if resource is None:
                deny = True
                reasons.append("RESOURCE_NOT_REGISTERED")
            else:
                # Server-owned policy, never the caller's sensitivity or required_role.
                safe_event = event.model_copy(update={"resource": ResourceContext(
                    resource_id=resource.resource_id, resource_type=resource.resource_type,
                    sensitivity=resource.sensitivity,
                )})
                assessment = RuleBasedAnalyzer().assess(safe_event)
                detection = get_sigma_engine().evaluate(get_ocsf_normalizer().normalize(safe_event))
                matched = [match.rule_id for match in detection.matches]
                risk = max(assessment.risk_score, max(
                    ({"critical": 75, "high": 50, "medium": 25}.get(match.level.value, 0)
                     for match in detection.matches), default=0,
                ))
                evidence = assessment.evidence
                if event.user.role not in resource.roles or event.action not in resource.actions:
                    deny = True
                    reasons.append("RESOURCE_SCOPE_DENIED")
                if resource.require_managed and not event.device.managed:
                    deny = True
                    reasons.append("MANAGED_DEVICE_REQUIRED")
                age = (now - event.timestamp).total_seconds()
                if age >= resource.max_signal_age_seconds or age < -30:
                    hold = True
                    reasons.append("SIGNAL_EXPIRED_OR_FUTURE")
                if resource.require_mfa and event.auth_context.mfa != "success":
                    step_up = True
                    reasons.append("FRESH_MFA_REQUIRED")
            if not event.user.active or event.auth_context.authentication_result == "failure":
                deny = True
                reasons.append("IDENTITY_DENIED")
            if event.device.security_posture == "compromised":
                deny = True
                reasons.append("DEVICE_COMPROMISED")
            if event.auth_context.authentication_result == "unknown" or event.device.security_posture == "unknown":
                hold = True
                reasons.append("SIGNAL_INCOMPLETE")
            if previous:
                risk = max(risk, max(previous.risk_score - 10, 0))
                if previous.source_ip != event.network.ip:
                    step_up = True
                    reasons.append("NETWORK_CONTEXT_CHANGED")
            if risk >= 50:
                deny = True
                reasons.append("HIGH_RISK")
            elif risk >= 25 or event.device.security_posture == "at_risk":
                step_up = True
                reasons.append("ELEVATED_RISK")
            if expected == 199:
                hold = True
                reasons.append("SESSION_HISTORY_CAPACITY")
            challenge_verified = False
            if proof and previous and previous.challenge_id is not None:
                challenge_verified = bool(
                    previous.challenge_id and proof.challenge_id == previous.challenge_id
                    and previous.challenge_expires_at and previous.challenge_expires_at > now
                    and proof.issued_at > previous.evaluated_at
                    and event.auth_context.mfa == "success"
                )
                if not challenge_verified:
                    step_up = True
                    reasons.append("SIGNED_MFA_CHALLENGE_REQUIRED")
            elif proof and proof.challenge_id is not None:
                raise SessionConflict("no outstanding challenge for this proof")
            decision = "DENY" if deny else "HOLD" if hold else "STEP_UP" if step_up else "ALLOW"
            status = {"DENY": "REVOKED", "HOLD": "HELD", "STEP_UP": "STEP_UP_REQUIRED", "ALLOW": "ACTIVE"}[decision]
            challenge_id = None
            challenge_expires = None
            if proof and decision != "DENY" and (
                decision == "STEP_UP" or (previous and previous.challenge_id
                                           and not (challenge_verified and decision == "ALLOW"))
            ):
                if (previous and previous.challenge_id
                        and previous.challenge_expires_at and previous.challenge_expires_at > now):
                    challenge_id = previous.challenge_id
                    challenge_expires = previous.challenge_expires_at
                else:
                    challenge_id = secrets.token_urlsafe(32)
                    challenge_expires = now + timedelta(seconds=120)
            token = secrets.token_urlsafe(32) if decision == "ALLOW" else None
            expires = min(
                now + timedelta(seconds=resource.grant_ttl_seconds),
                event.timestamp + timedelta(seconds=resource.max_signal_age_seconds),
            ) if token else None
            if expires and proof:
                expires = min(expires, proof.expires_at)
            session = SessionDecision(
                session_id=request.session_id, tenant_id=principal.tenant_id,
                operator_id=principal.subject, user_id=event.user.user_id,
                device_id=event.device.device_id, source_ip=event.network.ip,
                version=expected + 1, event_id=event.event_id, observed_at=event.timestamp,
                evaluated_at=now, resource_id=event.resource.resource_id, action=event.action,
                decision=decision, status=status, risk_score=risk,
                reason_codes=reasons or ["POLICY_SATISFIED"], evidence=evidence,
                matched_rule_ids=matched, policy_version=self.policy.version,
                policy_digest_sha256=self.policy_digest, input_digest_sha256=digest,
                grant_expires_at=expires,
                signal_trust=trust, signal_source_id=proof.source_id if proof else None,
                signal_key_id=proof.key_id if proof else None,
                signal_source_digest=proof.source_digest if proof else None,
                signal_expires_at=proof.expires_at if proof else None,
                challenge_id=challenge_id, challenge_expires_at=challenge_expires,
            )
            self._append(transaction, {"kind": "decision", "session": session.model_dump(mode="json"),
                                       "grant_hash": _digest(token) if token else None})
            return SessionEvaluationResult(session=session, grant_token=token)

    def revoke(self, session_id: str, request: SessionRevocationRequest, principal: Principal,
               *, now: datetime | None = None) -> SessionDecision:
        now = now or datetime.now(UTC)
        with self._transaction() as transaction:
            entry = self._latest(transaction[1], principal.tenant_id, session_id)
            if entry is None:
                raise SessionMissing(session_id)
            previous = SessionDecision.model_validate(entry["session"])
            if request.expected_version != previous.version or previous.version >= 200:
                raise SessionConflict("session version conflict or history capacity reached")
            session = SessionDecision.model_validate({**previous.model_dump(),
                "version": previous.version + 1, "decision": "DENY", "status": "REVOKED",
                "event_id": "revoke-" + secrets.token_hex(12), "evaluated_at": now,
                "reason_codes": ["OPERATOR_REVOKED"], "grant_expires_at": None,
                "challenge_id": None, "challenge_expires_at": None})
            self._append(transaction, {"kind": "decision", "session": session.model_dump(mode="json"),
                                       "grant_hash": None, "revoked_by": principal.subject,
                                       "note": request.note})
            return session

    def access(self, request: ProtectedAccessRequest, principal: Principal,
               *, now: datetime | None = None) -> ProtectedAccessResult:
        now = now or datetime.now(UTC)
        with self._transaction() as transaction:
            entry = self._latest(transaction[1], principal.tenant_id, request.session_id)
            reason = "GRANT_INVALID"
            version = None
            token_hash = _digest(request.grant_token)
            if entry is not None:
                session = SessionDecision.model_validate(entry["session"])
                version = session.version
                consumed = any(item["kind"] == "access" and item.get("allowed")
                               and item.get("grant_hash") == token_hash for item in transaction[1])
                if session.operator_id == principal.subject:
                    if session.decision != "ALLOW" or session.status != "ACTIVE":
                        reason = "SESSION_NOT_AUTHORIZED"
                    elif not hmac.compare_digest(entry.get("grant_hash") or "", token_hash):
                        reason = "GRANT_INVALID"
                    elif session.resource_id != request.resource_id or session.action != request.action:
                        reason = "SCOPE_DENIED"
                    elif session.policy_digest_sha256 != self.policy_digest:
                        reason = "POLICY_CHANGED"
                    elif session.signal_trust == "verified_source" and (
                        session.signal_source_digest != self.signal_verifier.source_digest(
                            principal.tenant_id, session.signal_source_id, session.signal_key_id, now
                        )
                    ):
                        reason = "SIGNAL_SOURCE_REVOKED"
                    elif session.signal_expires_at is not None and session.signal_expires_at <= now:
                        reason = "SIGNAL_PROOF_EXPIRED"
                    elif (session.evaluated_at > now or session.grant_expires_at is None
                          or session.grant_expires_at <= now):
                        reason = "GRANT_EXPIRED"
                    elif consumed:
                        reason = "GRANT_ALREADY_USED"
                    else:
                        reason = "ACCESS_GRANTED"
            allowed = reason == "ACCESS_GRANTED"
            self._append(transaction, {"kind": "access", "tenant_id": principal.tenant_id,
                                       "operator_id": principal.subject, "session_id": request.session_id,
                                       "resource_id": request.resource_id, "action": request.action.value,
                                       "session_version": version, "allowed": allowed,
                                       "reason_code": reason,
                                       "grant_hash": token_hash, "recorded_at": now.isoformat()})
            return ProtectedAccessResult(
                allowed=allowed, reason_code=reason, session_version=version,
                content="모의 업무 자원에 대한 접근이 허용되었습니다." if allowed else None,
            )
