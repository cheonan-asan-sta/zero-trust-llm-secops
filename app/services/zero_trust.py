"""Local PE/PA/PEP demonstration. Submitted signals are simulated, not attested identity."""

import hashlib
import hmac
import json
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.continuous_signal_models import ObservationApplication, SignedContinuousSignal
from app.models import ResourceContext
from app.security import Principal
from app.services import policy_journal
from app.services.ocsf import get_ocsf_normalizer
from app.services.policy_journal import JournalLimits, JournalUnavailable
from app.services.sigma import get_sigma_engine
from app.services.trusted_signals import SignalVerifier, VerifiedSignal, canonical_observation
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
_RESTRICTION_RANK = {"ALLOW": 0, "STEP_UP": 1, "HOLD": 2, "DENY": 3}


class SessionConflict(ValueError):
    pass


class SessionMissing(LookupError):
    pass


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ZeroTrustOperations:
    """SQLite transactions serialize decisions, revocations and single-use resource access.

    The complete archived prefix and active journal remain the source of state.
    Each operation verifies their chain before deriving sessions/grants, so there
    is no unverified mutable projection and no forgotten consumption or revocation.
    """

    def __init__(self, path: Path, policy_path: Path = POLICY_PATH,
                 signal_verifier: SignalVerifier | None = None,
                 *, journal_limits: JournalLimits | None = None) -> None:
        self.path = path
        self.journal_limits = journal_limits or JournalLimits()
        self.signal_verifier = signal_verifier or SignalVerifier()
        self.policy = ZeroTrustPolicyBundle.model_validate_json(policy_path.read_text("utf-8"))
        self.policy_digest = _digest(self.policy.model_dump_json())
        self.resources = {item.resource_id: item for item in self.policy.resources}
        if len(self.resources) != len(self.policy.resources):
            raise ValueError("duplicate resource policy")
        path.parent.mkdir(parents=True, exist_ok=True)
        policy_journal.initialize(path, self.journal_limits)

    @contextmanager
    def _transaction(self):
        try:
            with policy_journal.transaction(self.path, self.journal_limits) as transaction:
                for entry in transaction[1]:
                    if entry["kind"] == "decision":
                        SessionDecision.model_validate(entry["session"])
                    elif entry["kind"] == "observation":
                        ObservationApplication.model_validate(entry)
                    elif entry["kind"] != "access":
                        raise JournalUnavailable("unknown journal entry")
                yield transaction
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, SessionConflict):
                raise
            raise JournalUnavailable("zero trust journal is unavailable") from exc

    @staticmethod
    def _append(transaction, entry):
        policy_journal.append(transaction, entry)

    def journal_status(self) -> dict:
        with self._transaction() as transaction:
            return policy_journal.status(transaction)

    def compact_journal(self, *, limit: int | None = None) -> dict:
        """Move an immutable prefix without changing logical policy history."""
        with self._transaction() as transaction:
            return policy_journal.compact(transaction, limit=limit)

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

    def revalidate_sessions(self, *, now: datetime | None = None) -> dict[str, int]:
        """Persist proof expiry and withdrawn authority even with an empty inbox.

        This local maintenance operation never issues grants or lowers restrictions.
        The latest journal decisions are also its durable progress: concurrent or
        restarted scanners repeat no effects until the session or authority changes.
        """
        if now is None:
            now = datetime.now(UTC)
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("session revalidation requires timezone")
        with self._transaction() as transaction:
            _, entries, _ = transaction
            latest = {}
            for entry in entries:
                if entry["kind"] == "decision":
                    session = entry["session"]
                    latest[(session["tenant_id"], session["session_id"])] = session
            candidates = [SessionDecision.model_validate(value) for value in latest.values()
                          if value.get("signal_trust", "demo") == "verified_source"
                          and value["status"] != "REVOKED"]
            authorities = self.signal_verifier.current_source_digests(now)
            changes = []
            for previous in candidates:
                current = authorities.get((previous.tenant_id, previous.signal_source_id,
                                           previous.signal_key_id))
                if current is None or current != previous.signal_source_digest:
                    decision, reason = "DENY", "SIGNAL_SOURCE_REVOKED"
                elif previous.signal_expires_at is None or previous.signal_expires_at <= now:
                    decision, reason = "HOLD", "SIGNAL_PROOF_EXPIRED"
                else:
                    continue
                if (reason in previous.reason_codes
                        and _RESTRICTION_RANK[previous.decision] >= _RESTRICTION_RANK[decision]):
                    continue
                if previous.version >= 200:
                    raise JournalUnavailable("session history capacity reached")
                session = SessionDecision.model_validate({
                    **previous.model_dump(), "version": previous.version + 1,
                    "event_id": "check-" + secrets.token_hex(16), "evaluated_at": now,
                    "decision": decision, "status": "REVOKED" if decision == "DENY" else "HELD",
                    "reason_codes": list(dict.fromkeys([*previous.reason_codes, reason])),
                    "grant_expires_at": None,
                    # Preserve an outstanding MFA challenge on HOLD, just as a
                    # synchronous HOLD cannot erase that additional requirement.
                    "challenge_id": None if decision == "DENY" else previous.challenge_id,
                    "challenge_expires_at": (None if decision == "DENY"
                                             else previous.challenge_expires_at),
                })
                changes.append((session, previous.version, reason))
            policy_journal.ensure_capacity(transaction, len(changes))
            for session, previous_version, reason in changes:
                self._append(transaction, {
                    "kind": "decision", "session": session.model_dump(mode="json"),
                    "grant_hash": None, "trigger": "periodic_revalidation",
                    "revalidation": {"previous_version": previous_version, "reason_code": reason,
                                     "checked_at": now.isoformat()},
                })
            return {"checked": len(candidates), "changed": len(changes),
                    "held": sum(session.status == "HELD" for session, _, _ in changes),
                    "revoked": sum(session.status == "REVOKED" for session, _, _ in changes)}

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

    @staticmethod
    def _restriction_for(observation):
        if observation.kind == "identity":
            if not observation.active or observation.authentication_result == "failure":
                return "DENY"
            if observation.authentication_result == "unknown":
                return "HOLD"
        else:
            if not observation.managed or observation.security_posture == "compromised":
                return "DENY"
            if observation.security_posture == "unknown":
                return "HOLD"
            if observation.security_posture == "at_risk":
                return "STEP_UP"
        return None

    @staticmethod
    def _observation_restriction(entries, tenant_id, user_id, device_id):
        """Restrictions are sticky until a future explicit, reviewed recovery protocol.

        A positive or out-of-order observation cannot erase earlier adverse evidence,
        and a fresh synchronous event or a new session cannot bypass that evidence.
        """
        restrictions = [
            entry["restriction"] for entry in entries
            if entry["kind"] == "observation" and entry["tenant_id"] == tenant_id
            and entry["restriction"] is not None
            and entry["observation"]["subject_id"] == (
                user_id if entry["observation"]["kind"] == "identity" else device_id
            )
        ]
        return max(restrictions, key=_RESTRICTION_RANK.__getitem__, default=None)

    @staticmethod
    def _observation_result(entries, tenant_id, event_id, input_digest):
        duplicate = next((entry for entry in entries if entry["kind"] == "observation"
                          and entry["tenant_id"] == tenant_id
                          and entry["event_id"] == event_id), None)
        if duplicate is None:
            return None
        marker = ObservationApplication.model_validate(duplicate)
        if not hmac.compare_digest(marker.input_digest_sha256, input_digest):
            raise SessionConflict("observation identifier reused with different input")
        return {"matched_sessions": marker.matched_sessions, "changed_sessions": 0,
                "stale": marker.stale, "duplicate": True}

    def observation_result(self, tenant_id: str, event_id: str, input_digest: str) -> dict | None:
        """Read committed effects for ACK recovery without performing new effects.

        The entire bounded journal chain is validated. This lookup does not require
        the original signing authority to remain valid: source/key revocation must
        prevent new processing, not conceal a transaction already committed before
        a worker died. A tenant, event or digest mismatch never replays effects.
        """
        with self._transaction() as transaction:
            return self._observation_result(transaction[1], tenant_id, event_id, input_digest)

    def apply_observation(
        self, signal: SignedContinuousSignal, input_digest: str,
        *, now: datetime | None = None,
    ) -> dict:
        """Apply an authenticated durable observation atomically and without new grants.

        The receiver verifies freshness before acknowledging durable storage. The
        worker must reverify current source/key/scope with verify_observation before
        calling this method, even on retry. Expiry during queue delay does not prevent
        adverse restrictions; positive observations never clear state or prove MFA.
        Older adverse evidence may only strengthen restrictions and is reported stale.
        """
        now = now or datetime.now(UTC)
        if not hmac.compare_digest(input_digest, hashlib.sha256(canonical_observation(signal)).hexdigest()):
            raise SessionConflict("observation digest mismatch")
        with self._transaction() as transaction:
            entries = transaction[1]
            duplicate = self._observation_result(
                entries, signal.tenant_id, signal.event_id, input_digest,
            )
            if duplicate:
                return duplicate
            matching_observations = [entry for entry in entries
                                     if entry["kind"] == "observation"
                                     and entry["tenant_id"] == signal.tenant_id
                                     and entry["observation"]["kind"] == signal.observation.kind
                                     and entry["observation"]["subject_id"]
                                     == signal.observation.subject_id]
            stale = any(signal.observed_at <= datetime.fromisoformat(entry["observed_at"])
                        for entry in matching_observations)
            restriction = self._restriction_for(signal.observation)
            latest = {}
            for entry in entries:
                if entry["kind"] == "decision" and entry["session"]["tenant_id"] == signal.tenant_id:
                    session = entry["session"]
                    latest[session["session_id"]] = session
            matched = [SessionDecision.model_validate(session) for session in latest.values()
                       if (session["user_id"] if signal.observation.kind == "identity"
                           else session["device_id"]) == signal.observation.subject_id]
            changed = []
            for previous in matched:
                if restriction is None or _RESTRICTION_RANK[restriction] <= _RESTRICTION_RANK[previous.decision]:
                    continue
                if previous.version >= 200:
                    raise SessionConflict("session history capacity reached")
                reason = f"CONTINUOUS_{signal.observation.kind.upper()}_{restriction}"
                session = SessionDecision.model_validate({
                    **previous.model_dump(), "version": previous.version + 1,
                    "event_id": "obs-" + _digest(signal.tenant_id + "." + signal.event_id
                                                 + "." + previous.session_id),
                    "evaluated_at": now, "decision": restriction,
                    "status": {"STEP_UP": "STEP_UP_REQUIRED", "HOLD": "HELD",
                               "DENY": "REVOKED"}[restriction],
                    "risk_score": max(previous.risk_score, 75 if restriction == "DENY" else 25),
                    "reason_codes": list(dict.fromkeys([*previous.reason_codes, reason])),
                    "evidence": [*previous.evidence,
                                 (f"{signal.observation.kind}:{signal.observation.subject_id}:"
                                  f"{signal.event_id}")],
                    "input_digest_sha256": input_digest, "grant_expires_at": None,
                    "challenge_id": None, "challenge_expires_at": None,
                })
                changed.append(session)
            # Preflight every bound before the first write; SQLite also rolls back
            # the whole fanout if a later append or marker insertion fails.
            policy_journal.ensure_capacity(transaction, len(changed) + 1)
            for session in changed:
                self._append(transaction, {"kind": "decision",
                    "session": session.model_dump(mode="json"), "grant_hash": None,
                    "observation_event_id": signal.event_id})
            marker = ObservationApplication(
                tenant_id=signal.tenant_id, event_id=signal.event_id,
                source_id=signal.source_id, key_id=signal.key_id,
                input_digest_sha256=input_digest, observed_at=signal.observed_at, recorded_at=now,
                observation=signal.observation, restriction=restriction,
                matched_sessions=len(matched), changed_sessions=len(changed), stale=stale,
            )
            self._append(transaction, marker.model_dump(mode="json"))
            return {"matched_sessions": len(matched), "changed_sessions": len(changed),
                    "stale": stale, "duplicate": False}

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
            observation_restriction = self._observation_restriction(
                entries, principal.tenant_id, event.user.user_id, event.device.device_id,
            )
            if observation_restriction:
                deny = deny or observation_restriction == "DENY"
                hold = hold or observation_restriction == "HOLD"
                step_up = step_up or observation_restriction == "STEP_UP"
                reasons.append("CONTINUOUS_OBSERVATION_" + observation_restriction)
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
