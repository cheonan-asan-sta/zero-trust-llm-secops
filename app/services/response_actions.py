"""Two independent approvals and one durable simulated result.

Response records use their own kinds in the existing encrypted/restored context
journal. Work-baseline approvals never count toward this response quorum.
"""

import hashlib
import json
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime

from app.response_models import ResponseCancel, ResponseCommand, ResponseCreate, ResponseReview
from app.security import Role
from app.services.behavior_context_store import ContextStoreUnavailable

RESPONSE_KINDS = frozenset(
    {"response_request", "response_approval", "response_cancel", "response_result"}
)


class ResponseDenied(Exception):
    pass


class ResponseNotFound(LookupError):
    pass


class ResponseConflict(Exception):
    pass


class ResponseInvalid(Exception):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def require(principal, role):
    if role not in principal.effective_roles:
        raise ResponseDenied("response_role_required")


class ResponseService:
    def __init__(self, store, operations):
        self.store, self.operations = store, operations

    @contextmanager
    def _transaction(self):
        # Match the existing context -> policy lock order. Commit the response
        # journal while the policy snapshot is still locked, so a concurrent
        # session change cannot slip between target validation and publication.
        with ExitStack() as stack:
            tx = stack.enter_context(self.store.transaction())
            with self.operations._transaction() as policy:
                yield tx, policy
                stack.close()

    @staticmethod
    def _binding(policy, session_id, tenant):
        found = [
            row["session"]
            for row in policy[1]
            if row["kind"] == "decision"
            and row["session"]["session_id"] == session_id
            and row["session"]["tenant_id"] == tenant
        ]
        if not found:
            raise ResponseNotFound("response_target_not_found")
        session = found[-1]
        return {
            key: session[key]
            for key in (
                "session_id",
                "tenant_id",
                "operator_id",
                "event_id",
                "version",
                "input_digest_sha256",
                "user_id",
                "device_id",
                "resource_id",
                "action",
            )
        }

    @staticmethod
    def _base(tx, identifier, principal):
        entry = tx.get("response_request", principal.tenant_id, identifier)
        if entry is None:
            raise ResponseNotFound("response_request_not_found")
        payload = entry["payload"]
        if payload["requester"] != entry["actor"] or payload["request_digest"] != digest(
            {key: payload[key] for key in ("request", "requester", "binding")}
        ):
            raise ContextStoreUnavailable("response_request_integrity")
        return payload

    def _view(self, tx, policy, identifier, principal, now):
        base = self._base(tx, identifier, principal)
        reviews = [
            row
            for row in tx.entries
            if row["kind"] == "response_approval"
            and row["tenant_id"] == principal.tenant_id
            and row["payload"]["request_id"] == identifier
        ]
        approvers = [row["actor"] for row in reviews]
        if (
            Role.RESPONDER not in principal.effective_roles
            and principal.subject != base["requester"]
            and principal.subject not in approvers
        ):
            raise ResponseNotFound("response_request_not_found")
        if (
            len(approvers) > 2
            or len(set(approvers)) != len(approvers)
            or base["requester"] in approvers
            or any(
                row["payload"]["command"]["request_digest"] != base["request_digest"]
                for row in reviews
            )
        ):
            raise ContextStoreUnavailable("response_review_integrity")
        cancelled = tx.get("response_cancel", principal.tenant_id, identifier)
        executed = tx.get("response_result", principal.tenant_id, identifier)
        if cancelled and executed:
            raise ContextStoreUnavailable("response_terminal_integrity")
        try:
            current = (
                self._binding(policy, base["binding"]["session_id"], principal.tenant_id)
                == base["binding"]
            )
        except ResponseNotFound:
            current = False
        expired = now >= datetime.fromisoformat(base["request"]["expires_at"])
        status = (
            "EXECUTED"
            if executed
            else "CANCELLED"
            if cancelled
            else "EXPIRED"
            if expired
            else "STALE"
            if not current
            else "APPROVED"
            if len(reviews) == 2
            else "PENDING"
        )
        kind = base["request"]["action"]
        target = {
            "kind": "device" if kind == "isolate_device" else "account",
            "id": base["binding"]["device_id"]
            if kind == "isolate_device"
            else base["binding"]["user_id"],
        }
        if kind == "reduce_privilege":
            target["resource_id"] = base["binding"]["resource_id"]
        return {
            "request_id": identifier,
            "request_digest": base["request_digest"],
            "version": 1 + len(reviews) + int(bool(cancelled or executed)),
            "status": status,
            "requester": base["requester"],
            "reason": base["request"]["reason"],
            "approved_by": approvers,
            "reviews": [
                {
                    "subject": row["actor"],
                    "reason": row["payload"]["command"]["reason"],
                    "approved_at": row["created_at"],
                    "receipt_version": row["payload"]["version"],
                }
                for row in reviews
            ],
            "required_approvals": 2,
            "action": kind,
            "target": target,
            "session_binding": base["binding"],
            "target_current": current,
            "expires_at": base["request"]["expires_at"],
            "simulation_only": True,
            "result": executed["payload"]["result"] if executed else None,
        }

    @staticmethod
    def _guard(view, command, statuses):
        if (
            command.request_digest != view["request_digest"]
            or command.expected_version != view["version"]
        ):
            raise ResponseConflict("response_version_or_digest_conflict")
        if view["status"] not in statuses:
            raise ResponseConflict("response_not_eligible_" + view["status"].lower())

    def create(self, request, principal, *, now=None):
        require(principal, Role.RESPONDER)
        now = now or datetime.now(UTC)
        request = ResponseCreate.model_validate(request.model_dump(mode="json"))
        body = request.model_dump(mode="json")
        with self._transaction() as (tx, policy):
            previous = tx.get("response_request", principal.tenant_id, request.request_id)
            if previous:
                if previous["actor"] != principal.subject or previous["payload"]["request"] != body:
                    raise ResponseConflict("response_identifier_conflict")
                return self._view(tx, policy, request.request_id, principal, now) | {
                    "duplicate": True,
                    "receipt_version": 1,
                }
            if not 0 < (request.expires_at - now).total_seconds() <= 300:
                raise ResponseInvalid("response_expiry_must_be_within_five_minutes")
            binding = self._binding(policy, request.session_id, principal.tenant_id)
            if (
                binding["operator_id"] != principal.subject
                and Role.ADMIN not in principal.effective_roles
            ):
                raise ResponseDenied("response_target_operator_scope")
            if binding["version"] != request.expected_session_version:
                raise ResponseConflict("response_target_version_conflict")
            payload = {"request": body, "requester": principal.subject, "binding": binding}
            payload["request_digest"] = digest(payload)
            tx.put(
                "response_request",
                principal.tenant_id,
                request.request_id,
                payload,
                principal.subject,
                now,
            )
            return self._view(tx, policy, request.request_id, principal, now) | {
                "duplicate": False,
                "receipt_version": 1,
            }

    def approve(self, identifier, command, principal, *, now=None):
        require(principal, Role.RESPONDER)
        now = now or datetime.now(UTC)
        command = ResponseReview.model_validate(command.model_dump(mode="json"))
        body = command.model_dump(mode="json")
        with self._transaction() as (tx, policy):
            base = self._base(tx, identifier, principal)
            if base["requester"] == principal.subject:
                raise ResponseDenied("response_self_approval_forbidden")
            key = digest([identifier, principal.subject])
            previous = tx.get("response_approval", principal.tenant_id, key)
            view = self._view(tx, policy, identifier, principal, now)
            if previous:
                if previous["payload"]["command"] != body:
                    raise ResponseConflict("response_review_retry_conflict")
                return view | {"duplicate": True, "receipt_version": previous["payload"]["version"]}
            self._guard(view, command, {"PENDING"})
            tx.put(
                "response_approval",
                principal.tenant_id,
                key,
                {"request_id": identifier, "command": body, "version": view["version"] + 1},
                principal.subject,
                now,
            )
            return self._view(tx, policy, identifier, principal, now) | {
                "duplicate": False,
                "receipt_version": view["version"] + 1,
            }

    def cancel(self, identifier, command, principal, *, now=None):
        require(principal, Role.RESPONDER)
        now = now or datetime.now(UTC)
        command = ResponseCancel.model_validate(command.model_dump(mode="json"))
        body = command.model_dump(mode="json")
        with self._transaction() as (tx, policy):
            view = self._view(tx, policy, identifier, principal, now)
            if (
                principal.subject not in [view["requester"], *view["approved_by"]]
                and Role.ADMIN not in principal.effective_roles
            ):
                raise ResponseDenied("response_cancellation_scope")
            previous = tx.get("response_cancel", principal.tenant_id, identifier)
            if previous:
                if previous["actor"] != principal.subject or previous["payload"]["command"] != body:
                    raise ResponseConflict("response_cancel_retry_conflict")
                return view | {"duplicate": True, "receipt_version": previous["payload"]["version"]}
            self._guard(view, command, {"PENDING", "APPROVED", "STALE", "EXPIRED"})
            tx.put(
                "response_cancel",
                principal.tenant_id,
                identifier,
                {"request_id": identifier, "command": body, "version": view["version"] + 1},
                principal.subject,
                now,
            )
            return self._view(tx, policy, identifier, principal, now) | {
                "duplicate": False,
                "receipt_version": view["version"] + 1,
            }

    def execute(self, identifier, command, principal, *, now=None):
        require(principal, Role.RESPONDER)
        now = now or datetime.now(UTC)
        command = ResponseCommand.model_validate(command.model_dump(mode="json"))
        body = command.model_dump(mode="json")
        with self._transaction() as (tx, policy):
            view = self._view(tx, policy, identifier, principal, now)
            if (
                principal.subject != view["requester"]
                and Role.ADMIN not in principal.effective_roles
            ):
                raise ResponseDenied("response_execution_operator_scope")
            previous = tx.get("response_result", principal.tenant_id, identifier)
            if previous:
                if previous["actor"] != principal.subject or previous["payload"]["command"] != body:
                    raise ResponseConflict("response_execution_already_consumed")
                return view | {"duplicate": True, "receipt_version": previous["payload"]["version"]}
            self._guard(view, command, {"APPROVED"})
            result = {
                "mode": "simulation",
                "status": "SIMULATED",
                "effect_applied": False,
                "action": view["action"],
                "target": view["target"],
                "approved_by": view["approved_by"],
                "request_digest": view["request_digest"],
                "executed_by": principal.subject,
                "executed_at": now.isoformat(),
            }
            tx.put(
                "response_result",
                principal.tenant_id,
                identifier,
                {
                    "request_id": identifier,
                    "command": body,
                    "version": view["version"] + 1,
                    "result": result,
                },
                principal.subject,
                now,
            )
            return self._view(tx, policy, identifier, principal, now) | {
                "duplicate": False,
                "receipt_version": view["version"] + 1,
            }

    def get(self, identifier, principal, *, now=None):
        require(principal, Role.VIEWER)
        with self._transaction() as (tx, policy):
            return self._view(tx, policy, identifier, principal, now or datetime.now(UTC))

    def recent(self, principal, *, limit=50, now=None):
        require(principal, Role.VIEWER)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ResponseInvalid("response_list_limit")
        with self._transaction() as (tx, policy):
            rows = [
                row
                for row in tx.entries
                if row["kind"] == "response_request"
                and row["tenant_id"] == principal.tenant_id
                and (
                    Role.RESPONDER in principal.effective_roles
                    or row["actor"] == principal.subject
                    or any(
                        item["kind"] == "response_approval"
                        and item["tenant_id"] == principal.tenant_id
                        and item["actor"] == principal.subject
                        and item["payload"]["request_id"] == row["record_id"]
                        for item in tx.entries
                    )
                )
            ]
            return [
                self._view(tx, policy, row["record_id"], principal, now or datetime.now(UTC))
                for row in rows[-limit:][::-1]
            ]
