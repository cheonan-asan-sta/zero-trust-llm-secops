"""Real mTLS reviewer identities, durable response approval and full cutover."""

from datetime import UTC, datetime, timedelta

from scripts.test_recoverable_mtls_runtime import RecoveryChecks, main


class ResponseChecks(RecoveryChecks):
    expected_context_records = 13  # Four context fixtures plus nine actual response records.

    def __init__(self, directory):
        super().__init__(directory)
        self.report["schema"] = "response-mtls-verification-1"
        self.seeded_responses = False

    def api(self, path, body=None, *, reviewer=None, expected=200):
        request = {"profile": "core", "path": path, "method": "POST" if body is not None else "GET"}
        if body is not None:
            request["body"] = body
        result = (
            self.runtime.probe(request)
            if reviewer is None
            else self.runtime.reviewer_probe(reviewer, request)
        )
        self.require(result["status"] == expected, "response_http_status_" + str(result["status"]))
        self.require(result["tls_version"] == "TLSv1.3", "response_transport_not_tls13")
        return result["body"]

    @staticmethod
    def command(view, *, review=False):
        command = {"expected_version": view["version"], "request_digest": view["request_digest"]}
        if review:
            command["reason"] = "Independent local containment review"
        return command

    def proposal(self, grant, identifier):
        return self.api(
            "/response/requests",
            {
                "request_id": identifier,
                "session_id": grant[0],
                "expected_session_version": 1,
                "action": "isolate_device",
                "expires_at": (datetime.now(UTC) + timedelta(seconds=295)).isoformat(),
                "reason": "Validate scoped local containment without external side effects",
            },
            expected=201,
        )

    def quorum(self, view):
        self.require(
            bool(view["reason"]) and view["reviews"] == [], "response_review_context_missing"
        )
        path = "/response/requests/" + view["request_id"]
        first = self.command(view, review=True)
        self.api(path + "/approvals", first, expected=403)
        self.api(path + "/execute", self.command(view), expected=409)
        view = self.api(path + "/approvals", first, reviewer="a")
        self.api(path + "/execute", self.command(view), expected=409)
        self.api(path + "/approvals", first, reviewer="b", expected=409)
        view = self.api(path + "/approvals", self.command(view, review=True), reviewer="b")
        duplicate = self.api(path + "/approvals", first, reviewer="a")
        self.require(
            duplicate["duplicate"] and duplicate["receipt_version"] == 2,
            "response_review_counted_twice",
        )
        self.require(
            view["approved_by"] == ["runtime-reviewer-a", "runtime-reviewer-b"],
            "response_identity_not_distinct",
        )
        self.require(
            [row["subject"] for row in view["reviews"]] == view["approved_by"]
            and all(row["reason"] == first["reason"] for row in view["reviews"]),
            "response_review_rationales_not_preserved",
        )
        self.api(path + "/execute", self.command(view), reviewer="a", expected=403)
        return view

    def access(self, grant, allowed, label):
        result = super().access(grant, allowed, label)
        if label == "pre_restore_grant_consumed_over_mtls" and not self.seeded_responses:
            self.seeded_responses = True
            self.pending = self.quorum(self.proposal(grant, "pending-response"))
            self.executed = self.quorum(self.proposal(grant, "executed-response"))
            self.execute_command = self.command(self.executed)
            self.response_receipt = self.api(
                "/response/requests/executed-response/execute", self.execute_command
            )
            self.require(
                self.response_receipt["result"]["status"] == "SIMULATED"
                and self.response_receipt["result"]["effect_applied"] is False,
                "response_real_effect_reported",
            )
            duplicate = self.api(
                "/response/requests/executed-response/execute", self.execute_command
            )
            self.require(
                duplicate["duplicate"] and duplicate["result"] == self.response_receipt["result"],
                "response_executed_twice",
            )
            cancelled = self.proposal(grant, "cancelled-response")
            self.cancelled = self.api(
                "/response/requests/cancelled-response/cancel", self.command(cancelled, review=True)
            )
            for reviewer in ("a", "b"):
                self.api("/zero-trust/signals/evaluate", {}, reviewer=reviewer, expected=403)
                self.api("/response/requests", {}, reviewer=reviewer, expected=403)
            self.add("separate_mtls_reviewers_require_quorum_and_cannot_issue_or_execute")
        return result

    def run(self):
        super().run()
        self.report["completed"] = False
        pending = self.api("/response/requests/pending-response")
        self.require(
            not pending["target_current"] and pending["status"] in {"STALE", "EXPIRED"},
            "response_restore_did_not_fence_target",
        )
        self.api(
            "/response/requests/pending-response/execute", self.command(self.pending), expected=409
        )
        old = self.api("/response/requests/executed-response/execute", self.execute_command)
        self.require(
            old["duplicate"] and old["result"] == self.response_receipt["result"],
            "response_restore_changed_execution_receipt",
        )
        cancelled = self.api("/response/requests/cancelled-response")
        self.require(cancelled["status"] == "CANCELLED", "response_restore_lost_cancellation")
        self.api(
            "/response/requests/cancelled-response/execute", self.command(cancelled), expected=409
        )
        self.add(
            "full_restore_preserves_response_quorum_result_cancellation_and_rejects_old_target"
        )
        fresh = self.mint("response-after-recovery")
        view = self.quorum(self.proposal(fresh, "fresh-response"))
        command = self.command(view)
        receipt = self.api("/response/requests/fresh-response/execute", command)
        self.require(receipt["result"]["effect_applied"] is False, "response_fresh_not_simulated")
        self.runtime.compose("restart", "app")
        self.wait(
            lambda: (
                self.runtime.probe({"profile": "core", "path": "/health/live"})["status"] == 200
            ),
            "response_app_restart_not_ready",
        )
        retried = self.api("/response/requests/fresh-response/execute", command)
        self.require(
            retried["duplicate"] and retried["result"] == receipt["result"],
            "response_restart_reexecuted",
        )
        self.add("fresh_approval_and_exact_execution_receipt_survive_real_app_restart")
        self.report["completed"] = True


if __name__ == "__main__":
    raise SystemExit(main(ResponseChecks))
