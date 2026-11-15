"""Start only administrator-configured inactive units; never accept commands.

The local system manager, unit configuration and privileged administrators are
inside the trust boundary. A competing root writer can defeat local attribution.
Use one broker ledger per host. This is not a distributed service orchestrator.
"""

import subprocess
from dataclasses import dataclass

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import READ_ENV, collect_current_systemd
from scripts.f1_lab.shared_execution_evidence import ServiceEvent


@dataclass(frozen=True)
class UnitTarget:
    tenant_id: str
    server_id: str
    unit: str
    executable_sha256: str
    command_sha256: str


class SystemdUnitLauncher:
    def __init__(self, targets, runtime_key, *, source_id, key_id):
        require(isinstance(targets, (list, tuple)) and 1 <= len(targets) <= 100, "launcher_targets")
        self.targets = {}
        for target in targets:
            # Reuse strict event scope validation without trusting caller input.
            ServiceEvent(
                tenant_id=target.tenant_id,
                server_id=target.server_id,
                unit=target.unit,
                boot_id="1" * 32,
                invocation_id="2" * 32,
                process_id=1,
                event_id=target.command_sha256,
                raw_sha256=target.executable_sha256,
                observed_at="2026-01-01T00:00:00Z",
                mode="systemd",
                collection_basis="manager_snapshot",
            )
            scope = target.tenant_id, target.server_id, target.unit
            require(scope not in self.targets, "launcher_duplicate_target")
            self.targets[scope] = target
        self.runtime_key, self.source_id, self.key_id = runtime_key, source_id, key_id

    def target(self, request):
        target = self.targets.get((request.tenant_id, request.server_id, request.unit))
        require(
            target is not None
            and (request.command_sha256, request.executable_sha256)
            == (target.command_sha256, target.executable_sha256),
            "launcher_scope_or_command",
        )
        return target

    @staticmethod
    def state(unit):
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--no-pager",
                "--property=Id,LoadState,ActiveState,MainPID,InvocationID,Job",
                "--",
                unit,
            ],
            capture_output=True,
            timeout=5,
            env=READ_ENV,
            check=False,
        )
        require(
            result.returncode == 0 and len(result.stdout) <= 8192, "launcher_manager_unavailable"
        )
        pairs = [line.split("=", 1) for line in result.stdout.decode("ascii").splitlines()]
        require(
            len(pairs) == 6 and all(len(p) == 2 for p in pairs) and len({p[0] for p in pairs}) == 6,
            "launcher_manager_fields",
        )
        state = dict(pairs)
        require(
            set(state) == {"Id", "LoadState", "ActiveState", "MainPID", "InvocationID", "Job"}
            and state["Id"] == unit,
            "launcher_manager_identity",
        )
        return state

    def launch(self, request):
        self.target(request)
        state = self.state(request.unit)
        require(
            state["LoadState"] == "loaded"
            and state["ActiveState"] == "inactive"
            and state["MainPID"] == "0"
            and not state["Job"]
            and not state["InvocationID"],
            "launcher_requires_inactive_unit",
        )
        result = subprocess.run(
            ["/usr/bin/systemctl", "start", "--", request.unit],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=READ_ENV,
            check=False,
        )
        require(result.returncode == 0, "launcher_start_uncertain")

    def collect(self, request):
        self.target(request)
        return collect_current_systemd(
            request.unit,
            self.runtime_key,
            tenant_id=request.tenant_id,
            server_id=request.server_id,
            source_id=self.source_id,
            key_id=self.key_id,
        )
