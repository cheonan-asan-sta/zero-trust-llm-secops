import json
from collections import Counter
from datetime import UTC, date, datetime
from functools import lru_cache
from hashlib import sha256
from importlib.resources import files
from pathlib import Path, PurePosixPath

from app.models import (
    AssuranceSummary,
    ControlPriority,
    ControlRecord,
    ControlRegistryPayload,
    ControlStatus,
)


class AssuranceRegistry:
    def __init__(self, payload: ControlRegistryPayload) -> None:
        self.payload = payload
        self._controls = {control.control_id: control for control in payload.controls}
        canonical = json.dumps(
            payload.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.digest_sha256 = sha256(canonical).hexdigest()
        self.validation_issues = self._validate_registry()

    @property
    def controls(self) -> list[ControlRecord]:
        return list(self.payload.controls)

    def get(self, control_id: str) -> ControlRecord:
        try:
            return self._controls[control_id]
        except KeyError as exc:
            raise KeyError(control_id) from exc

    def summary(self, *, as_of: date | None = None) -> AssuranceSummary:
        current_date = as_of or datetime.now(UTC).date()
        status_counts = Counter(control.status.value for control in self.payload.controls)
        priority_counts = Counter(control.priority.value for control in self.payload.controls)
        domain_counts = Counter(control.domain for control in self.payload.controls)
        applicable = [
            control
            for control in self.payload.controls
            if control.status != ControlStatus.NOT_APPLICABLE
        ]
        score = sum(
            1.0
            if control.status == ControlStatus.IMPLEMENTED
            else 0.5
            if control.status == ControlStatus.PARTIAL
            else 0.0
            for control in applicable
        )
        implementation_rate = score / len(applicable) if applicable else 1.0
        overdue = sorted(
            control.control_id
            for control in applicable
            if control.review_due_on < current_date
        )
        return AssuranceSummary(
            registry_version=self.payload.registry_version,
            registry_digest_sha256=self.digest_sha256,
            as_of=current_date,
            valid=not self.validation_issues,
            total_controls=len(self.payload.controls),
            applicable_controls=len(applicable),
            implementation_rate=round(implementation_rate, 4),
            status_counts={status.value: status_counts[status.value] for status in ControlStatus},
            priority_counts={priority.value: priority_counts[priority.value] for priority in ControlPriority},
            domain_counts=dict(sorted(domain_counts.items())),
            evidence_count=sum(len(control.evidence) for control in self.payload.controls),
            overdue_control_ids=overdue,
        )

    def validate_evidence_locations(self, project_root: Path) -> list[str]:
        root = project_root.resolve()
        issues: list[str] = []
        for control in self.payload.controls:
            for evidence in control.evidence:
                location_path = _evidence_path(evidence.location)
                if location_path is None:
                    issues.append(
                        f"{control.control_id}/{evidence.evidence_id}: unsafe evidence location"
                    )
                    continue
                candidate = (root / Path(*location_path.parts)).resolve()
                if not candidate.is_relative_to(root) or not candidate.is_file():
                    issues.append(
                        f"{control.control_id}/{evidence.evidence_id}: missing {location_path}"
                    )
        return issues

    def _validate_registry(self) -> list[str]:
        issues: list[str] = []
        evidence_ids: set[str] = set()
        for control in self.payload.controls:
            for evidence in control.evidence:
                if evidence.evidence_id in evidence_ids:
                    issues.append(f"duplicate evidence ID: {evidence.evidence_id}")
                evidence_ids.add(evidence.evidence_id)
                if _evidence_path(evidence.location) is None:
                    issues.append(
                        f"{control.control_id}/{evidence.evidence_id}: unsafe evidence location"
                    )
        return issues


def _evidence_path(location: str) -> PurePosixPath | None:
    raw_path = location.split("::", 1)[0].strip().replace("\\", "/")
    path = PurePosixPath(raw_path)
    if not raw_path or path.is_absolute() or ".." in path.parts:
        return None
    return path


@lru_cache
def get_assurance_registry() -> AssuranceRegistry:
    resource = files("app.data").joinpath("control-register.json")
    payload = ControlRegistryPayload.model_validate_json(resource.read_text(encoding="utf-8"))
    return AssuranceRegistry(payload)
