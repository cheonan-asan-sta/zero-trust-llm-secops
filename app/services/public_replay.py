import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from functools import lru_cache
from hashlib import sha256
from importlib.resources import files

from app.models import (
    AuthContext,
    BehaviorContext,
    DetectionPipelineResult,
    DetectionQualityTargets,
    DeviceContext,
    EventAction,
    IncidentQualityTargets,
    NetworkContext,
    PublicReplayDataset,
    PublicReplayRecordResult,
    PublicReplayResult,
    PublicReplaySuiteResult,
    ResourceContext,
    SecurityEvent,
    UserContext,
)
from app.services.correlation import CorrelationEngine, get_correlation_engine
from app.services.ocsf import OCSFNormalizer, get_ocsf_normalizer
from app.services.sigma import SigmaEngine, get_sigma_engine

REPLAY_VERSION = "0.14.0"
_WINDOWS_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_WINDOWS = {"event": _WINDOWS_NAMESPACE}


class PublicReplayService:
    version = REPLAY_VERSION

    def __init__(
        self,
        normalizer: OCSFNormalizer,
        sigma_engine: SigmaEngine,
        correlation_engine: CorrelationEngine,
    ) -> None:
        self._normalizer = normalizer
        self._sigma_engine = sigma_engine
        self._correlation_engine = correlation_engine
        self.validation_issues: list[str] = []
        self._datasets: list[PublicReplayDataset] = []
        self.quality_targets = DetectionQualityTargets()
        self.incident_quality_targets = IncidentQualityTargets()
        self.manifest_digest_sha256 = ""
        self._load_manifest()

    @property
    def valid(self) -> bool:
        return not self.validation_issues and bool(self._datasets)

    def datasets(self) -> list[PublicReplayDataset]:
        return list(self._datasets)

    def run_all(self, tenant_id: str) -> PublicReplaySuiteResult:
        results = [self.run_dataset(dataset.dataset_id, tenant_id) for dataset in self._datasets]
        return PublicReplaySuiteResult(
            replay_version=REPLAY_VERSION,
            dataset_count=len(results),
            event_count=sum(len(result.records) for result in results),
            finding_count=sum(result.finding_count for result in results),
            incident_count=sum(len(result.incidents) for result in results),
            expectations_met=all(result.expectation_met for result in results),
            results=results,
        )

    def run_dataset(self, dataset_id: str, tenant_id: str) -> PublicReplayResult:
        dataset = next(
            (item for item in self._datasets if item.dataset_id == dataset_id),
            None,
        )
        if dataset is None:
            raise KeyError(dataset_id)
        records = self._parse_dataset(dataset)
        replayed: list[PublicReplayRecordResult] = []
        pipelines: list[DetectionPipelineResult] = []
        for source_record_id, raw_digest, event in records:
            normalized = self._normalizer.normalize(event)
            detection = self._sigma_engine.evaluate(normalized)
            pipeline = DetectionPipelineResult(normalized=normalized, detection=detection)
            pipelines.append(pipeline)
            replayed.append(
                PublicReplayRecordResult(
                    source_record_id=source_record_id,
                    raw_record_sha256=raw_digest,
                    converted_event=event,
                    normalized=normalized,
                    detection=detection,
                )
            )
        correlation = self._correlation_engine.correlate(pipelines, tenant_id)
        finding_count = sum(len(item.detection.matches) for item in replayed)
        observed_rule_ids = {
            match.rule_id for item in replayed for match in item.detection.matches
        }
        observed_windows = sorted(incident.window_minutes for incident in correlation.incidents)
        observed_deduplicated_count = sum(
            summary.deduplicated_count for summary in correlation.window_summaries
        )
        detection_expectation_met = (
            finding_count == dataset.expected_finding_count
            and observed_rule_ids == set(dataset.expected_rule_ids)
        )
        incident_expectation_met = (
            correlation.incident_count == dataset.expected_incident_count
            and observed_windows == dataset.expected_incident_windows_minutes
            and correlation.entity_graph.node_count == dataset.expected_entity_node_count
            and correlation.entity_graph.edge_count == dataset.expected_entity_edge_count
            and observed_deduplicated_count == dataset.expected_deduplicated_count
        )
        return PublicReplayResult(
            dataset=dataset,
            adapter_version=REPLAY_VERSION,
            records=replayed,
            finding_count=finding_count,
            window_summaries=correlation.window_summaries,
            entity_graph=correlation.entity_graph,
            incidents=correlation.incidents,
            detection_expectation_met=detection_expectation_met,
            incident_expectation_met=incident_expectation_met,
            expectation_met=detection_expectation_met and incident_expectation_met,
        )

    def _load_manifest(self) -> None:
        resource_root = files("app.data").joinpath("replay")
        manifest_resource = resource_root.joinpath("manifest.json")
        try:
            manifest_bytes = manifest_resource.read_bytes()
            payload = json.loads(manifest_bytes)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.validation_issues.append(f"public replay manifest unavailable: {exc}")
            return
        self.manifest_digest_sha256 = sha256(manifest_bytes).hexdigest()
        if not isinstance(payload, dict) or not isinstance(payload.get("datasets"), list):
            self.validation_issues.append("public replay manifest requires a datasets list")
            return
        try:
            self.quality_targets = DetectionQualityTargets.model_validate(
                payload.get("quality_targets", {})
            )
            self.incident_quality_targets = IncidentQualityTargets.model_validate(
                payload.get("incident_quality_targets", {})
            )
        except (TypeError, ValueError) as exc:
            self.validation_issues.append(f"public replay quality targets are invalid: {exc}")
            return

        seen_ids: set[str] = set()
        approved_rule_ids = {rule.rule_id for rule in self._sigma_engine.summaries()}
        for document in payload["datasets"]:
            try:
                dataset = PublicReplayDataset.model_validate(document)
                if dataset.dataset_id in seen_ids:
                    raise ValueError(f"duplicate public replay dataset: {dataset.dataset_id}")
                seen_ids.add(dataset.dataset_id)
                unknown_rules = set(dataset.expected_rule_ids) - approved_rule_ids
                if unknown_rules:
                    raise ValueError(
                        f"unknown expected rules for {dataset.dataset_id}: {sorted(unknown_rules)}"
                    )
                fixture = resource_root.joinpath(dataset.fixture_name)
                fixture_bytes = fixture.read_bytes()
                fixture_digest = sha256(fixture_bytes).hexdigest()
                if fixture_digest != dataset.fixture_sha256:
                    raise ValueError(
                        f"fixture digest mismatch for {dataset.dataset_id}: {fixture_digest}"
                    )
                records = self._parse_dataset(dataset)
                if len(records) != dataset.record_count:
                    raise ValueError(
                        f"record count mismatch for {dataset.dataset_id}: {len(records)}"
                    )
                self._datasets.append(dataset)
            except (OSError, TypeError, ValueError, ET.ParseError, json.JSONDecodeError) as exc:
                dataset_name = (
                    document.get("dataset_id", "unknown")
                    if isinstance(document, dict)
                    else "unknown"
                )
                self.validation_issues.append(f"{dataset_name}: {exc}")

    def _parse_dataset(
        self,
        dataset: PublicReplayDataset,
    ) -> list[tuple[str, str, SecurityEvent]]:
        fixture = files("app.data").joinpath("replay", dataset.fixture_name)
        fixture_bytes = fixture.read_bytes()
        if dataset.adapter == "windows_event_xml":
            return _parse_windows_events(fixture_bytes)
        if dataset.adapter == "wiz_audit_json":
            return _parse_wiz_events(fixture_bytes)
        return _parse_aws_console_failures(fixture_bytes)


def _parse_windows_events(data: bytes) -> list[tuple[str, str, SecurityEvent]]:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ValueError("XML document type and entity declarations are not supported")
    root = ET.fromstring(data)
    records: list[tuple[str, str, SecurityEvent]] = []
    for element in root.findall("event:Event", _WINDOWS):
        event_id = _required_xml_text(element, "event:System/event:EventID")
        logon_type = _windows_data(element, "LogonType")
        if event_id != "4624" or logon_type != "10":
            continue
        record_id = _required_xml_text(element, "event:System/event:EventRecordID")
        computer = _required_xml_text(element, "event:System/event:Computer")
        timestamp_element = element.find("event:System/event:TimeCreated", _WINDOWS)
        if timestamp_element is None or not timestamp_element.get("SystemTime"):
            raise ValueError(f"Windows record {record_id} has no SystemTime")
        raw_record = ET.tostring(element, encoding="utf-8")
        source_ip = _windows_data(element, "IpAddress")
        user_name = _windows_data(element, "TargetUserName")
        event = SecurityEvent(
            event_id=f"public-splunk-rdp-{record_id}",
            timestamp=_parse_timestamp(timestamp_element.get("SystemTime", "")),
            user=UserContext(user_id=user_name, role="administrator", active=True),
            device=DeviceContext(
                device_id=f"remote-{source_ip}",
                managed=True,
                security_posture="healthy",
            ),
            network=NetworkContext(
                ip=source_ip,
                location="attack-range-lab",
                access_method="remote",
                location_anomaly=False,
            ),
            resource=ResourceContext(
                resource_id=computer,
                resource_type="windows-host",
                sensitivity="high",
                required_role="administrator",
            ),
            action=EventAction.REMOTE_ACCESS,
            auth_context=AuthContext(
                authentication_result="success",
                mfa="unknown",
                failed_attempts=0,
            ),
            behavior=BehaviorContext(
                event_text="Windows Security Event 4624 Logon Type 10"
            ),
        )
        records.append((record_id, sha256(raw_record).hexdigest(), event))
    return records


def _parse_wiz_events(data: bytes) -> list[tuple[str, str, SecurityEvent]]:
    payload = json.loads(data)
    if not isinstance(payload, list):
        raise TypeError("Wiz audit fixture must be a list")
    records: list[tuple[str, str, SecurityEvent]] = []
    for document in payload:
        if not isinstance(document, dict):
            raise TypeError("Wiz audit records must be objects")
        action_parameters = document.get("actionParameters")
        service_account = document.get("serviceAccount")
        if not isinstance(action_parameters, dict) or not isinstance(service_account, dict):
            raise TypeError("Wiz audit record is missing account context")
        record_id = _required_json_string(document, "id")
        raw_record = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        user_id = _required_json_string(action_parameters, "userID")
        service_id = _required_json_string(service_account, "id")
        user_pool = _required_json_string(action_parameters, "userpoolID")
        event = SecurityEvent(
            event_id=f"public-sentinel-wiz-{record_id}",
            timestamp=_parse_timestamp(_required_json_string(document, "timestamp")),
            user=UserContext(user_id=user_id, role="cloud-user", active=True),
            device=DeviceContext(
                device_id=service_id,
                managed=True,
                security_posture="healthy",
            ),
            network=NetworkContext(
                ip=document.get("sourceIP") or "0.0.0.0",
                location="public-sample",
                access_method="unknown",
                location_anomaly=False,
            ),
            resource=ResourceContext(
                resource_id=user_pool,
                resource_type="cloud-identity-service",
                sensitivity="internal",
                required_role="cloud-user",
            ),
            action=EventAction.LOGIN,
            auth_context=AuthContext(
                authentication_result="success",
                mfa="unknown",
                failed_attempts=0,
            ),
            behavior=BehaviorContext(event_text="Wiz audit successful login"),
        )
        records.append((record_id, sha256(raw_record).hexdigest(), event))
    return records


def _parse_aws_console_failures(data: bytes) -> list[tuple[str, str, SecurityEvent]]:
    source_lines = [line.strip() for line in data.splitlines() if line.strip()]
    documents = [json.loads(line) for line in source_lines]
    if not all(isinstance(document, dict) for document in documents):
        raise TypeError("AWS CloudTrail fixture records must be objects")

    failure_counts = Counter(
        _required_json_string(document, "sourceIPAddress") for document in documents
    )
    records: list[tuple[str, str, SecurityEvent]] = []
    for raw_record, document in zip(source_lines, documents, strict=True):
        identity = document.get("userIdentity")
        response = document.get("responseElements")
        if not isinstance(identity, dict) or not isinstance(response, dict):
            raise TypeError("AWS CloudTrail record is missing identity or response context")
        if document.get("eventName") != "ConsoleLogin" or response.get("ConsoleLogin") != "Failure":
            raise ValueError("AWS CloudTrail replay accepts failed ConsoleLogin records only")

        record_id = _required_json_string(document, "eventID")
        source_ip = _required_json_string(document, "sourceIPAddress")
        account_id = _required_json_string(identity, "accountId")
        user_id = _required_json_string(identity, "userName")
        region = _required_json_string(document, "awsRegion")
        failures = failure_counts[source_ip]
        event = SecurityEvent(
            event_id=f"public-splunk-aws-{record_id}",
            timestamp=_parse_timestamp(_required_json_string(document, "eventTime")),
            user=UserContext(user_id=user_id, role="cloud-user", active=True),
            device=DeviceContext(
                device_id=f"aws-console-{source_ip}",
                managed=False,
                security_posture="unknown",
            ),
            network=NetworkContext(
                ip=source_ip,
                location=f"aws-{region}",
                access_method="remote",
                location_anomaly=False,
            ),
            resource=ResourceContext(
                resource_id=f"aws-account-{account_id}",
                resource_type="cloud-account",
                sensitivity="critical",
                required_role="cloud-user",
            ),
            action=EventAction.LOGIN,
            auth_context=AuthContext(
                authentication_result="failure",
                mfa="unknown",
                failed_attempts=failures,
            ),
            behavior=BehaviorContext(
                request_rate="high" if failures >= 3 else "normal",
                event_text="AWS CloudTrail ConsoleLogin Failure",
            ),
        )
        records.append((record_id, sha256(raw_record).hexdigest(), event))
    return records


def _required_xml_text(element: ET.Element, path: str) -> str:
    child = element.find(path, _WINDOWS)
    if child is None or not child.text:
        raise ValueError(f"Windows event is missing {path}")
    return child.text.strip()


def _windows_data(element: ET.Element, name: str) -> str:
    for item in element.findall("event:EventData/event:Data", _WINDOWS):
        if item.get("Name") == name and item.text:
            return item.text.strip()
    raise ValueError(f"Windows event is missing EventData.{name}")


def _required_json_string(document: dict, key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"public replay record is missing {key}")
    return value.strip()


def _parse_timestamp(value: str) -> datetime:
    normalized = re.sub(
        r"\.(\d{6})\d+(?=Z$)",
        r".\1",
        value.strip(),
    ).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("public replay timestamp must include a timezone")
    return parsed


@lru_cache
def get_public_replay_service() -> PublicReplayService:
    return PublicReplayService(
        get_ocsf_normalizer(),
        get_sigma_engine(),
        get_correlation_engine(),
    )
