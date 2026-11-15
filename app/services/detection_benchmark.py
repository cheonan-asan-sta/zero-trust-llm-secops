"""Offline, family-separated operational detection evaluation; no model or cloud calls."""

import hashlib
import json
import random
from collections import Counter, defaultdict
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Literal

from pydantic import Field

from app.models import SecurityEvent, StrictModel
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import get_sigma_engine

Split = Literal["development", "holdout"]


class BenchmarkUnavailable(ValueError):
    pass


class BenchmarkCase(StrictModel):
    case_id: str = Field(min_length=3, max_length=100)
    session_id: str = Field(min_length=3, max_length=120)
    family_id: str = Field(min_length=3, max_length=100)
    split: Split
    domain: str
    threat: bool = Field(strict=True)
    expected_rule_ids: list[str]
    event: SecurityEvent


class Family(StrictModel):
    family_id: str
    domain: str
    split: Split
    threat: bool = Field(strict=True)
    rationale: str = Field(min_length=20)
    patch: dict[str, object]
    variations: dict[str, list[object]]
    approval: bool
    expected_rule_ids: list[str]


class BenchmarkTargets(StrictModel):
    minimum_precision: float = Field(ge=.95, le=1)
    minimum_recall: float = Field(ge=.95, le=1)
    minimum_f1: float = Field(ge=.95, le=1)
    maximum_false_positive_rate: float = Field(ge=0, le=.05)
    minimum_positive_families_per_rule: int = Field(ge=2)
    minimum_negative_families: int = Field(ge=12)


class BenchmarkManifest(StrictModel):
    version: Literal["1.0.0"]
    source_kind: Literal["authored_synthetic"]
    license: Literal["MIT"]
    label_policy: str
    review_status: Literal["author_assigned_pending_independent_team_review"]
    family_count: int = Field(ge=12, le=1000)
    case_count: int = Field(ge=12, le=10000)
    variants_per_family: int = Field(ge=1, le=100)
    generator_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    catalog_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cases_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    targets: BenchmarkTargets


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def signal_pattern(event):
    """Ignore IDs and nuisance context when auditing duplicate detection inputs."""
    return _digest(_canonical({
        "action": event.action, "role": event.user.role, "active": event.user.active,
        "device": event.device.model_dump(exclude={"device_id"}),
        "network": event.network.model_dump(exclude={"ip", "location"}),
        "resource": event.resource.model_dump(exclude={"resource_id"}),
        "auth": event.auth_context.model_dump(exclude={"session_age_minutes"}),
        "behavior": event.behavior.model_dump(exclude={"policy_exception", "event_text"}),
    }))


def confusion(truth, prediction):
    if len(truth) != len(prediction):
        raise ValueError("truth and prediction lengths differ")
    return {
        "tp": sum(t and p for t, p in zip(truth, prediction)),
        "fp": sum(not t and p for t, p in zip(truth, prediction)),
        "fn": sum(t and not p for t, p in zip(truth, prediction)),
        "tn": sum(not t and not p for t, p in zip(truth, prediction)),
    }


def metrics(counts):
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))

    def ratio(n, d):
        return n / d if d else None

    return {"precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn), "false_positive_rate": ratio(fp, fp + tn)}


def _meets(values, targets):
    return {
        key: values[key] is not None and (
            values[key] <= targets["maximum_false_positive_rate"] if key == "false_positive_rate"
            else values[key] >= targets[f"minimum_{key}"]
        ) for key in ("precision", "recall", "f1", "false_positive_rate")
    }


def family_intervals(rows, repetitions=1000, seed=20261101):
    groups = defaultdict(list)
    for row in rows:
        groups[row["family_id"]].append(row)
    positive, negative = [], []
    for group in groups.values():
        counts = confusion([r["threat"] for r in group], [r["detected"] for r in group])
        (positive if group[0]["threat"] else negative).append(counts)
    samples = {key: [] for key in metrics({"tp": 0, "fp": 0, "fn": 0, "tn": 0})}
    rng = random.Random(seed)
    for _ in range(repetitions):
        selected = [*rng.choices(positive, k=len(positive)), *rng.choices(negative, k=len(negative))]
        total = {key: sum(item[key] for item in selected) for key in ("tp", "fp", "fn", "tn")}
        for key, value in metrics(total).items():
            if value is not None:
                samples[key].append(value)

    def percentile(values, fraction):
        values = sorted(values)
        position = (len(values) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(values) - 1)
        return values[lower] + (values[upper] - values[lower]) * (position - lower)

    return {
        "method": "label-stratified-family-cluster-percentile-bootstrap",
        "confidence_level": 0.95, "repetitions": repetitions, "seed": seed,
        "family_count": len(groups),
        "intervals": {key: {"lower": percentile(values, .025) if values else None,
                            "upper": percentile(values, .975) if values else None,
                            "valid_replicates": len(values)} for key, values in samples.items()},
        "scope": "Variation among authored families; not a population guarantee or independent-row interval.",
    }


class DetectionBenchmark:
    def __init__(self, root: Path | None = None, *, engine=None, normalizer=None):
        self.root = root or files("app.data").joinpath("benchmark")
        self.engine = engine or get_sigma_engine()
        self.normalizer = normalizer or get_ocsf_normalizer()
        self.cases: list[BenchmarkCase] = []
        self.families: dict[str, Family] = {}
        self._load()

    def _load(self):
        try:
            raw_manifest = self.root.joinpath("manifest.json").read_bytes()
            self.manifest = BenchmarkManifest.model_validate_json(raw_manifest).model_dump()
            if (self.manifest["version"] != "1.0.0"
                    or self.manifest["source_kind"] != "authored_synthetic"
                    or not self.engine.valid):
                raise ValueError("invalid benchmark or detector")
            self.manifest_digest = _digest(raw_manifest)
            raw_catalog = self.root.joinpath("families.json").read_bytes()
            raw_cases = self.root.joinpath("cases.jsonl").read_bytes()
            if len(raw_cases) > 10_000_000:
                raise ValueError("benchmark too large")
            if (_digest(raw_catalog) != self.manifest["catalog_sha256"]
                    or _digest(raw_cases) != self.manifest["cases_sha256"]):
                raise ValueError("benchmark digest mismatch")
            families = [Family.model_validate(item) for item in json.loads(raw_catalog)]
            self.families = {item.family_id: item for item in families}
            self.cases = [BenchmarkCase.model_validate_json(line) for line in raw_cases.splitlines()]
            if (len(self.families) != len(families) or len(families) != self.manifest["family_count"]
                    or len(self.cases) != self.manifest["case_count"]):
                raise ValueError("benchmark count or duplicate family mismatch")
            known = {rule.rule_id for rule in self.engine.summaries()}
            seen = {key: set() for key in ("case", "session", "event")}
            by_split = {split: defaultdict(set) for split in ("development", "holdout")}
            family_counts = Counter()
            for case in self.cases:
                family = self.families[case.family_id]
                if ((case.split, case.threat, case.domain, case.expected_rule_ids)
                        != (family.split, family.threat, family.domain, family.expected_rule_ids)
                        or case.event.ground_truth is not None
                        or bool(case.expected_rule_ids) != case.threat
                        or not set(case.expected_rule_ids) <= known):
                    raise ValueError("case label, split or target rule mismatch")
                for kind, value in (("case", case.case_id), ("session", case.session_id),
                                    ("event", case.event.event_id)):
                    if value in seen[kind]:
                        raise ValueError("duplicate case, session or event")
                    seen[kind].add(value)
                family_counts[case.family_id] += 1
                groups = by_split[case.split]
                for kind, value in (("family", case.family_id), ("session", case.session_id),
                                    ("user", case.event.user.user_id), ("device", case.event.device.device_id),
                                    ("pattern", signal_pattern(case.event))):
                    groups[kind].add(value)
            if set(family_counts) != set(self.families) or any(
                count != self.manifest["variants_per_family"] for count in family_counts.values()
            ):
                raise ValueError("family support mismatch")
            self.overlap = {kind: len(by_split["development"][kind] & by_split["holdout"][kind])
                            for kind in ("family", "session", "user", "device", "pattern")}
            if any(self.overlap.values()):
                raise ValueError(f"development/holdout leakage: {self.overlap}")
            for split in by_split:
                subset = [case for case in self.cases if case.split == split]
                if {c.threat for c in subset} != {True, False}:
                    raise ValueError("split requires both labels")
            if max(c.event.timestamp for c in self.cases if c.split == "development") >= min(
                c.event.timestamp for c in self.cases if c.split == "holdout"
            ):
                raise ValueError("development must precede holdout in time")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise BenchmarkUnavailable(f"Detection benchmark validation failed: {exc}") from exc

    def evaluate(self, split: Split = "holdout"):
        if split not in ("development", "holdout"):
            raise ValueError("unknown split")
        cases = [case for case in self.cases if case.split == split]
        rows = []
        for case in cases:
            error = None
            try:
                # Labels, rationales, IDs of expected rules and split metadata never enter the detector.
                normalized = self.normalizer.normalize(case.event)
                result = self.engine.evaluate(normalized)
                predicted = sorted(match.rule_id for match in result.matches)
            except (ValueError, TypeError, RuntimeError):
                predicted, error = [], "evaluation_failed"
            detected = bool(predicted)
            rows.append({"case_id": case.case_id, "session_id": case.session_id,
                         "family_id": case.family_id, "domain": case.domain, "threat": case.threat,
                         "detected": detected, "expected_rule_ids": case.expected_rule_ids,
                         "predicted_rule_ids": predicted, "error": error,
                         "outcome": "TP" if case.threat and detected else "FN" if case.threat else "FP" if detected else "TN",
                         "pattern_sha256": signal_pattern(case.event)})
        counts = confusion([r["threat"] for r in rows], [r["detected"] for r in rows])
        scores = metrics(counts)
        checks = _meets(scores, self.manifest["targets"])
        rules = []
        for rule in self.engine.summaries():
            expected = [rule.rule_id in row["expected_rule_ids"] for row in rows]
            predicted = [rule.rule_id in row["predicted_rule_ids"] for row in rows]
            rule_counts = confusion(expected, predicted)
            values = metrics(rule_counts)
            positive_families = len({r["family_id"] for r in rows if rule.rule_id in r["expected_rule_ids"]})
            supported = positive_families >= self.manifest["targets"]["minimum_positive_families_per_rule"]
            rules.append({"rule_id": rule.rule_id, "title": rule.title, "confusion": rule_counts,
                          "metrics": values, "positive_family_count": positive_families,
                          "negative_count": rule_counts["fp"] + rule_counts["tn"],
                          "support_sufficient": supported,
                          "targets_met": _meets(values, self.manifest["targets"]),
                          "passed": supported and all(_meets(values, self.manifest["targets"]).values())})
        negative_families = len({r["family_id"] for r in rows if not r["threat"]})
        checks.update(
            evaluation_errors=sum(r["error"] is not None for r in rows) == 0,
            every_rule_supported=all(rule["support_sufficient"] for rule in rules),
            every_rule_meets_targets=all(rule["passed"] for rule in rules),
            negative_family_support=negative_families >= self.manifest["targets"]["minimum_negative_families"],
        )
        intervals = family_intervals(rows)
        bounds = intervals["intervals"]
        statistical_support = all(checks.values()) and all(
            (bounds[key]["upper"] is not None and bounds[key]["upper"] <= .05)
            if key == "false_positive_rate" else
            (bounds[key]["lower"] is not None and bounds[key]["lower"] >= .95)
            for key in scores
        )
        unique_rows = list({(r["pattern_sha256"], r["threat"]): r for r in rows}.values())
        pattern_labels = defaultdict(set)
        for row in rows:
            pattern_labels[row["pattern_sha256"]].add(row["threat"])
        unique_counts = confusion([r["threat"] for r in unique_rows], [r["detected"] for r in unique_rows])
        domains = {}
        for domain in sorted({row["domain"] for row in rows}):
            selected = [row for row in rows if row["domain"] == domain]
            domain_counts = confusion([r["threat"] for r in selected], [r["detected"] for r in selected])
            domains[domain] = {"confusion": domain_counts, "metrics": metrics(domain_counts)}
        fingerprint = _digest(_canonical({"manifest": self.manifest_digest,
                                         "ruleset": self.engine.ruleset_digest_sha256,
                                         "mapping": self.normalizer.mapping_digest_sha256,
                                         "split": split, "rows": rows}))
        return {
            "evaluation_version": "1.0.0", "source_kind": "authored_synthetic", "split": split,
            "label_policy": self.manifest["label_policy"], "review_status": self.manifest["review_status"],
            "corpus_case_count": len(self.cases), "corpus_family_count": len(self.families),
            "case_count": len(cases), "family_count": len({c.family_id for c in cases}),
            "threat_count": counts["tp"] + counts["fn"], "benign_count": counts["tn"] + counts["fp"],
            "unique_signal_pattern_count": len({r["pattern_sha256"] for r in rows}),
            "duplicate_pattern_label_count": len(rows) - len(unique_rows),
            "ambiguous_pattern_count": sum(len(labels) > 1 for labels in pattern_labels.values()),
            "deduplicated": {"case_count": len(unique_rows), "confusion": unique_counts,
                             "metrics": metrics(unique_counts)},
            "confusion": counts, "metrics": scores, "confidence": intervals,
            "statistical_target_supported": statistical_support,
            "targets": self.manifest["targets"], "targets_met": checks, "gate_passed": all(checks.values()),
            "evaluation_error_count": sum(r["error"] is not None for r in rows),
            "split_overlap_counts": self.overlap, "rule_coverage_rate": sum(r["support_sufficient"] for r in rules) / len(rules),
            "rules": rules, "domains": domains, "cases": rows,
            "macro_rule_metrics": {
                key: sum(rule["metrics"][key] for rule in rules) / len(rules)
                if all(rule["metrics"][key] is not None for rule in rules) else None
                for key in scores
            },
            "manifest_digest_sha256": self.manifest_digest,
            "cases_digest_sha256": self.manifest["cases_sha256"],
            "ruleset_digest_sha256": self.engine.ruleset_digest_sha256,
            "evaluation_fingerprint_sha256": fingerprint,
            "limitations": [
                "Authored operational labels await independent team review; holdout is family-separated, not an external blind test.",
                "Variants share scenario mechanics and are not independent real-world attacks; inspect unique patterns and family intervals.",
                "Balanced case mix does not represent enterprise threat prevalence.",
                "Evaluates Sigma event alerts, not LLM accuracy, session policy enforcement or incident correlation.",
                "Rules were not tuned on this holdout; benchmark failure is an observed result, not a test-runner error.",
            ],
        }


@lru_cache
def get_detection_benchmark():
    return DetectionBenchmark()
