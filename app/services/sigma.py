import fnmatch
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from importlib.resources import files
from uuid import UUID

import yaml

from app.models import (
    NormalizedSecurityEvent,
    SigmaDetectionMatch,
    SigmaDetectionResult,
    SigmaRuleLevel,
    SigmaRuleLifecycle,
    SigmaRuleSummary,
)

ENGINE_VERSION = "0.11.0"
SIGMA_SPECIFICATION_VERSION = "2.1.0"
_RULE_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
_SUPPORTED_MODIFIERS = {
    "all",
    "cased",
    "contains",
    "endswith",
    "exists",
    "fieldref",
    "gt",
    "gte",
    "lt",
    "lte",
    "neq",
    "startswith",
}
_CONDITION_TOKEN = re.compile(
    r"\s*(\(|\)|1|all|and|or|not|of|them|[A-Za-z_][A-Za-z0-9_*]*)",
    re.IGNORECASE,
)
_LEVEL_ORDER = {
    SigmaRuleLevel.INFORMATIONAL: 0,
    SigmaRuleLevel.LOW: 1,
    SigmaRuleLevel.MEDIUM: 2,
    SigmaRuleLevel.HIGH: 3,
    SigmaRuleLevel.CRITICAL: 4,
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


ConditionNode = tuple


class _ConditionParser:
    def __init__(self, condition: str, selector_names: set[str]) -> None:
        self.tokens = self._tokenize(condition)
        self.position = 0
        self.selector_names = selector_names

    def parse(self) -> ConditionNode:
        node = self._parse_or()
        if self.position != len(self.tokens):
            raise ValueError(f"unexpected condition token: {self.tokens[self.position]}")
        return node

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(condition):
            match = _CONDITION_TOKEN.match(condition, position)
            if not match:
                raise ValueError(f"unsupported Sigma condition near: {condition[position:]}")
            tokens.append(match.group(1).lower())
            position = match.end()
        if not tokens:
            raise ValueError("Sigma condition cannot be empty")
        return tokens

    def _parse_or(self) -> ConditionNode:
        node = self._parse_and()
        while self._take("or"):
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> ConditionNode:
        node = self._parse_not()
        while self._take("and"):
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self) -> ConditionNode:
        if self._take("not"):
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> ConditionNode:
        if self._take("("):
            node = self._parse_or()
            self._expect(")")
            return node

        token = self._next()
        if token in {"1", "all"}:
            self._expect("of")
            pattern = self._next()
            if pattern != "them" and "*" not in pattern:
                raise ValueError("Sigma quantifier requires 'them' or a wildcard selector pattern")
            return ("quantifier", token, pattern)
        if token not in self.selector_names:
            raise ValueError(f"unknown Sigma selector in condition: {token}")
        return ("selector", token)

    def _take(self, token: str) -> bool:
        if self.position < len(self.tokens) and self.tokens[self.position] == token:
            self.position += 1
            return True
        return False

    def _expect(self, token: str) -> None:
        if not self._take(token):
            actual = self.tokens[self.position] if self.position < len(self.tokens) else "<end>"
            raise ValueError(f"expected '{token}' in Sigma condition, got '{actual}'")

    def _next(self) -> str:
        if self.position >= len(self.tokens):
            raise ValueError("unexpected end of Sigma condition")
        token = self.tokens[self.position]
        self.position += 1
        return token


@dataclass(frozen=True)
class _CompiledRule:
    summary: SigmaRuleSummary
    detection: dict[str, object]
    condition: ConditionNode


class SigmaEngine:
    def __init__(self, rules: list[_CompiledRule], validation_issues: list[str]) -> None:
        self._rules = rules
        self.validation_issues = validation_issues
        digest_input = [
            f"{rule.summary.rule_id}:{rule.summary.digest_sha256}"
            for rule in sorted(rules, key=lambda item: item.summary.rule_id)
        ]
        self.ruleset_digest_sha256 = sha256("\n".join(digest_input).encode()).hexdigest()

    @property
    def valid(self) -> bool:
        return not self.validation_issues and bool(self.approved_rules)

    @property
    def approved_rules(self) -> list[_CompiledRule]:
        return [
            rule
            for rule in self._rules
            if rule.summary.lifecycle == SigmaRuleLifecycle.APPROVED
            and rule.summary.status in {"test", "stable"}
        ]

    def summaries(self) -> list[SigmaRuleSummary]:
        return [rule.summary for rule in self._rules]

    def evaluate(self, normalized: NormalizedSecurityEvent) -> SigmaDetectionResult:
        event = normalized.event.model_dump(mode="json", exclude_none=True)
        matches: list[SigmaDetectionMatch] = []
        for rule in self.approved_rules:
            selector_results = {
                name: _match_selector(selector, event)
                for name, selector in rule.detection.items()
                if name != "condition"
            }
            if not _evaluate_condition(rule.condition, selector_results):
                continue
            matched_selectors = sorted(
                name for name, matched in selector_results.items() if matched
            )
            matches.append(
                SigmaDetectionMatch(
                    **rule.summary.model_dump(),
                    matched_selectors=matched_selectors,
                )
            )

        highest = max(
            (match.level for match in matches),
            key=lambda level: _LEVEL_ORDER[level],
            default=None,
        )
        return SigmaDetectionResult(
            engine_version=ENGINE_VERSION,
            specification_version=SIGMA_SPECIFICATION_VERSION,
            ruleset_digest_sha256=self.ruleset_digest_sha256,
            evaluated_rule_count=len(self.approved_rules),
            matches=matches,
            highest_level=highest,
        )

    @classmethod
    def from_documents(cls, documents: list[tuple[str, object]]) -> "SigmaEngine":
        rules: list[_CompiledRule] = []
        issues: list[str] = []
        seen_ids: set[str] = set()
        for source_name, document in documents:
            try:
                rule = _compile_rule(document)
                if rule.summary.rule_id in seen_ids:
                    raise ValueError(f"duplicate Sigma rule ID: {rule.summary.rule_id}")
                seen_ids.add(rule.summary.rule_id)
                rules.append(rule)
            except (TypeError, ValueError) as exc:
                issues.append(f"{source_name}: {exc}")
        return cls(rules, issues)


def _compile_rule(document: object) -> _CompiledRule:
    if not isinstance(document, dict):
        raise TypeError("Sigma document must be a mapping")
    title = _required_string(document, "title")
    rule_id = _required_string(document, "id")
    try:
        parsed_id = UUID(rule_id)
    except ValueError as exc:
        raise ValueError("Sigma rule ID must be a UUID") from exc
    if parsed_id.version != 4:
        raise ValueError("Sigma rule ID must be UUIDv4")

    status = _required_string(document, "status")
    if status not in _RULE_STATUSES:
        raise ValueError(f"unsupported Sigma rule status: {status}")
    level = SigmaRuleLevel(_required_string(document, "level"))
    if document.get("taxonomy") != "ocsf":
        raise ValueError("Sigma rules must declare the ocsf taxonomy")
    if not isinstance(document.get("logsource"), dict):
        raise TypeError("Sigma rule requires a logsource mapping")

    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise TypeError("Sigma rule requires a detection mapping")
    condition_text = detection.get("condition")
    if not isinstance(condition_text, str):
        raise TypeError("Sigma detection requires a string condition")
    selectors = {str(key) for key in detection if key != "condition"}
    if not selectors:
        raise ValueError("Sigma detection requires at least one selector")
    normalized_detection = {str(key): value for key, value in detection.items()}
    _validate_selectors(normalized_detection)
    condition = _ConditionParser(condition_text, selectors).parse()

    workflow = document.get("x_secops")
    if not isinstance(workflow, dict):
        raise TypeError("Sigma rule requires x_secops lifecycle metadata")
    lifecycle = SigmaRuleLifecycle(_required_string(workflow, "lifecycle"))
    version = _required_string(workflow, "version")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Sigma rule version must use semantic versioning")
    test_case_ids = workflow.get("test_case_ids", [])
    if not isinstance(test_case_ids, list) or not all(
        isinstance(item, str) and item for item in test_case_ids
    ):
        raise ValueError("x_secops.test_case_ids must be a list of strings")
    if lifecycle == SigmaRuleLifecycle.APPROVED:
        _required_string(workflow, "approved_by")
        _required_string(workflow, "approved_on")
        if not test_case_ids:
            raise ValueError("approved Sigma rules require test_case_ids")

    tags = document.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
        raise ValueError("Sigma tags must be a list of strings")
    digest = sha256(_canonical_json(document)).hexdigest()
    return _CompiledRule(
        summary=SigmaRuleSummary(
            rule_id=rule_id,
            title=title,
            status=status,
            lifecycle=lifecycle,
            level=level,
            version=version,
            digest_sha256=digest,
            tags=tags,
            test_case_ids=test_case_ids,
        ),
        detection=normalized_detection,
        condition=condition,
    )


def _required_string(mapping: dict, key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing string field: {key}")
    return value.strip()


def _validate_selectors(detection: dict[str, object]) -> None:
    for name, selector in detection.items():
        if name == "condition":
            continue
        mappings = selector if isinstance(selector, list) else [selector]
        if not mappings:
            raise ValueError(f"Sigma selector cannot be empty: {name}")
        for mapping in mappings:
            if not isinstance(mapping, dict):
                raise TypeError(f"Sigma selector must contain field mappings: {name}")
            for field_expression in mapping:
                modifiers = str(field_expression).split("|")[1:]
                unsupported = set(modifiers) - _SUPPORTED_MODIFIERS
                if unsupported:
                    raise ValueError(
                        f"unsupported Sigma modifier(s) {sorted(unsupported)} in {field_expression}"
                    )


def _match_selector(selector: object, event: dict[str, object]) -> bool:
    if isinstance(selector, list):
        return any(
            _match_mapping(candidate, event)
            for candidate in selector
            if isinstance(candidate, dict)
        )
    if isinstance(selector, dict):
        return _match_mapping(selector, event)
    return False


def _match_mapping(mapping: dict, event: dict[str, object]) -> bool:
    return all(_match_field(str(expression), expected, event) for expression, expected in mapping.items())


def _match_field(expression: str, expected: object, event: dict[str, object]) -> bool:
    field, *modifiers = expression.split("|")
    exists, actual = _lookup(event, field)
    if "exists" in modifiers:
        return exists is bool(expected)
    if not exists:
        return False

    expected_values = expected if isinstance(expected, list) else [expected]
    predicate = _value_predicate(actual, modifiers, event)
    if "all" in modifiers:
        return all(predicate(value) for value in expected_values)
    return any(predicate(value) for value in expected_values)


def _value_predicate(
    actual: object,
    modifiers: list[str],
    event: dict[str, object],
) -> Callable[[object], bool]:
    def matches(expected: object) -> bool:
        comparison = expected
        if "fieldref" in modifiers:
            if not isinstance(expected, str):
                return False
            found, comparison = _lookup(event, expected)
            if not found:
                return False

        for modifier, operator in {
            "gt": lambda left, right: left > right,
            "gte": lambda left, right: left >= right,
            "lt": lambda left, right: left < right,
            "lte": lambda left, right: left <= right,
        }.items():
            if modifier in modifiers:
                return _numeric_compare(actual, comparison, operator)

        if isinstance(actual, str) and isinstance(comparison, str):
            left = actual if "cased" in modifiers else actual.casefold()
            right = comparison if "cased" in modifiers else comparison.casefold()
            if "contains" in modifiers:
                result = right in left
            elif "startswith" in modifiers:
                result = left.startswith(right)
            elif "endswith" in modifiers:
                result = left.endswith(right)
            elif "*" in right or "?" in right:
                result = fnmatch.fnmatchcase(left, right)
            else:
                result = left == right
        else:
            result = actual == comparison
        return not result if "neq" in modifiers else result

    return matches


def _numeric_compare(actual: object, expected: object, operator: Callable) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
        return False
    return bool(operator(actual, expected))


def _lookup(event: dict[str, object], field: str) -> tuple[bool, object]:
    current: object = event
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _evaluate_condition(node: ConditionNode, selectors: dict[str, bool]) -> bool:
    operation = node[0]
    if operation == "selector":
        return selectors[node[1]]
    if operation == "not":
        return not _evaluate_condition(node[1], selectors)
    if operation == "and":
        return _evaluate_condition(node[1], selectors) and _evaluate_condition(node[2], selectors)
    if operation == "or":
        return _evaluate_condition(node[1], selectors) or _evaluate_condition(node[2], selectors)
    if operation == "quantifier":
        mode, pattern = node[1], node[2]
        candidates = [
            matched
            for name, matched in selectors.items()
            if not name.startswith("_")
            and (pattern == "them" or fnmatch.fnmatchcase(name, pattern))
        ]
        if not candidates:
            return False
        return all(candidates) if mode == "all" else any(candidates)
    raise ValueError(f"unknown condition operation: {operation}")


@lru_cache
def get_sigma_engine() -> SigmaEngine:
    rule_directory = files("app.data").joinpath("sigma")
    documents: list[tuple[str, object]] = []
    loading_issues: list[str] = []
    try:
        resources = sorted(rule_directory.iterdir(), key=lambda item: item.name)
    except (FileNotFoundError, OSError) as exc:
        return SigmaEngine([], [f"Sigma rule directory unavailable: {exc}"])
    for resource in resources:
        if not resource.name.endswith((".yml", ".yaml")):
            continue
        try:
            document = yaml.safe_load(resource.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            loading_issues.append(f"{resource.name}: could not load rule: {exc}")
            continue
        documents.append((resource.name, document))
    engine = SigmaEngine.from_documents(documents)
    if not loading_issues:
        return engine
    return SigmaEngine(engine._rules, [*loading_issues, *engine.validation_issues])
