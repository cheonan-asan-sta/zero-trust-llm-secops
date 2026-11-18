"""Check a local regression evidence bundle; this is not an independent witness."""

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

RUNS = (
    "full_native_linux",
    "windows_expanded",
    "corrected_contract_linux",
    "corrected_contract_windows",
)


def _read_inside(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("Evidence path must be repository-relative")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Evidence file is outside the repository or missing")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Evidence file exceeds local verification bound")
    return path.read_bytes()


def verify(repository_root, report_path):
    root = Path(repository_root).resolve()
    report = json.loads(_read_inside(root, report_path))
    actual = {}
    for key in RUNS:
        recorded = report[key]
        raw = _read_inside(root, recorded["repository_xml"])
        if hashlib.sha256(raw).hexdigest() != recorded["sha256"]:
            raise ValueError(f"{key}: XML SHA-256 mismatch")
        xml = ET.fromstring(raw)
        cases = list(xml.iter("testcase"))
        nodes, failed, passed = set(), set(), set()
        counts = dict.fromkeys(("tests", "failures", "errors", "skipped", "passed"), 0)
        for case in cases:
            node = case.get("classname"), case.get("name")
            if None in node or node in nodes:
                raise ValueError(f"{key}: missing or duplicate testcase identity")
            nodes.add(node)
            counts["tests"] += 1
            statuses = [
                name for name in ("failure", "error", "skipped") if case.find(name) is not None
            ]
            if len(statuses) > 1:
                raise ValueError(f"{key}: ambiguous testcase outcome")
            if not statuses:
                counts["passed"] += 1
                passed.add(node)
            elif statuses[0] == "skipped":
                counts["skipped"] += 1
            else:
                counts["failures" if statuses[0] == "failure" else "errors"] += 1
                failed.add(node)
        for name, value in counts.items():
            if int(recorded[name]) != value:
                raise ValueError(f"{key}: recorded {name} disagrees with XML testcase outcomes")
        recorded_failed = {(node["classname"], node["name"]) for node in recorded["failed_nodes"]}
        if recorded_failed != failed:
            raise ValueError(f"{key}: recorded failure identities disagree with XML")
        actual[key] = {"counts": counts, "failed": failed, "passed": passed}
    for original, recheck in (
        ("full_native_linux", "corrected_contract_linux"),
        ("windows_expanded", "corrected_contract_windows"),
    ):
        if not actual[original]["failed"] <= actual[recheck]["passed"]:
            raise ValueError(f"{original}: failed nodes are not all passing in the recheck")
        if actual[recheck]["failed"]:
            raise ValueError(f"{recheck}: recheck still has failed nodes")
    return {
        "ok": True,
        "scope": "local_report_xml_consistency_not_independent_witness",
        "fresh_full_suite_green": False,
        "runs": {key: value["counts"] for key, value in actual.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--report", default="docs/infrastructure-results/extra-local-validation-20261119.json"
    )
    args = parser.parse_args()
    try:
        result = verify(args.repository_root, args.report)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        parser.exit(1, f"Local evidence verification failed: {error}\n")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
