"""Reject altered evidence and unsupported regression-success claims."""

import hashlib
import json

import pytest

from scripts.verify_extra_local_validation import RUNS, verify


@pytest.fixture
def bundle(tmp_path):
    report = {}
    for key in RUNS:
        recheck = key.startswith("corrected")
        xml = (
            '<testsuite><testcase classname="tests.sample" name="ordinary"/>'
            '<testcase classname="tests.sample" name="contract">'
            + ("" if recheck else '<failure message="old expectation"/>')
            + "</testcase></testsuite>"
        ).encode()
        (tmp_path / (key + ".xml")).write_bytes(xml)
        report[key] = {
            "repository_xml": key + ".xml",
            "sha256": hashlib.sha256(xml).hexdigest(),
            "tests": 2,
            "passed": 2 if recheck else 1,
            "failures": 0 if recheck else 1,
            "errors": 0,
            "skipped": 0,
            "failed_nodes": [] if recheck else [{"classname": "tests.sample", "name": "contract"}],
        }

    def save():
        (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")

    save()
    return tmp_path, report, save


def test_preserves_raw_failures_and_distinguishes_recheck_from_full_green(bundle):
    root, _, _ = bundle
    result = verify(root, "report.json")
    assert result["ok"] and not result["fresh_full_suite_green"]
    assert result["runs"]["full_native_linux"]["failures"] == 1
    assert result["runs"]["corrected_contract_linux"]["passed"] == 2


def test_altered_xml_is_rejected_without_rewriting_evidence(bundle):
    root, _, _ = bundle
    path = root / "full_native_linux.xml"
    path.write_bytes(path.read_bytes() + b" ")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="SHA-256"):
        verify(root, "report.json")
    assert path.read_bytes() == before


def test_forged_success_count_does_not_override_actual_xml(bundle):
    root, report, save = bundle
    report["full_native_linux"].update(failures=0, passed=2)
    save()
    with pytest.raises(ValueError, match="disagrees"):
        verify(root, "report.json")


def test_different_passing_case_does_not_cover_the_original_failure(bundle):
    root, report, save = bundle
    path = root / "corrected_contract_linux.xml"
    raw = path.read_bytes().replace(b'name="contract"', b'name="unrelated"')
    path.write_bytes(raw)
    report["corrected_contract_linux"]["sha256"] = hashlib.sha256(raw).hexdigest()
    save()
    with pytest.raises(ValueError, match="not all passing"):
        verify(root, "report.json")


def test_report_cannot_hide_original_failure_identity(bundle):
    root, report, save = bundle
    report["full_native_linux"]["failed_nodes"] = []
    save()
    with pytest.raises(ValueError, match="failure identities"):
        verify(root, "report.json")


def test_report_cannot_read_outside_repository(bundle):
    root, report, save = bundle
    report["full_native_linux"]["repository_xml"] = "../outside.xml"
    save()
    with pytest.raises(ValueError, match="outside"):
        verify(root, "report.json")


def test_duplicate_case_identity_cannot_inflate_passing_counts(bundle):
    root, report, save = bundle
    path = root / "corrected_contract_linux.xml"
    raw = path.read_bytes().replace(b'name="contract"', b'name="ordinary"')
    path.write_bytes(raw)
    report["corrected_contract_linux"]["sha256"] = hashlib.sha256(raw).hexdigest()
    save()
    with pytest.raises(ValueError, match="duplicate"):
        verify(root, "report.json")
