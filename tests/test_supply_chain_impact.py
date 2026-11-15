import copy
import json
import sys
from pathlib import Path

import pytest

from scripts import assess_supply_chain as impact
from scripts.review_supply_chain import digest
from scripts.supply_chain_runtime_probe import scan_references

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "docs/infrastructure-results/c03-impact-inputs-20261105.json"
REVIEW = ROOT / "docs/infrastructure-results/c03-findings-review-20261105.json"


@pytest.fixture
def evidence():
    return json.loads(INPUT.read_text(encoding="utf-8")), json.loads(REVIEW.read_text(encoding="utf-8"))


def by_advisory(report, identity):
    return next(row for row in report["findings"] if identity in row["advisory_ids"])


def test_real_inventory_review_preserves_all_findings_and_never_grants_approval(evidence):
    packet, review = evidence
    report = impact.assess(packet, review)
    assert report["counts"]["findings"] == 200
    assert report["counts"]["vendor_coverage"] == 200
    assert report["counts"]["priorities"] == {"P1": 17, "P2": 178, "P3": 5}
    assert {r["group_id"] for r in report["findings"]} == {g["id"] for g in review["groups"]}
    assert all(not r["waiver_or_suppression"] and not r["upstream_fixed_in_image"]
               and r["independent_review"] == "pending" for r in report["findings"])
    assert not report["security_gate_passed"] and not report["production_approved"]


def test_unimportant_severity_and_absent_systemd_do_not_discard_shared_libraries(evidence):
    report = impact.assess(*evidence)
    rows = [r for r in report["findings"] if r["vendor_fact"].get("source_package") == "systemd"]
    assert len(rows) == 14
    assert all(r["infra_disposition"] == "vendor_open_shared_library" for r in rows)
    differences = [r for r in report["findings"] if "severity_disagreement" in r["original_flags"]]
    assert len(differences) == 78
    assert all(not r["waiver_or_suppression"] for r in differences)


def test_metadata_package_review_does_not_clear_other_packages_from_same_source(evidence):
    report = impact.assess(*evidence)
    gcc = [r for r in report["findings"] if r["vendor_fact"].get("source_package") == "gcc-14"]
    assert sum(r["infra_disposition"] == "source_match_metadata_package" for r in gcc) == 5
    assert sum(r["infra_disposition"] == "vendor_open_shared_library" for r in gcc) == 10


def test_sqlite_linkage_and_extensions_are_not_equated_with_successful_exploitation(evidence):
    report = impact.assess(*evidence)
    rows = [r for r in report["findings"] if r["package"]["name"] == "libsqlite3-0"]
    assert len(rows) == 14
    assert all(r["action_priority"] == "P1" and r["exploitability"] == "not_demonstrated" for r in rows)


@pytest.mark.parametrize("feature,advisory,expected", [
    ("pip_invoked_data_filter", "GHSA-4xh5-x5gv-qwph", "specific_pip_fallback_precondition_mitigated"),
    ("pip_install_disables_version_check", "GHSA-jp4c-xjxw-mgf9", "specific_pip_self_check_precondition_mitigated"),
])
def test_mitigation_requires_observed_precondition_and_never_closes_advisory(evidence, feature, advisory, expected):
    packet, review = evidence
    before = by_advisory(impact.assess(packet, review), advisory)
    assert before["infra_disposition"] == expected
    packet["runtime"]["features"][feature] = False
    after = by_advisory(impact.assess(packet, review), advisory)
    assert after["infra_disposition"] == "conditional_build_input_risk"
    assert not before["upstream_fixed_in_image"] and not after["upstream_fixed_in_image"]


def test_presence_of_init_reopens_the_specific_boot_precondition(evidence):
    packet, review = evidence
    packet["runtime"]["commands"]["init"]["path"] = "/sbin/init"
    row = by_advisory(impact.assess(packet, review), "TEMP-0517018-A83CE6")
    assert row["infra_disposition"] == "conditional_local_or_maintenance_risk"


def test_vendor_resolved_status_still_requires_installed_backport_review(evidence):
    packet, review = evidence
    fact = next(f for f in packet["vendor_facts"] if f["package"]["ecosystem"] == "deb")
    fact["release_record"]["status"] = "resolved"
    report = impact.assess(packet, review)
    row = next(r for r in report["findings"] if r["group_id"] == fact["group_id"])
    assert row["infra_disposition"] == "vendor_state_changed_review_required"
    assert not row["upstream_fixed_in_image"]


@pytest.mark.parametrize("change,code", [
    (lambda p: p["image"].update(id="sha256:" + "0" * 64), "historical_image_mismatch"),
    (lambda p: p["runtime"].update(uid=0), "unverified_runtime_controls"),
    (lambda p: p["runtime"].update(rootfs_readonly=False), "unverified_runtime_controls"),
    (lambda p: p["runtime"]["process_security"].update(NoNewPrivs="0"), "unverified_runtime_controls"),
    (lambda p: p["runtime"]["process_security"].update(CapBnd="1"), "unverified_runtime_controls"),
    (lambda p: p["probe_campaign"]["runs"][0].update(network="bridge"), "unverified_probe_isolation"),
    (lambda p: p["probe_campaign"]["runs"][0].update(privileged=True), "unverified_probe_isolation"),
    (lambda p: p["probe_campaign"]["runs"][0].update(output_sha256="0" * 64), "probe_repeats_unverified"),
    (lambda p: p["vendor_facts"].pop(), "vendor_coverage_mismatch"),
    (lambda p: p["vendor_facts"].append(copy.deepcopy(p["vendor_facts"][0])), "duplicate_evidence_row"),
    (lambda p: p["vendor_facts"][0]["package"].update(version="wrong"), "vendor_finding_scope_mismatch"),
    (lambda p: p["vendor_sources"]["debian-tracker"].update(status=404), "vendor_source_not_verified"),
    (lambda p: p["vendor_sources"]["debian-tracker"].update(url="https://example.com/data"), "unexpected_debian_source"),
])
def test_wrong_image_controls_custody_or_coverage_are_rejected(evidence, change, code):
    packet, review = evidence
    change(packet)
    with pytest.raises(ValueError, match=code):
        impact.assess(packet, review)


@pytest.mark.parametrize("field,value,code", [
    ("source_package", "wrong-source", "debian_source_mapping_mismatch"),
    ("source_version", "999", "debian_source_mapping_mismatch"),
    ("release", "bookworm", "debian_source_mapping_mismatch"),
])
def test_binary_version_and_debian_source_version_cannot_be_interchanged(evidence, field, value, code):
    packet, review = evidence
    fact = next(f for f in packet["vendor_facts"] if f["package"]["name"] == "bash")
    fact[field] = value
    with pytest.raises(ValueError, match=code):
        impact.assess(packet, review)


def test_disputed_record_must_have_current_vendor_disputed_tag(evidence):
    packet, review = evidence
    fact = next(f for f in packet["vendor_facts"] if f["advisory_id"] == "CVE-2026-3479")
    fact["tags"] = []
    with pytest.raises(ValueError, match="dispute_not_verified"):
        impact.assess(packet, review)


def test_non_psf_record_cannot_assert_python_applicability(evidence):
    packet, review = evidence
    fact = next(f for f in packet["vendor_facts"] if f["package"]["ecosystem"] == "binary")
    fact["provider_org_id"] = "another-publisher"
    with pytest.raises(ValueError, match="unexpected_python_publisher"):
        impact.assess(packet, review)


def test_unsupported_version_ranges_cannot_fall_back_to_unaffected(evidence):
    packet, review = evidence
    fact = next(f for f in packet["vendor_facts"] if f["package"]["ecosystem"] == "binary")
    fact["affected"][0]["versions"][0]["versionType"] = "custom"
    with pytest.raises(ValueError, match="unsupported_python_range"):
        impact.assess(packet, review)


@pytest.mark.parametrize("value,affected", [("3.12.15", True), ("3.12.16", False), ("3.12.16rc1", True)])
def test_python_range_boundaries_do_not_lexically_order_version_numbers(value, affected):
    fact = [{"product": "CPython", "defaultStatus": "unaffected", "versions": [
        {"version": "3.12.0", "lessThan": "3.12.16", "status": "affected", "versionType": "python"}]}]
    assert impact.python_affected(value, fact) is affected


@pytest.mark.parametrize("rule", [">= 1", "< 25.3 || > 26", "any", "< 25.3+vendor"])
def test_pip_range_grammar_is_explicit_not_a_general_pypi_solver(rule):
    with pytest.raises(ValueError):
        impact.pip_affected("25.0.1", rule)


def test_ast_reference_scan_resolves_aliases_without_executing_source(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "sample.py").write_text(
        "import base64 as b\nfrom urllib.request import urlopen as request\n"
        "raise RuntimeError('never execute')\nb.b64decode(b'YQ==', validate=True)\nrequest('example')\n"
        "# poplib.POP3('not a call')\n", encoding="utf-8")
    rows = scan_references([root])
    assert [(r["call"], r["options"]) for r in rows] == [
        ("base64.b64decode", {"validate": True}), ("urllib.request.urlopen", {})]


def cli_arguments(packet, tmp_path, monkeypatch):
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(packet), encoding="utf-8")
    output = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", ["impact", "--input", str(path), "--input-sha256",
        digest(path.read_bytes()), "--review", str(REVIEW), "--review-sha256", digest(REVIEW.read_bytes()),
        "--output", str(output)])
    return path, output


def test_cli_is_reproducible_and_existing_reports_cannot_be_overwritten(evidence, tmp_path, monkeypatch):
    packet, _ = evidence
    _, output = cli_arguments(packet, tmp_path, monkeypatch)
    assert impact.main() == 0
    saved = output.read_bytes()
    assert json.loads(saved)["security_gate_passed"] is False
    assert impact.main() == 1
    assert output.read_bytes() == saved


def test_cli_changed_packet_hash_does_not_emit_a_report(evidence, tmp_path, monkeypatch):
    packet, _ = evidence
    path, output = cli_arguments(packet, tmp_path, monkeypatch)
    path.write_bytes(path.read_bytes() + b" ")
    assert impact.main() == 1
    assert not output.exists()


def test_cli_review_binding_cannot_use_a_different_original_review(evidence, tmp_path, monkeypatch):
    packet, _ = evidence
    packet["review_sha256"] = "f" * 64
    _, output = cli_arguments(packet, tmp_path, monkeypatch)
    assert impact.main() == 1
    assert not output.exists()
