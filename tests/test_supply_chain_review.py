import copy
import json
import sys

import pytest

from scripts import review_supply_chain as review

CVE = "CVE-2024-35195"
GHSA = "GHSA-9wx4-h78v-vm56"
IMAGE = "sha256:" + "a" * 64


def grype(advisory=CVE, aliases=(), name="requests", version="2.31.0", kind="python"):
    return {"artifact": {"type": kind, "name": name, "version": version},
            "vulnerability": {"id": advisory, "severity": "High",
                              "fix": {"versions": ["2.32.0"], "state": "fixed"}},
            "relatedVulnerabilities": [{"id": alias} for alias in aliases]}


def trivy(advisory=CVE, aliases=(), name="requests", version="2.31.0"):
    return {"VulnerabilityID": advisory, "VendorIDs": list(aliases), "PkgName": name,
            "InstalledVersion": version, "Severity": "HIGH", "FixedVersion": "2.32.0"}


def gdoc(*matches):
    return {"matches": list(matches)}


def tdoc(*vulns):
    return {"Results": [{"Type": "python-pkg", "Vulnerabilities": list(vulns)}]}


def compared(g, t):
    return review.compare(review.normalized(g, "grype"), review.normalized(t, "trivy"))


def test_native_match_preserves_both_providers_without_disposition():
    groups = compared(gdoc(grype()), tdoc(trivy()))
    assert len(groups) == 1
    group = groups[0]
    assert group["relation"] == "same_native_id"
    assert group["flags"] == []
    assert set(group["evidence"]) == {"grype", "trivy"}
    assert group["review_state"] == "unreviewed"
    assert group["applicability"] == "not_assessed"


@pytest.mark.parametrize("g,t", [
    (grype(GHSA, [CVE]), trivy()), (grype(GHSA), trivy(aliases=[GHSA])),
])
def test_direct_provider_alias_is_scoped_and_marked_as_claim(g, t):
    groups = compared(gdoc(g), tdoc(t))
    assert len(groups) == 1
    assert groups[0]["relation"] == "direct_provider_alias"
    assert groups[0]["evidence"]["grype"]["native_id"] == GHSA


@pytest.mark.parametrize("field,value", [("name", "different"), ("version", "9"), ("kind", "binary")])
def test_alias_cannot_merge_other_package_version_or_ecosystem(field, value):
    groups = compared(gdoc(grype(GHSA, [CVE], **{field: value})), tdoc(trivy()))
    assert len(groups) == 2
    assert {g["relation"] for g in groups} == {"grype_only", "trivy_only"}


def test_alias_does_not_use_shared_alias_transitivity_urls_or_description():
    match = grype(GHSA, ["CVE-2020-0001"])
    match["vulnerability"]["description"] = CVE
    match["vulnerability"]["urls"] = ["https://example.com/" + CVE]
    groups = compared(gdoc(match), tdoc(trivy(aliases=["CVE-2020-0001"])))
    assert len(groups) == 2


def test_ambiguous_alias_graph_does_not_silently_drop_or_collapse_rows():
    groups = compared(gdoc(grype(GHSA, [CVE, "CVE-2020-0001"])),
                      tdoc(trivy(), trivy("CVE-2020-0001")))
    assert len(groups) == 3
    assert all("ambiguous_alias" in g["flags"] for g in groups)
    assert sum(len(g["evidence"]) for g in groups) == 3


def test_multiple_observations_and_fix_severity_differences_preserved():
    first, second = grype(), grype()
    second["vulnerability"]["severity"] = "Low"
    right = trivy()
    right["FixedVersion"] = "3.0, 4.0"
    group = compared(gdoc(first, first, second), tdoc(right))[0]
    assert len(group["evidence"]["grype"]["observations"]) == 2
    assert set(group["flags"]) == {"severity_disagreement", "fix_versions_disagreement",
                                    "multiple_provider_observations"}


def test_binary_and_temporary_findings_are_queued_without_false_positive_verdict():
    groups = compared(gdoc(grype(kind="binary")), tdoc(trivy("TEMP-01234-ABCDE")))
    assert {f for g in groups for f in g["flags"]} == {
        "missing_counterpart", "binary_catalog_scope", "temporary_advisory"}
    assert all(g["applicability"] == "not_assessed" for g in groups)


def test_input_order_has_no_effect_on_report_ids_or_groups():
    a, b = grype(), grype("CVE-2020-0001")
    c, d = trivy(), trivy("CVE-2020-0002")
    assert compared(gdoc(a, b), tdoc(c, d)) == compared(gdoc(b, a), tdoc(d, c))


def test_native_match_is_not_used_to_hide_a_conflicting_alias_claim():
    groups = compared(gdoc(grype(CVE, ["CVE-2020-0001"])),
                      tdoc(trivy(), trivy("CVE-2020-0001")))
    assert len(groups) == 3
    assert all("ambiguous_alias" in g["flags"] for g in groups)


def test_unknown_vendor_id_is_preserved_but_not_used_as_advisory_equivalence():
    groups = compared(gdoc(grype(GHSA, ["VENDOR-UNKNOWN"])), tdoc(trivy(aliases=["VENDOR-UNKNOWN"])))
    assert len(groups) == 2
    assert groups[0]["evidence"]
    assert all("VENDOR-UNKNOWN" in next(iter(g["evidence"].values()))["observations"][0][
        "reported_aliases"] for g in groups)


@pytest.mark.parametrize("document,scanner", [({}, "grype"), ({}, "trivy"),
    ({"Results": [{"Type": "python-pkg", "Vulnerabilities": None}]}, "trivy"),
    (gdoc(grype("<script>")), "grype"), (gdoc(grype(name="bad\nname")), "grype")])
def test_malformed_or_missing_scan_data_is_rejected(document, scanner):
    with pytest.raises(ValueError):
        review.normalized(document, scanner)


@pytest.fixture
def campaign(tmp_path):
    raw = tmp_path / "out"
    raw.mkdir()
    summary = {"schema": "c03-pilot-1", "completed": True, "repeats": 3,
               "source_commit": "b" * 40, "app_image_id": IMAGE,
               "image_archive_sha256": "c" * 64, "conditions": {"scan_network": "none"},
               "db_files": {"db": "d" * 64}, "db_files_after": {"db": "d" * 64},
               "tools": {"tools": [{"name": s, "tag": "v1.0"}
                                   for s in ["syft", "grype", "trivy"]]},
               "results": {"database_files_unchanged_during_offline_scans": True,
                           "raw_artifacts": {}, "findings": {}}}

    def write(name, doc):
        data = (json.dumps(doc, sort_keys=True) + "\n").encode()
        (raw / name).write_bytes(data)
        summary["results"]["raw_artifacts"]["out/" + name] = {
            "bytes": len(data), "sha256": review.digest(data)}

    write("installed.json", {"pypi": [["requests", "2.31.0"]], "deb": ""})
    for i in range(1, 4):
        for scanner in ["syft", "grype", "trivy"]:
            doc = ({"artifacts": [{"type": "python", "name": "requests", "version": "2.31.0"}]}
                   if scanner == "syft" else gdoc(grype()) if scanner == "grype" else tdoc(trivy()))
            if scanner == "trivy":
                doc.update({"Metadata": {"ImageID": IMAGE}, "Trivy": {"Version": "1.0"}})
                doc["Results"][0]["Packages"] = [{"Name": "requests", "Version": "2.31.0"}]
            else:
                doc.update({"source": {"metadata" if scanner == "syft" else "target": {
                    "imageID": IMAGE}}, "descriptor": {"version": "1.0"}})
            write(f"run-{i}-{scanner}.json", doc)
            write(f"run-{i}-{scanner}.metrics.json", {"exit_code": 0})
    for scanner in ["grype", "trivy"]:
        summary["results"]["findings"][scanner] = {"rows": [["pypi", "requests", "2.31.0", CVE]]}
        for version in ["2.31.0", "2.32.0"]:
            doc = gdoc(grype()) if scanner == "grype" else tdoc(trivy())
            if version == "2.32.0":
                doc = gdoc() if scanner == "grype" else tdoc()
            write(f"control-{version}-{scanner}.json", doc)
            write(f"control-{version}-{scanner}.metrics.json", {"exit_code": 0})
    path = tmp_path / "summary.json"

    def load():
        data = json.dumps(summary).encode()
        path.write_bytes(data)
        return review.Campaign(path, review.digest(data), raw)

    return summary, raw, write, load


def test_campaign_rechecks_manifest_full_repeats_inventory_and_controls(campaign):
    _, _, _, load = campaign
    report = load().report()
    assert report["counts"]["unreviewed"] == 1
    assert report["counts"]["relations"] == {"same_native_id": 1}
    assert report["basis"]["inventory_matched"] == 1
    assert len(report["basis"]["verified_inputs"]) == 27
    assert not report["review_complete"]


@pytest.mark.parametrize("mutation,code", [
    (lambda s: s.update(completed=False), "campaign_incomplete"),
    (lambda s: s.update(repeats=True), "invalid_repeat_count"),
    (lambda s: s["conditions"].update(scan_network="bridge"), "scan_not_offline"),
    (lambda s: s["db_files_after"].update(db="e" * 64), "database_drift"),
    (lambda s: s["results"]["findings"]["grype"].update(rows=[]), "summary_findings_mismatch"),
])
def test_campaign_refuses_unreliable_summary(campaign, mutation, code):
    summary, _, _, load = campaign
    mutation(summary)
    with pytest.raises(ValueError, match=code):
        load().report()


@pytest.mark.parametrize("file,change,code", [
    ("run-2-grype.json", lambda d: d["matches"][0]["vulnerability"].update(severity="Low"),
     "repeat_metadata_drift"),
    ("run-2-trivy.json", lambda d: d["Metadata"].update(ImageID="wrong"), "scan_image_mismatch"),
    ("run-2-syft.json", lambda d: d["descriptor"].update(version="2.0"), "scanner_version_mismatch"),
    ("run-2-trivy.json", lambda d: d["Results"][0].update(Packages=[]), "inventory_mismatch"),
    ("run-2-grype.metrics.json", lambda d: d.update(exit_code=1), "scanner_exit_not_zero"),
    ("control-2.31.0-grype.json", lambda d: d.update(matches=[]), "advisory_control_failed"),
    ("control-2.31.0-trivy.json", lambda d: d["Results"][0]["Vulnerabilities"][0].update(
        PkgName="other-package"), "advisory_control_failed"),
])
def test_campaign_rechecks_raw_conditions_not_just_recorded_pass_flags(campaign, file, change, code):
    _, raw, write, load = campaign
    doc = json.loads((raw / file).read_text())
    change(doc)
    write(file, doc)
    with pytest.raises(ValueError, match=code):
        load().report()


def test_changed_bytes_cannot_be_reanalyzed_against_old_manifest(campaign):
    _, raw, _, load = campaign
    (raw / "run-1-grype.json").write_text("{}")
    with pytest.raises(ValueError, match="artifact_digest_mismatch"):
        load().report()


def test_missing_raw_file_cannot_be_replaced_by_summary_counts(campaign):
    _, raw, _, load = campaign
    (raw / "run-2-grype.json").unlink()
    with pytest.raises(FileNotFoundError):
        load().report()


def test_missing_manifest_cannot_be_reconstructed_from_current_bytes(campaign):
    summary, _, _, load = campaign
    del summary["results"]["raw_artifacts"]["out/run-2-grype.json"]
    with pytest.raises(ValueError, match="missing_artifact_manifest"):
        load().report()


def test_size_limit_checked_before_reading_input(campaign, monkeypatch):
    _, _, _, load = campaign
    current = load()
    monkeypatch.setattr(review, "MAX_JSON", 1)
    with pytest.raises(ValueError, match="json_too_large"):
        current.report()


def test_symlink_cannot_substitute_manifest_artifact(campaign):
    _, raw, _, load = campaign
    source = raw / "installed.json"
    saved = raw.parent / "original.json"
    saved.write_bytes(source.read_bytes())
    source.unlink()
    try:
        source.symlink_to(saved)
    except OSError:
        pytest.skip("Host does not permit creating symbolic links")
    with pytest.raises(ValueError, match="artifact_path_escape"):
        load().report()


def test_positive_control_in_negative_version_is_rejected(campaign):
    _, _, write, load = campaign
    write("control-2.32.0-trivy.json", tdoc(trivy(version="2.32.0")))
    with pytest.raises(ValueError, match="advisory_control_failed"):
        load().report()


def test_wrong_summary_pin_rejected(campaign):
    _, _, _, load = campaign
    current = load()
    with pytest.raises(ValueError, match="summary_digest_mismatch"):
        review.Campaign(current.directory.parent / "summary.json", "f" * 64, current.directory)


@pytest.mark.parametrize("key", ["../summary.json", "out/../summary.json", "/out/file.json", "out/C:file"])
def test_manifest_paths_never_resolve_to_credentials_or_outside_files(campaign, key):
    summary, _, _, load = campaign
    summary["results"]["raw_artifacts"][key] = {"sha256": "a" * 64, "bytes": 0}
    with pytest.raises(ValueError, match="unsafe_manifest_path"):
        load()


def test_windows_and_linux_manifest_aliases_cannot_shadow_each_other(campaign):
    summary, _, _, load = campaign
    summary["results"]["raw_artifacts"]["out\\installed.json"] = copy.deepcopy(
        summary["results"]["raw_artifacts"]["out/installed.json"])
    with pytest.raises(ValueError, match="duplicate_manifest_path"):
        load()


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_ambiguous_json_is_rejected(data):
    with pytest.raises(ValueError):
        review.decode(data)


def test_cli_pending_gate_writes_review_queue_and_returns_two(campaign, monkeypatch):
    _, raw, _, load = campaign
    current = load()
    output = raw.parent / "review.json"
    monkeypatch.setattr(sys, "argv", ["review", "--summary", str(raw.parent / "summary.json"),
                        "--summary-sha256", current.pin, "--raw-directory", str(raw),
                        "--output", str(output), "--require-reviewed"])
    assert review.main() == 2
    original = output.read_bytes()
    assert not json.loads(original)["review_complete"]
    assert review.main() == 1  # Never overwrite evidence or an earlier report.
    assert output.read_bytes() == original


def test_cli_validation_failure_does_not_create_misleading_report(campaign, monkeypatch):
    _, raw, _, load = campaign
    current = load()
    output = raw.parent / "review.json"
    (raw / "run-1-trivy.json").write_text("{}")
    monkeypatch.setattr(sys, "argv", ["review", "--summary", str(raw.parent / "summary.json"),
                        "--summary-sha256", current.pin, "--raw-directory", str(raw),
                        "--output", str(output)])
    assert review.main() == 1
    assert not output.exists()
