import io
import json
import tarfile

import pytest

from scripts import compare_supply_chain as c03


@pytest.fixture
def release_asset():
    tool = {"repo": "anchore/syft", "tag": "v1.56.0"}
    asset = {"name": "syft.tar.gz", "digest": "sha256:" + "a" * 64,
             "browser_download_url": "https://github.com/anchore/syft/releases/download/v1.56.0/syft.tar.gz"}
    return tool, asset


@pytest.mark.parametrize("name", ["../syft", "..", "/syft", "syft\\bad", "syft name"])
def test_release_rejects_unsafe_names(release_asset, name):
    tool, asset = release_asset
    asset["name"] = name
    with pytest.raises(ValueError, match="unsafe_asset_name"):
        c03.validate_asset(tool, asset)


@pytest.mark.parametrize("field,value", [
    ("browser_download_url", "https://example.com/syft.tar.gz"),
    ("browser_download_url", "http://github.com/anchore/syft/releases/download/v1.56.0/syft.tar.gz"),
    ("digest", "sha256:123"),
])
def test_release_requires_pinned_origin_and_digest(release_asset, field, value):
    tool, asset = release_asset
    asset[field] = value
    with pytest.raises(ValueError):
        c03.validate_asset(tool, asset)


def test_locked_release_downloads_are_valid():
    lock = json.loads((c03.ROOT / "infra/supply-chain/tools.lock.json").read_text(encoding="utf-8"))
    assert {tool["name"] for tool in lock["tools"]} == {"syft", "grype", "trivy", "cosign"}
    for tool in lock["tools"]:
        for asset in tool["assets"]:
            c03.validate_asset(tool, asset)


def make_archive(path, members):
    with tarfile.open(path, "w:gz") as bundle:
        for name, kind in members:
            member = tarfile.TarInfo(name)
            if kind == "link":
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
                bundle.addfile(member)
            else:
                member.size = 6
                bundle.addfile(member, io.BytesIO(b"binary"))


@pytest.mark.parametrize("members", [
    [("../../syft", "file")], [("syft", "link")],
    [("syft", "file"), ("./syft", "file")],
])
def test_binary_extraction_rejects_traversal_links_and_duplicates(tmp_path, members):
    archive = tmp_path / "release.tgz"
    make_archive(archive, members)
    with pytest.raises(ValueError, match="invalid_binary_member"):
        c03.extract_binary(archive, "syft", tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_binary_extraction_ignores_other_paths(tmp_path):
    archive = tmp_path / "release.tgz"
    make_archive(archive, [("syft", "file"), ("../../outside", "file")])
    output = tmp_path / "output"
    c03.extract_binary(archive, "syft", output)
    assert output.read_bytes() == b"binary"
    assert set(tmp_path.iterdir()) == {archive, output}


def test_checksum_tampering_is_rejected(tmp_path):
    archive = tmp_path / "release.tgz"
    archive.write_bytes(b"original")
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(c03.sha256(archive) + "  release.tgz\n", encoding="utf-8")
    c03.check_archive(checksums, archive)
    archive.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="signed_archive_digest_mismatch"):
        c03.check_archive(checksums, archive)


def test_duplicate_checksum_is_rejected(tmp_path):
    archive = tmp_path / "release.tgz"
    archive.write_bytes(b"data")
    checksums = tmp_path / "checksums.txt"
    line = c03.sha256(archive) + "  release.tgz\n"
    checksums.write_text(line + line, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate_checksum"):
        c03.check_archive(checksums, archive)


def test_package_inventory_normalizes_python_only():
    syft = {"artifacts": [
        {"type": "python", "name": "Some_Pkg.Name", "version": "1.0"},
        {"type": "deb", "name": "libthing", "version": "1:2.0"},
        {"type": "binary", "name": "python", "version": "3.12"}]}
    trivy = {"Results": [
        {"Type": "python-pkg", "Packages": [{"Name": "some-pkg-name", "Version": "1.0"}]},
        {"Type": "debian", "Packages": [{"Name": "libthing", "Version": "1:2.0"}]}]}
    assert c03.syft_packages(syft) == c03.trivy_packages(trivy)
    assert ("deb", "libthing", "1:2.0") in c03.syft_packages(syft)


def test_findings_deduplicate_without_merging_advisory_aliases():
    row = {"artifact": {"type": "python", "name": "requests", "version": "2.31.0"},
           "vulnerability": {"id": "GHSA-9wx4-h78v-vm56"}}
    document = {"matches": [row, row]}
    assert c03.findings(document, "grype") == {
        ("pypi", "requests", "2.31.0", "GHSA-9wx4-h78v-vm56")}
    with pytest.raises(ValueError, match="unknown_scanner"):
        c03.findings(document, "other")


def test_trivy_inventory_preserves_debian_epoch_and_revision():
    document = {"Results": [{"Type": "debian", "Packages": [
        {"Name": "bash", "Version": "5.2.37", "Release": "2+b10"},
        {"Name": "bsdutils", "Version": "2.41.5", "Release": "0+deb13u1", "Epoch": 1}]}]}
    assert c03.trivy_packages(document) == {
        ("deb", "bash", "5.2.37-2+b10"), ("deb", "bsdutils", "1:2.41.5-0+deb13u1")}


def test_controls_are_metadata_not_executable_packages():
    positive = c03.control("2.31.0")
    negative = c03.control("2.32.0")
    assert positive["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"
    assert negative["components"][0]["purl"] == "pkg:pypi/requests@2.32.0"
    assert positive["bomFormat"] == "CycloneDX"


@pytest.fixture
def summary_files(tmp_path):
    out = tmp_path / "out"
    out.mkdir()

    def write(name, document):
        (out / name).write_text(json.dumps(document), encoding="utf-8")

    db_files = {"grype/v6/vulnerability.db": "a" * 64, "trivy/db/trivy.db": "b" * 64}
    (tmp_path / "summary.json").write_text(json.dumps({
        "repeats": 3, "db_files": db_files, "db_files_after": db_files}), encoding="utf-8")
    write("installed.json", {"pypi": [["Some_Pkg", "1.0"]], "deb": "libtest\t1:2.0\tinstalled\n"})
    for i in range(1, 4):
        write(f"run-{i}-syft.json", {"artifacts": [
            {"type": "python", "name": "some-pkg", "version": "1.0"}]})
        write(f"run-{i}-grype.json", {"matches": []})
        write(f"run-{i}-trivy.json", {"Results": []})
    for scanner in ["grype", "trivy"]:
        write(scanner + "-db-status.stdout", {"schema": 6})
        for version in ["2.31.0", "2.32.0"]:
            write(f"control-{version}-{scanner}.json", {})
    write("control-2.31.0-grype.json", {"matches": [{
        "artifact": {"type": "python", "name": "requests", "version": "2.31.0"},
        "vulnerability": {"id": "GHSA-9wx4-h78v-vm56"},
        "relatedVulnerabilities": [{"id": "CVE-2024-35195"}]}]})
    return tmp_path, write


def test_summary_preserves_missing_inventory_and_failed_positive_control(summary_files):
    directory, _ = summary_files
    results = c03.summarize(directory)["results"]
    assert results["inventory"]["syft"]["missing_installed_metadata"] == [("deb", "libtest", "1:2.0")]
    assert results["inventory"]["syft"]["matched_count"] == 1
    assert results["controls"]["grype"]["2.31.0"]["passed"]
    assert results["controls"]["grype"]["2.32.0"]["passed"]
    assert not results["controls"]["trivy"]["2.31.0"]["passed"]
    assert results["database_files_unchanged_during_offline_scans"]


def test_summary_detects_database_drift_and_repeat_disagreement(summary_files):
    directory, write = summary_files
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    summary["db_files_after"]["trivy/db/trivy.db"] = "c" * 64
    (directory / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    write("run-2-syft.json", {"artifacts": []})
    results = c03.summarize(directory)["results"]
    assert not results["database_files_unchanged_during_offline_scans"]
    assert not results["repeat_consistency"]["syft_inventory"]
