"""C03 local scanner pilot. Public release downloads and offline image scans only.

python -m scripts.compare_supply_chain --source-ref b4660ad --repeats 3
Artifacts stay under ignored runtime/c03; publish only the reviewed summary.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE = "python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"
IDENTITIES = {
    "syft": "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main",
    "grype": "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main",
    "trivy": "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.1",
}
MAX_ASSET = 250 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_asset(tool, asset):
    name = asset["name"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in {".", ".."}:
        raise ValueError("unsafe_asset_name")
    expected = f"https://github.com/{tool['repo']}/releases/download/{tool['tag']}/{name}"
    if asset["browser_download_url"] != expected:
        raise ValueError("unexpected_release_origin")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", asset["digest"]):
        raise ValueError("invalid_digest")


def download(tool, asset, destination):
    validate_asset(tool, asset)
    target = destination / asset["name"]
    expected = asset["digest"].removeprefix("sha256:")
    if target.is_file() and sha256(target) == expected:
        return
    partial = target.with_name(target.name + ".part")
    try:
        request = Request(asset["browser_download_url"], headers={"User-Agent": "secops-c03"})
        with urlopen(request, timeout=180) as response, partial.open("wb") as output:
            if urlparse(response.url).scheme != "https":
                raise ValueError("insecure_release_redirect")
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_ASSET:
                    raise ValueError("oversize_asset")
                output.write(chunk)
        if sha256(partial) != expected:
            raise ValueError("asset_digest_mismatch")
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


def extract_binary(archive, name, destination):
    """Extract exactly one regular binary, never archive paths/links/permissions."""
    with tarfile.open(archive, "r:gz") as bundle:
        matches = [item for item in bundle.getmembers() if item.name in {name, "./" + name}]
        if (len(matches) != 1 or not matches[0].isfile()
                or not 0 < matches[0].size <= MAX_ASSET):
            raise ValueError("invalid_binary_member")
        with bundle.extractfile(matches[0]) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)


def check_archive(checksums, archive):
    entries = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ValueError("invalid_checksum_line")
        name = fields[1].lstrip("*")
        if name in entries:
            raise ValueError("duplicate_checksum")
        entries[name] = fields[0]
    if entries.get(archive.name) != sha256(archive):
        raise ValueError("signed_archive_digest_mismatch")


def canonical_package(ecosystem, name, version):
    ecosystem = {"python": "pypi", "python-pkg": "pypi", "deb": "deb"}.get(ecosystem, ecosystem)
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return ecosystem, name, version


def syft_packages(document):
    return {canonical_package(p["type"], p["name"], p["version"])
            for p in document["artifacts"] if p["type"] in {"python", "deb"}}


def trivy_packages(document):
    result = set()
    for row in document.get("Results", []):
        ecosystem = row.get("Type")
        if ecosystem not in {"python-pkg", "debian"}:
            continue
        ecosystem = "deb" if ecosystem == "debian" else ecosystem
        for package in row.get("Packages", []):
            version = package["Version"]
            # Trivy separates Debian epoch/revision; do not mistake those for missing packages.
            if ecosystem == "deb":
                if package.get("Release"):
                    version += "-" + package["Release"]
                if package.get("Epoch"):
                    version = str(package["Epoch"]) + ":" + version
            result.add(canonical_package(ecosystem, package["Name"], version))
    return result


def findings(document, scanner):
    """One package/version/advisory tuple, preserving native advisory IDs."""
    rows = set()
    if scanner == "grype":
        for match in document.get("matches", []):
            package = match["artifact"]
            rows.add((*canonical_package(package["type"], package["name"], package["version"]),
                      match["vulnerability"]["id"]))
    elif scanner == "trivy":
        for row in document.get("Results", []):
            ecosystem = "deb" if row.get("Type") == "debian" else row.get("Type", "unknown")
            for vuln in row.get("Vulnerabilities", []):
                rows.add((*canonical_package(ecosystem, vuln["PkgName"], vuln["InstalledVersion"]),
                          vuln["VulnerabilityID"]))
    else:
        raise ValueError("unknown_scanner")
    return rows


def control(version):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "c03-metadata-control",
                                       "version": "1"}},
            "components": [{"type": "library", "name": "requests", "version": version,
                            "purl": f"pkg:pypi/requests@{version}"}]}


def installed_packages(installed):
    expected = {canonical_package("pypi", name, version) for name, version in installed["pypi"]}
    for line in installed["deb"].splitlines():
        name, version, status = line.split("\t")
        if status == 'installed':
            expected.add(canonical_package('deb', name, version))
    return expected


def summarize(directory, *, installed_reader=installed_packages, inventory_readers=None):
    """Compare inventory with installed metadata; finding totals are not accuracy."""
    directory = Path(directory)
    out = directory / "out"

    def read(name):
        return json.loads((out / name).read_text(encoding="utf-8"))

    report = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    installed = read("installed.json")
    expected = installed_reader(installed)
    inventories = {"installed_metadata": sorted(expected)}
    detections = {}
    results = {"inventory": inventories, "findings": detections, "controls": {}, "repeat_consistency": {}}
    for scanner, extractor in (inventory_readers or {"syft": syft_packages, "trivy": trivy_packages}).items():
        observed = [extractor(read(f"run-{i}-{scanner}.json")) for i in range(1, report["repeats"] + 1)]
        inventories[scanner] = {"observed": sorted(observed[0]),
                                "missing_installed_metadata": sorted(expected - observed[0]),
                                "additional_to_installed_metadata": sorted(observed[0] - expected),
                                "matched_count": len(expected & observed[0])}
        results["repeat_consistency"][scanner + "_inventory"] = all(s == observed[0] for s in observed)
    for scanner in ["grype", "trivy"]:
        observed = [findings(read(f"run-{i}-{scanner}.json"), scanner) for i in range(1, report["repeats"] + 1)]
        detections[scanner] = {"unique_package_native_advisories": len(observed[0]),
                                "rows": sorted(observed[0])}
        results["repeat_consistency"][scanner + "_findings"] = all(s == observed[0] for s in observed)
        results["controls"][scanner] = {}
        for version, expect_present in [("2.31.0", True), ("2.32.0", False)]:
            data = read(f"control-{version}-{scanner}.json")
            ids = {row[-1] for row in findings(data, scanner)}
            if scanner == "grype":
                for match in data.get("matches", []):
                    ids.update(v["id"] for v in match.get("relatedVulnerabilities", []))
            present = bool(ids & {"CVE-2024-35195", "GHSA-9wx4-h78v-vm56"})
            results["controls"][scanner][version] = {
                "target_advisory_present": present, "expected_present": expect_present,
                "passed": present == expect_present, "all_advisory_ids": sorted(ids)}
    results["native_advisory_id_overlap"] = len(
        findings(read("run-1-grype.json"), "grype") & findings(read("run-1-trivy.json"), "trivy"))
    results["advisory_comparison_limit"] = "Native IDs only; CVE/GHSA aliases may differ. Counts are not scanner accuracy."
    results["raw_artifacts"] = {str(p.relative_to(directory)): {"sha256": sha256(p), "bytes": p.stat().st_size}
        for p in out.iterdir() if p.is_file()}
    for scanner in ["grype", "trivy"]:
        results[scanner + "_database_status"] = read(scanner + "-db-status.stdout")
    before = {name: value for name, value in report["db_files"].items()
              if "grype" in name.replace("\\", "/").split("/")
              or name.replace("\\", "/").split("/")[-1] in {"trivy.db", "trivy-java.db", "metadata.json"}}
    results["database_files_unchanged_during_offline_scans"] = before == report["db_files_after"]
    report["results"] = results
    (directory / "summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def run(args, timeout=1800, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"command_failed:{args[0]}:{result.returncode}\n{result.stderr[-2500:]}")
    return result.stdout


# Runs inside a non-root, bounded container; measures the scanner child, not Docker startup.
MEASURE = r'''
import json, pathlib, resource, subprocess, sys, time
label = sys.argv[1]
started = time.perf_counter()
with open('/out/' + label + '.stderr', 'w') as err:
    result = subprocess.run(sys.argv[2:], stderr=err, check=False)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
metrics = {'exit_code': result.returncode, 'elapsed_seconds': time.perf_counter()-started,
           'child_maxrss_kib': usage.ru_maxrss, 'user_seconds': usage.ru_utime,
           'system_seconds': usage.ru_stime}
for name in ['memory.peak', 'cpu.stat', 'memory.events']:
    path = pathlib.Path('/sys/fs/cgroup') / name
    metrics[name] = path.read_text() if path.is_file() else None
pathlib.Path('/out/' + label + '.metrics.json').write_text(json.dumps(metrics))
sys.exit(result.returncode)
'''


class Pilot:
    def __init__(self, directory, source_ref, repeats, *, scratch_mib=512, memory_mib=2048):
        if (scratch_mib, memory_mib) not in {(512, 2048), (1536, 2048), (2048, 3072)}:
            raise ValueError("unsupported_scanner_scratch_budget")
        self.scratch_mib, self.memory_mib = scratch_mib, memory_mib
        self.directory = directory.resolve()
        if not self.directory.is_relative_to((ROOT / "runtime/c03").resolve()):
            raise ValueError("work_directory_must_be_within_runtime_c03")
        self.source_ref = source_ref
        self.repeats = repeats
        self.ident = "c03-" + uuid.uuid4().hex[:12]
        self.runner_image = self.ident + "-runner"
        self.app_image = self.ident + "-app"
        self.cache_volume = self.ident + "-db"
        self.containers = []
        self.lock = json.loads((ROOT / "infra/supply-chain/tools.lock.json").read_text(encoding="utf-8"))
        self.report = {"schema": "c03-pilot-1", "started_at": datetime.now(UTC).isoformat(),
                       "source_commit": run(["git", "rev-parse", "--verify", "--end-of-options",
                                             source_ref + "^{commit}"]).strip(),
                       "runner_base": BASE, "tools": self.lock, "repeats": repeats,
                       "conditions": {"cpus": 2, "memory_bytes": memory_mib * 1024**2, "pids": 128,
                                      "uid": 10001, "scan_network": "none",
                                      "db_storage": "Docker Linux named volume"},
                       "cache_volume": self.cache_volume, "runs": []}
        if scratch_mib != 512:
            self.report["conditions"]["scratch_tmpfs_bytes"] = scratch_mib * 1024**2

    def save(self):
        (self.directory / "summary.json").write_text(
            json.dumps(self.report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def prepare(self):
        downloads = self.directory / "downloads"
        binaries = self.directory / "bin"
        for directory in [downloads, binaries, self.directory / "out", self.directory / "input"]:
            directory.mkdir(parents=True, exist_ok=True)
        self.save()
        tasks = [(tool, asset) for tool in self.lock["tools"] for asset in tool["assets"]]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda pair: download(*pair, downloads), tasks))
        for tool in self.lock["tools"]:
            if tool["name"] == "cosign":
                shutil.copyfile(downloads / "cosign-linux-amd64", binaries / "cosign")
            else:
                archive = next(a["name"] for a in tool["assets"] if a["name"].endswith(".tar.gz"))
                checksum = next(a["name"] for a in tool["assets"] if a["name"].endswith("_checksums.txt"))
                check_archive(downloads / checksum, downloads / archive)
                extract_binary(downloads / archive, tool["name"], binaries / tool["name"])
        (self.directory / "measure.py").write_text(MEASURE, encoding="utf-8")
        (self.directory / "Dockerfile.runner").write_text(
            f"FROM {BASE}\nCOPY bin /tools\nCOPY measure.py /measure.py\n"
            "RUN chmod 0555 /tools/* /measure.py && mkdir -p /cache/grype /cache/trivy "
            "&& chown -R 10001:10001 /cache\nENV HOME=/tmp\nUSER 10001:10001\n",
            encoding="utf-8")
        # Restrict build context to the public executables and measurement wrapper.
        (self.directory / ".dockerignore").write_text(
            "*\n!bin/\n!bin/*\n!measure.py\n!Dockerfile.runner\n", encoding="utf-8")
        run(["docker", "build", "--file", "Dockerfile.runner", "--tag", self.runner_image, "."],
            cwd=self.directory)
        self.report["runner_image_id"] = run(["docker", "image", "inspect", self.runner_image,
                                             "--format", "{{.Id}}"]).strip()
        run(["docker", "volume", "create", "--label", "secops.c03=" + self.ident, self.cache_volume])
        # The cosign bootstrap is pinned by the official GitHub release SHA256 over TLS.
        # GitHub did not expose a SLSA attestation for this asset (404); do not claim otherwise.
        self.report["cosign_bootstrap"] = "official_release_SHA256_over_TLS; no_GitHub_SLSA_attestation"
        for name, identity in IDENTITIES.items():
            tool = next(t for t in self.lock["tools"] if t["name"] == name)
            checksum = next(a["name"] for a in tool["assets"] if a["name"].endswith("_checksums.txt"))
            self.container("verify-" + name, ["/tools/cosign", "verify-blob", "/downloads/" + checksum,
                "--bundle", "/downloads/" + checksum + ".sigstore.json",
                "--certificate-identity", identity, "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com"], network=True, downloads=True)
        self.report["signature_verification"] = {
            name: {"identity": identity, "checksum_verified": True} for name, identity in IDENTITIES.items()}
        for name in IDENTITIES:
            self.container("version-" + name, ["/tools/" + name, "version"])
        self.save()

    def container(self, label, command, network=False, downloads=False):
        name = self.ident + "-" + label
        self.containers.append(name)
        args = ["docker", "run", "--name", name, "--read-only", "--cap-drop=ALL",
                "--label", "secops.c03=" + self.ident,
                "--security-opt=no-new-privileges:true", "--cpus=2", f"--memory={self.memory_mib//1024}g",
                f"--memory-swap={self.memory_mib//1024}g", "--pids-limit=128", "--tmpfs", f"/tmp:rw,nosuid,nodev,size={self.scratch_mib}m",
                "--network", "bridge" if network else "none"]
        args += ["--mount", f"type=volume,src={self.cache_volume},dst=/cache"]
        mounts = [("out", "/out", False), ("input", "/input", True)]
        if downloads:
            mounts.append(("downloads", "/downloads", True))
        for source, target, readonly in mounts:
            mount = f"type=bind,src={self.directory / source},dst={target}"
            args += ["--mount", mount + (",readonly" if readonly else "")]
        args += ["--env", "GRYPE_DB_CACHE_DIR=/cache/grype", "--env", "GRYPE_DB_AUTO_UPDATE=false",
                 "--env", "TRIVY_CACHE_DIR=/cache/trivy", self.runner_image,
                 "python", "/measure.py", label, *command]
        print(json.dumps({"stage": label, "network": "bridge" if network else "none"}), flush=True)
        for suffix in [".stdout", ".stderr", ".metrics.json", ".docker.stderr"]:
            (self.directory / "out" / (label + suffix)).unlink(missing_ok=True)
        started = time.perf_counter()
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=1800, check=False)
        out = self.directory / "out"
        (out / (label + ".stdout")).write_text(result.stdout, encoding="utf-8")
        (out / (label + ".docker.stderr")).write_text(result.stderr, encoding="utf-8")
        metrics_path = out / (label + ".metrics.json")
        metrics = json.loads(metrics_path.read_text()) if metrics_path.is_file() else {}
        self.report["runs"].append({"label": label, "network": "bridge" if network else "none",
            "docker_wall_seconds": time.perf_counter() - started, "container_exit": result.returncode,
            "metrics": metrics})
        self.save()
        if result.returncode:
            log = out / (label + ".stderr")
            raise RuntimeError(f"stage_failed:{label}:{result.returncode}\n" +
                               (log.read_text(encoding="utf-8")[-2500:] if log.exists() else result.stderr[-2500:]))
        return result.stdout

    def source_image(self):
        source = self.directory / (self.ident + "-source")
        source.mkdir()
        archive = self.directory / "source.tar"
        run(["git", "archive", "--format=tar", "--output=" + str(archive), self.report["source_commit"]])
        with tarfile.open(archive) as bundle:
            for item in bundle.getmembers():
                target = (source / item.name).resolve()
                if not target.is_relative_to(source.resolve()) or not (item.isfile() or item.isdir()):
                    raise ValueError("unsafe_source_archive")
            bundle.extractall(source, filter="data")
        recipe = source / "Dockerfile"
        recipe.write_text(recipe.read_text(encoding="utf-8").replace(
            "FROM python:3.12-slim", "FROM " + BASE, 1), encoding="utf-8")
        self.report["source_archive_sha256"] = sha256(archive)
        self.report["build_recipe_override"] = "Dockerfile FROM replaced with runner_base digest"
        run(["docker", "build", "--tag", self.app_image, "."], cwd=source)
        self.report["app_image_id"] = run(["docker", "image", "inspect", self.app_image,
                                          "--format", "{{.Id}}"]).strip()
        image_archive = self.directory / "input/app.tar"
        run(["docker", "save", "--output", str(image_archive), self.app_image])
        self.report["image_archive_sha256"] = sha256(image_archive)
        inventory_code = ("import importlib.metadata,json,subprocess; "
            "print(json.dumps({'pypi':[(d.metadata['Name'],d.version) for d in importlib.metadata.distributions()],"
            "'deb':subprocess.check_output(['dpkg-query','-W','-f=${Package}\\t${Version}\\t${db:Status-Status}\\n'],text=True)}))")
        inventory_name = self.ident + "-inventory"
        self.containers.append(inventory_name)
        raw = run(["docker", "run", "--name", inventory_name, "--network=none", "--read-only",
                   "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--entrypoint", "python",
                   self.app_image, "-c", inventory_code])
        (self.directory / "out/installed.json").write_text(raw, encoding="utf-8")
        for version in ["2.31.0", "2.32.0"]:
            (self.directory / f"input/requests-{version}.json").write_text(
                json.dumps(control(version)), encoding="utf-8")
        self.save()

    def scan(self, initialize_db=True, trivy_timeout=None):
        # Historical campaigns keep their original CLI defaults. A new campaign
        # may explicitly budget more analysis time without skipping any checks.
        if trivy_timeout not in (None, "15m"):
            raise ValueError("unsupported_trivy_timeout")
        trivy_budget = ["--timeout", trivy_timeout] if trivy_timeout else []
        if trivy_timeout:
            self.report["trivy_scan_timeout"] = trivy_timeout
        if initialize_db:
            self.container("grype-db-update", ["/tools/grype", "db", "update"], network=True)
            self.container("trivy-db-update", ["/tools/trivy", "image", "--download-db-only", "--no-progress"], network=True)
        self.container("grype-db-status", ["/tools/grype", "db", "status", "-o", "json"])
        self.container("trivy-db-status", ["/tools/trivy", "version", "--format", "json"])
        self.report["db_files"] = self.database_hashes("before")
        self.save()
        for index in range(self.repeats + 1):
            prefix = "warmup" if index == 0 else f"run-{index}"
            self.container(prefix + "-syft", ["/tools/syft", "docker-archive:/input/app.tar", "--scope", "squashed",
                "-o", "syft-json=/out/" + prefix + "-syft.json"])
            self.container(prefix + "-grype", ["/tools/grype", "sbom:/out/" + prefix + "-syft.json",
                "-o", "json", "--file", "/out/" + prefix + "-grype.json"])
            self.container(prefix + "-trivy", ["/tools/trivy", "image", "--input", "/input/app.tar",
                "--scanners", "vuln", "--list-all-pkgs", "--skip-db-update", "--skip-java-db-update",
                "--offline-scan", "--no-progress", "--format", "json", "--output", "/out/" + prefix + "-trivy.json", *trivy_budget])
        for version in ["2.31.0", "2.32.0"]:
            self.container("control-" + version + "-grype", ["/tools/grype", "sbom:/input/requests-" + version + ".json",
                "-o", "json", "--file", "/out/control-" + version + "-grype.json"])
            self.container("control-" + version + "-trivy", ["/tools/trivy", "sbom", "/input/requests-" + version + ".json",
                "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--no-progress", "--format", "json",
                "--output", "/out/control-" + version + "-trivy.json", *trivy_budget])
        self.report["db_files_after"] = self.database_hashes("after")
        self.save()

    def database_hashes(self, phase):
        code = ("import hashlib,json,pathlib; root=pathlib.Path('/cache'); result={}; "
                "files=[p for p in root.rglob('*') if p.is_file() and "
                "('grype' in p.parts or p.name in {'trivy.db','trivy-java.db','metadata.json'})]; "
                "exec(\"for p in files:\\n h=hashlib.sha256()\\n "
                "with p.open('rb') as f:\\n  while chunk:=f.read(1048576): h.update(chunk)\\n "
                "result[str(p.relative_to(root))]=h.hexdigest()\"); print(json.dumps(result))")
        return json.loads(self.container("db-hashes-" + phase, ["python", "-c", code]))

    def cleanup(self):
        for name in self.containers:
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True, check=False)
        for image in [self.app_image, self.runner_image]:
            subprocess.run(["docker", "image", "rm", image], capture_output=True, check=False)
        # Keep the inert DB volume for reproducing exactly the same database snapshot.
        # It has no running process and incurs no cloud/API cost; its name is in summary.json.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/c03")
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--repeats", type=int, choices=range(3, 11), default=3)
    args = parser.parse_args()
    pilot = Pilot(args.directory, args.source_ref, args.repeats)
    try:
        pilot.prepare()
        pilot.source_image()
        pilot.scan()
        pilot.report["completed"] = True
        pilot.save()
        pilot.report = summarize(pilot.directory)
    except Exception as exc:
        pilot.report["completed"] = False
        pilot.report["failure"] = str(exc)
        raise
    finally:
        pilot.report["finished_at"] = datetime.now(UTC).isoformat()
        pilot.save()
        pilot.cleanup()


if __name__ == "__main__":
    main()
