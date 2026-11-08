"""Offline paired scan of an already built image, copying a verified frozen DB.

Never calls Pilot.source_image (the historical base override) or updates the DB.
Only new owned containers, runner image and cache copy are cleaned up. The input
image, original database and historical evidence remain untouched.
"""

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from scripts.compare_supply_chain import (
    BASE,
    IDENTITIES,
    MEASURE,
    ROOT,
    Pilot,
    control,
    extract_binary,
    run,
    sha256,
    summarize,
)


def require(value, message):
    if not value:
        raise ValueError(message)


def verify_prior_snapshot(previous, lock):
    require(previous["completed"] and previous["tools"] == lock, "historical_scanner_lock")
    signatures = previous["signature_verification"]
    require(set(signatures) == set(IDENTITIES) and all(
        signatures[name]["checksum_verified"] is True and signatures[name]["identity"] == identity
        for name, identity in IDENTITIES.items()), "historical_signature_record")
    require(previous["db_files"] == previous["db_files_after"] and bool(previous["db_files"]),
            "historical_database_mutation")


def prepare(pilot, previous_path):
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    verify_prior_snapshot(previous, pilot.lock)
    for name in ("bin", "input", "out"):
        (pilot.directory / name).mkdir(parents=True, exist_ok=True)
    # Reconstruct executables from the exact release archives whose signed
    # checksums were verified in the historical pilot; verify all asset bytes.
    downloads = ROOT / "runtime/c03/downloads"
    for tool in pilot.lock["tools"]:
        for asset in tool["assets"]:
            require(sha256(downloads / asset["name"]) == asset["digest"].removeprefix("sha256:"),
                    "frozen_tool_asset_digest")
        destination = pilot.directory / "bin" / tool["name"]
        if tool["name"] == "cosign":
            shutil.copyfile(downloads / "cosign-linux-amd64", destination)
        else:
            archive = next(a["name"] for a in tool["assets"] if a["name"].endswith(".tar.gz"))
            extract_binary(downloads / archive, tool["name"], destination)
    (pilot.directory / "measure.py").write_text(MEASURE, encoding="utf-8", newline="\n")
    (pilot.directory / "Dockerfile.runner").write_text(
        f"FROM {BASE}\nCOPY bin /tools\nCOPY measure.py /measure.py\n"
        "RUN chmod 0555 /tools/* /measure.py\nENV HOME=/tmp\nUSER 10001:10001\n", encoding="utf-8", newline="\n")
    (pilot.directory / ".dockerignore").write_text(
        "*\n!bin/\n!bin/*\n!measure.py\n!Dockerfile.runner\n", encoding="utf-8", newline="\n")
    run(["docker", "build", "--file", "Dockerfile.runner", "--tag", pilot.runner_image, "."], cwd=pilot.directory)
    pilot.report["runner_image_id"] = run(["docker", "image", "inspect", pilot.runner_image, "--format", "{{.Id}}"]).strip()
    pilot.report["previous_summary_sha256"] = sha256(previous_path)
    pilot.report["signature_verification"] = previous["signature_verification"]
    pilot.report["signature_reuse"] = "Prior signed-checksum verification; identical release asset hashes checked again, no new signature query."
    pilot.report["binary_sha256"] = {p.name: sha256(p) for p in (pilot.directory / "bin").iterdir()}
    original = previous["cache_volume"]
    require(original.startswith("c03-") and original.endswith("-db") and original != pilot.cache_volume,
            "original_cache_scope")
    run(["docker", "volume", "inspect", original])  # Never silently create a missing original.
    run(["docker", "volume", "create", "--label", "secops.c03=" + pilot.ident, pilot.cache_volume])
    copier = pilot.ident + "-copy"
    pilot.containers.append(copier)
    run(["docker", "run", "--name", copier, "--network", "none", "--read-only", "--user", "0:0",
         "--label", "secops.c03=" + pilot.ident,
         "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_READ_SEARCH", "--security-opt=no-new-privileges:true",
         "--mount", f"type=volume,src={original},dst=/original,readonly",
         "--mount", f"type=volume,src={pilot.cache_volume},dst=/cache", "--entrypoint", "sh", BASE,
         "-c", "cp -R /original/. /cache/ && chown -R 10001:10001 /cache"])
    pilot.report["frozen_database_source"] = original
    copied = pilot.database_hashes("copied")
    require(copied == previous["db_files_after"], "copied_database_digest")
    pilot.save()


def inspect_image(pilot, image):
    image_id = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"]).strip()
    pilot.report["app_image_id"] = image_id
    pilot.report["build_recipe_override"] = None
    pilot.report["image_origin"] = "Already built candidate image; no source rebuild or historical base substitution."
    archive = pilot.directory / "input/app.tar"
    run(["docker", "save", "--output", str(archive), image_id])
    pilot.report["image_archive_sha256"] = sha256(archive)
    paths = {p: digest for p, digest in pilot.report["source_input_sha256"].items()
             if p.startswith(("app/", "scripts/"))}
    probe = "import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in " + repr(list(paths)) + "}))"
    observed = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python", image_id, "-c", probe])
    require(json.loads(observed) == paths, "candidate_image_source_mismatch")
    pilot.report["image_app_scripts_source_verified"] = True
    code = ("import importlib.metadata,json,subprocess; "
        "print(json.dumps({'pypi':[(d.metadata['Name'],d.version) for d in importlib.metadata.distributions()],"
        "'deb':subprocess.check_output(['dpkg-query','-W','-f=${Package}\\t${Version}\\t${db:Status-Status}\\n'],text=True)}))")
    raw = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges:true", "--entrypoint", "python", image_id, "-c", code])
    (pilot.directory / "out/installed.json").write_text(raw, encoding="utf-8")
    for version in ("2.31.0", "2.32.0"):
        (pilot.directory / f"input/requests-{version}.json").write_text(json.dumps(control(version)), encoding="utf-8")
    pilot.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--previous-summary", required=True, type=Path)
    args = parser.parse_args()
    require(not args.directory.exists(), "fresh_scan_directory_required")
    pilot = Pilot(args.directory, args.source_ref, 3)
    pilot.directory.mkdir(parents=True)
    # Do not let inherited cleanup remove the caller's input image.
    pilot.app_image = pilot.ident + "-unused-input"
    try:
        pilot.report["source_dirty"] = bool(run(["git", "status", "--porcelain"]).strip())
        paths = [ROOT / name for name in ("Dockerfile", "pyproject.toml", "scripts/recheck_supply_chain.py")]
        paths += [p for folder in ("app", "scripts", "infra/runtime") for p in (ROOT / folder).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".py", ".json", ".yaml", ".lock", ".patch", ".md"}]
        pilot.report["source_input_sha256"] = {p.relative_to(ROOT).as_posix(): sha256(p) for p in paths}
        prepare(pilot, args.previous_summary)
        inspect_image(pilot, args.image)
        pilot.scan(initialize_db=False)
        pilot.report["completed"] = True
        pilot.save()
        pilot.report = summarize(pilot.directory)
        require(pilot.report["results"]["database_files_unchanged_during_offline_scans"], "database_changed")
    except Exception as exc:
        pilot.report["completed"] = False
        pilot.report["failure"] = str(exc)
        raise
    finally:
        pilot.report["finished_at"] = datetime.now(UTC).isoformat()
        pilot.save()
        pilot.cleanup()
        # Retain only the original frozen DB; the copied cache is disposable.
        subprocess.run(["docker", "volume", "rm", pilot.cache_volume], capture_output=True, check=False)


if __name__ == "__main__":
    main()
