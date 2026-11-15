"""Container-only, hash-bound runtime patch preparation. No host environment setup."""

import argparse
import ctypes
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_lock():
    lock = json.loads((HERE / "sources.lock.json").read_text(encoding="utf-8"))
    require(lock["schema"] == "secops-runtime-sources-1", "runtime_lock_schema")
    return lock


def apply_hunks(original, patch):
    """Exact unified-diff application, no offsets, fuzz, links, or file-name writes."""
    source, lines = original.splitlines(keepends=True), patch.splitlines(keepends=True)
    require(lines[:2] == ["--- Lib/http/client.py\n", "+++ Lib/http/client.py\n"], "patch_file_scope")
    output, cursor, index = [], 0, 2
    while index < len(lines):
        header = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n", lines[index])
        require(header is not None, "patch_hunk_header")
        old_start, old_count, new_start, new_count = header.groups()
        start = int(old_start) - 1
        require(cursor <= start <= len(source), "patch_hunk_order")
        output.extend(source[cursor:start])
        require(len(output) == int(new_start) - 1, "patch_new_offset")
        cursor, removed, added = start, 0, 0
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            require(line[:1] in {" ", "+", "-"}, "patch_line")
            if line[0] in " -":
                require(cursor < len(source) and source[cursor] == line[1:], "patch_context_mismatch")
                cursor += 1
                removed += 1
            if line[0] in " +":
                output.append(line[1:])
                added += 1
            index += 1
        require(removed == int(old_count or 1) and added == int(new_count or 1), "patch_hunk_size")
    output.extend(source[cursor:])
    return "".join(output)


def patch_http(lock):
    require(platform.python_version() == lock["python_version"], "runtime_python_version")
    target = Path(sysconfig.get_path("stdlib")) / "http/client.py"
    before = target.read_bytes()
    spec = lock["http_client"]
    require(sha256(before) == spec["before_sha256"], "stdlib_before_digest")
    patch = (HERE / "http-client.patch").read_bytes()
    require(sha256(patch) == spec["patch_sha256"], "stdlib_patch_digest")
    after = apply_hunks(before.decode("utf-8"), patch.decode("utf-8")).encode()
    require(sha256(after) == spec["after_sha256"], "stdlib_after_digest")
    compile(after, str(target), "exec")
    target.write_bytes(after)
    # The child process doing downloads starts after this function exits. Never
    # rely on an already imported, unpatched http.client object in this process.
    print(json.dumps({"http_client_patched_sha256": spec["after_sha256"]}))


def download(spec, destination, limit=16 * 1024 * 1024):
    url = urlparse(spec["url"])
    require(url.scheme == "https" and url.hostname in {"www.sqlite.org", "files.pythonhosted.org"},
            "runtime_source_origin")
    request = Request(spec["url"], headers={"User-Agent": "secops-pinned-runtime"})
    with urlopen(request, timeout=120) as response:
        final = urlparse(response.url)
        require(final.scheme == "https" and final.hostname == url.hostname, "runtime_source_redirect")
        data = response.read(limit + 1)
    require(len(data) <= limit and sha256(data) == spec["sha256"], "runtime_source_digest")
    if "sha3_256" in spec:
        require(hashlib.sha3_256(data).hexdigest() == spec["sha3_256"], "runtime_source_sha3")
    destination.write_bytes(data)


def extract_sqlite(archive, directory):
    root = directory.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        require(len(members) < 10000, "source_archive_count")
        for member in members:
            target = (root / member.name).resolve()
            require(target.is_relative_to(root) and (member.isfile() or member.isdir()), "source_archive_path")
        bundle.extractall(root, filter="data")
    sources = list(root.glob("*/sqlite3.c"))
    require(len(sources) == 1, "sqlite_amalgamation_missing")
    return sources[0]


def build_sqlite(lock, output, profile):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secops-sqlite-") as scratch:
        scratch = Path(scratch)
        archive = scratch / "sqlite.tar.gz"
        download(lock["sqlite"], archive)
        source = extract_sqlite(archive, scratch)
        library = output / "libsqlite3.so.0"
        defines = lock["sqlite_compile_defines"]
        require(all(re.fullmatch(r"SQLITE_[A-Z0-9_]+(?:=[0-9]+)?", item) for item in defines),
                "sqlite_compile_options")
        subprocess.run(["gcc", "-O2", "-fPIC", "-shared", "-Wl,-soname,libsqlite3.so.0",
                        "-Wl,-z,relro,-z,now", *["-D" + item for item in defines], str(source),
                        "-lm", "-ldl", "-pthread", "-o", str(library)], check=True)
        library.chmod(0o555)
        native = ctypes.CDLL(str(library))
        native.sqlite3_libversion.restype = ctypes.c_char_p
        native.sqlite3_sourceid.restype = ctypes.c_char_p
        require(native.sqlite3_libversion().decode() == lock["sqlite"]["version"], "sqlite_built_version")
        require(native.sqlite3_sourceid().decode() == lock["sqlite"]["source_id"], "sqlite_source_id")
        shutil.copyfile(source.parent / "sqlite3.h", output / "sqlite3.h")
        library_dir = "/usr/lib/x86_64-linux-gnu" if profile == "debian" else "/var/lang/lib"
        (output / "sqlite3.pc").write_text(
            f"prefix=/usr/local\nlibdir={library_dir}\nincludedir=${{prefix}}/include\n\n"
            "Name: SQLite\nDescription: Hash-verified upstream SQLite runtime\n"
            f"Version: {lock['sqlite']['version']}\nLibs: -L${{libdir}} -lsqlite3\nCflags: -I${{includedir}}\n",
            encoding="utf-8")
        download(lock["pip"], output / lock["pip"]["filename"])
        compiler = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]
        metadata = {"schema": "secops-runtime-build-1", "python": lock["python_version"],
                    "profile": profile, "library_path": library_dir + "/libsqlite3.so.0",
                    "sqlite": lock["sqlite"], "sqlite_compile_defines": defines,
                    "library_sha256": sha256(library.read_bytes()), "compiler": compiler,
                    "http_client": lock["http_client"], "pip": lock["pip"]}
        if profile == "debian":
            package = scratch / "package"
            control = package / "DEBIAN"
            control.mkdir(parents=True)
            native_path = package / "usr/lib/x86_64-linux-gnu"
            native_path.mkdir(parents=True)
            shutil.copyfile(library, native_path / "libsqlite3.so.0.3.54.1")
            (native_path / "libsqlite3.so.0").symlink_to("libsqlite3.so.0.3.54.1")
            (control / "control").write_text(
                "Package: libsqlite3-0\nVersion: 3.54.1-0secops1\nArchitecture: amd64\n"
                "Source: sqlite3 (3.54.1-0secops1)\nMulti-Arch: same\nSection: libs\nPriority: optional\n"
                "Depends: libc6 (>= 2.41)\nMaintainer: SecOps local build <noreply@example.invalid>\n"
                "Description: Locally maintained hash-verified SQLite security runtime\n"
                " Built from upstream 3.54.1; not a Debian security-team release.\n", encoding="utf-8")
            (control / "triggers").write_text("activate-noawait ldconfig\n", encoding="utf-8")
            doc = package / "usr/share/doc/libsqlite3-0"
            doc.mkdir(parents=True)
            (doc / "copyright").write_text(
                "SQLite is in the public domain. https://www.sqlite.org/copyright.html\n"
                "Local security build provenance: /opt/secops-runtime/runtime.json\n", encoding="utf-8")
            deb = output / "libsqlite3-0_3.54.1-0secops1_amd64.deb"
            subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(package), str(deb)], check=True)
            metadata["debian_package"] = {"filename": deb.name, "sha256": sha256(deb.read_bytes()),
                                           "version": "3.54.1-0secops1", "official_debian_build": False}
        (output / "runtime.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def install_library(assets):
    metadata = json.loads((assets / "runtime.json").read_text(encoding="utf-8"))
    require(sha256((assets / "libsqlite3.so.0").read_bytes()) == metadata["library_sha256"],
            "sqlite_install_digest")
    if metadata["profile"] == "debian":
        spec = metadata["debian_package"]
        package = assets / spec["filename"]
        require(sha256(package.read_bytes()) == spec["sha256"], "sqlite_deb_digest")
        subprocess.run(["dpkg", "-i", str(package)], check=True)
        version = subprocess.check_output(["dpkg-query", "-W", "-f", "${Version}", "libsqlite3-0"], text=True)
        require(version == spec["version"], "sqlite_deb_version")
        subprocess.run(["ldconfig"], check=True)
    else:
        require(metadata["profile"] == "lambda", "runtime_profile")
        target = Path("/var/lang/lib/libsqlite3.so.0").resolve()
        require(target.is_relative_to(Path("/var/lang/lib")), "lambda_library_scope")
        temporary = target.with_name(target.name + ".secops-new")
        shutil.copyfile(assets / "libsqlite3.so.0", temporary)
        temporary.chmod(0o555)
        # Never truncate the inode of a library mapped by this Python process.
        os.replace(temporary, target)


def bootstrap_pip(lock, assets):
    wheel = assets / lock["pip"]["filename"]
    require(sha256(wheel.read_bytes()) == lock["pip"]["sha256"], "pip_bootstrap_digest")
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], check=True)
    require(importlib.metadata.version("pip") == lock["pip"]["version"], "pip_bootstrap_version")
    refresh_ensurepip(lock, wheel)


def refresh_ensurepip(lock, wheel):
    """Prevent a fresh venv from reinstalling the old bundled pip distribution."""
    require(sha256(wheel.read_bytes()) == lock["pip"]["sha256"], "ensurepip_new_wheel_digest")
    target = Path(sysconfig.get_path("stdlib")) / "ensurepip/__init__.py"
    spec = lock["ensurepip"]
    before = target.read_bytes()
    require(sha256(before) == spec["before_sha256"], "ensurepip_before_digest")
    old_marker = ('_PIP_VERSION = "' + spec["old_version"] + '"').encode()
    new_marker = ('_PIP_VERSION = "' + lock["pip"]["version"] + '"').encode()
    require(before.count(old_marker) == 1, "ensurepip_marker")
    after = before.replace(old_marker, new_marker)
    require(sha256(after) == spec["after_sha256"], "ensurepip_after_digest")
    bundled = target.parent / "_bundled"
    old = bundled / f"pip-{spec['old_version']}-py3-none-any.whl"
    require({p.name for p in bundled.glob("*.whl")} == {old.name}, "ensurepip_bundle_scope")
    require(sha256(old.read_bytes()) == spec["old_wheel_sha256"], "ensurepip_old_wheel_digest")
    compile(after, str(target), "exec")
    shutil.copyfile(wheel, bundled / lock["pip"]["filename"])
    target.write_bytes(after)
    old.unlink()


def build_project(output):
    output.mkdir(parents=True, exist_ok=True)
    require(not list(output.iterdir()), "project_wheel_directory_not_empty")
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
                    "--wheel-dir", str(output), "."], check=True)
    wheels = list(output.glob("zero_trust_llm_secops-*-py3-none-any.whl"))
    require(len(wheels) == 1, "project_wheel_identity")
    wheel = wheels[0]
    (output / "project.lock").write_text(str(wheel) + " --hash=sha256:" + sha256(wheel.read_bytes()) + "\n",
                                        encoding="utf-8")


def verify(lock, metadata_path):
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    require(platform.python_version() == lock["python_version"], "runtime_python_version")
    require(importlib.metadata.version("pip") == lock["pip"]["version"], "runtime_pip_version")
    import ensurepip
    require(ensurepip.version() == lock["pip"]["version"], "runtime_ensurepip_version")
    ensurepip_file = Path(ensurepip.__file__)
    require(sha256(ensurepip_file.read_bytes()) == lock["ensurepip"]["after_sha256"], "runtime_ensurepip_digest")
    bundled_wheels = list((ensurepip_file.parent / "_bundled").glob("*.whl"))
    require(len(bundled_wheels) == 1 and bundled_wheels[0].name == lock["pip"]["filename"]
            and sha256(bundled_wheels[0].read_bytes()) == lock["pip"]["sha256"], "runtime_ensurepip_bundle")
    client = Path(sysconfig.get_path("stdlib")) / "http/client.py"
    require(sha256(client.read_bytes()) == lock["http_client"]["after_sha256"], "runtime_http_digest")
    require(sqlite3.sqlite_version == lock["sqlite"]["version"], "runtime_sqlite_version")
    library = Path(metadata["library_path"]).resolve()
    require(sha256(library.read_bytes()) == metadata["library_sha256"], "runtime_sqlite_library_digest")
    with sqlite3.connect(":memory:") as database:
        require(database.execute("SELECT sqlite_source_id()").fetchone()[0] == lock["sqlite"]["source_id"],
                "runtime_sqlite_source")
        options = {row[0] for row in database.execute("PRAGMA compile_options")}
        require({"THREADSAFE=1", "ENABLE_FTS3", "ENABLE_FTS5", "ENABLE_RTREE", "ENABLE_SESSION"} <= options,
                "runtime_sqlite_features")
    print(json.dumps({"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                      "http_client_sha256": lock["http_client"]["after_sha256"],
                      "sqlite_library_sha256": metadata["library_sha256"], "pip": lock["pip"]["version"]}))


def main():
    require(sys.platform == "linux" and platform.machine() == "x86_64", "linux_amd64_container_only")
    require(os.geteuid() == 0, "container_build_root_required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["patch-http", "build-sqlite", "install-library", "bootstrap-pip", "build-project", "verify"])
    parser.add_argument("--assets", type=Path, default=Path("/runtime-assets"))
    parser.add_argument("--profile", choices=["debian", "lambda"], default="debian")
    args = parser.parse_args()
    lock = load_lock()
    if args.operation == "patch-http":
        patch_http(lock)
    elif args.operation == "build-sqlite":
        build_sqlite(lock, args.assets, args.profile)
    elif args.operation == "install-library":
        install_library(args.assets)
    elif args.operation == "bootstrap-pip":
        bootstrap_pip(lock, args.assets)
    elif args.operation == "build-project":
        build_project(args.assets)
    else:
        verify(lock, args.assets / "runtime.json")


if __name__ == "__main__":
    main()
