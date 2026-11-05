"""Read-only, offline metadata/feature probe for the pinned C03 image.

No exploit archive, remote peer, credentials, environment dump, or app request.
Invoke with `python -I /probe.py` inside the explicitly selected image.
"""

import ast
import base64
import binascii
import hashlib
import importlib.metadata
import inspect
import io
import json
import os
import pathlib
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
from unittest.mock import patch

REFERENCE_PREFIXES = ("base64.", "ssl.", "urllib.request.", "http.client.", "imaplib.",
                      "poplib.", "http.cookies.", "pkgutil.", "tarfile.", "sqlite3.")


def dotted(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value, aliases)
        return prefix + "." + node.attr if prefix else ""
    return ""


def scan_references(roots):
    """Direct AST references only; absence cannot rule out indirect or dynamic use."""
    result = []
    for root in roots:
        root = pathlib.Path(root)
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            aliases = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for item in node.names:
                        aliases[item.asname or item.name.split(".")[0]] = (
                            item.name if item.asname else item.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for item in node.names:
                        aliases[item.asname or item.name] = node.module + "." + item.name

            data = path.read_bytes().replace(b"\r\n", b"\n")
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = dotted(node.func, aliases)
                    if name.startswith(REFERENCE_PREFIXES):
                        selected = {}
                        for item in node.keywords:
                            if item.arg in {"validate", "filter"} and isinstance(item.value, ast.Constant):
                                selected[item.arg] = item.value.value
                        result.append({"file": root.name + "/" + path.relative_to(root).as_posix(),
                                       "line": node.lineno, "call": name, "options": selected,
                                       "source_lf_sha256": hashlib.sha256(data).hexdigest()})
    return sorted(result, key=lambda value: (value["file"], value["line"], value["call"]))


def source_evidence(obj):
    source = inspect.getsource(obj)
    return {"sha256": hashlib.sha256(source.encode()).hexdigest(),
            "file": inspect.getsourcefile(obj)}


def probe():
    if sys.platform != "linux":
        raise ValueError("linux_image_required")
    rows = subprocess.check_output([
        "dpkg-query", "-W", "-f",
        "${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\\n",
    ], text=True, encoding="utf-8").splitlines()
    installed = []
    for row in rows:
        name, version, source, source_version, status = row.split("\t")
        if status == "installed":
            installed.append({"name": name.split(":")[0], "version": version,
                              "source": source, "source_version": source_version})
    artifacts = {}
    for package in installed:
        paths = subprocess.check_output(["dpkg-query", "-L", package["name"]], text=True).splitlines()
        files = [path for path in paths if pathlib.Path(path).is_file()]
        commands_in_package = [path for path in files if path.startswith(
            ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"))]
        shared_objects = [path for path in files if ".so" in pathlib.Path(path).name]
        artifacts[package["name"]] = {
            "regular_file_count": len(files), "command_paths": commands_in_package,
            "shared_object_count": len(shared_objects), "shared_object_paths_sample": shared_objects[:12],
            "only_doc_or_lint_metadata": bool(files) and all(path.startswith(
                ("/usr/share/doc/", "/usr/share/lintian/")) for path in files),
        }
    commands = {}
    for name in ["bash", "su", "runuser", "tar", "rmt", "sulogin", "init", "systemd", "pip"]:
        path = shutil.which(name)
        value = {"path": path}
        if path:
            resolved = pathlib.Path(path).resolve()
            mode = resolved.stat().st_mode
            owner = subprocess.run(["dpkg-query", "-S", str(resolved)], capture_output=True,
                                   text=True, encoding="utf-8", check=False)
            value.update({"resolved": str(resolved), "suid": bool(mode & stat.S_ISUID),
                          "sgid": bool(mode & stat.S_ISGID),
                          "owner": owner.stdout.strip() if owner.returncode == 0 else None})
        commands[name] = value
    status = {}
    for line in pathlib.Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"NoNewPrivs", "CapEff", "CapPrm", "CapBnd", "Seccomp"}:
            status[key] = value.strip()
    # These are tiny public constants, not application tokens or crafted archives.
    alternative_accepts_standard = base64.urlsafe_b64decode(b"++//") == b"\xfb\xef\xff"
    accepts_extra_quad = base64.b64decode(b"YQ==Yg==") == b"a"
    try:
        base64.b64decode(b"YQ==Yg==", validate=True)
        strict_rejects_extra_quad = False
    except binascii.Error:
        strict_rejects_extra_quad = True
    import _sqlite3

    from pip._internal.commands import create_command
    from pip._internal.utils import unpacking

    filters = []
    data_filter_calls = []
    original = tarfile.TarFile.extractall
    original_data_filter = tarfile.data_filter

    def observed_data_filter(*args, **kwargs):
        data_filter_calls.append(True)
        return original_data_filter(*args, **kwargs)

    def observed_extract(self, *args, **kwargs):
        value = kwargs.get("filter")
        filters.append(value if isinstance(value, str) else getattr(value, "__name__", None))
        return original(self, *args, **kwargs)

    with tempfile.TemporaryDirectory(prefix="c03-benign-") as folder:
        folder = pathlib.Path(folder)
        archive, target = folder / "regular.tar", folder / "output"
        target.mkdir()
        with tarfile.open(archive, "w") as bundle:
            entry = tarfile.TarInfo("package/regular.txt")
            entry.size = 5
            bundle.addfile(entry, io.BytesIO(b"probe"))
        with patch.object(tarfile.TarFile, "extractall", observed_extract), patch.object(
                tarfile, "data_filter", observed_data_filter):
            unpacking.untar_file(str(archive), str(target))
        extract_ok = (target / "regular.txt").read_bytes() == b"probe"
    options, _ = create_command("install").parse_args(["--no-input", "."])
    with sqlite3.connect(":memory:") as database:
        compile_options = sorted(row[0] for row in database.execute("PRAGMA compile_options"))
    return {
        "schema": "c03-runtime-probe-1", "python_version": platform.python_version(),
        "python_executable": sys.executable, "uid": os.getuid(), "euid": os.geteuid(),
        "gid": os.getgid(), "process_security": status,
        "rootfs_readonly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "installed_deb": sorted(installed, key=lambda row: row["name"]),
        "installed_pypi": sorted([[d.metadata["Name"], d.version]
                                  for d in importlib.metadata.distributions()]),
        "deb_package_artifacts": artifacts,
        "commands": commands,
        "features": {"base64_urlsafe_accepts_standard_alphabet": alternative_accepts_standard,
                     "base64_default_accepts_data_after_padding": accepts_extra_quad,
                     "base64_validate_rejects_data_after_padding": strict_rejects_extra_quad,
                     "tarfile_has_data_filter": hasattr(tarfile, "data_filter"),
                     "pip_benign_extract_ok": extract_ok, "pip_effective_tar_filters": filters,
                     "pip_invoked_data_filter": bool(data_filter_calls),
                     "pip_install_disables_version_check": bool(options.disable_pip_version_check)},
        "pip_untar_source": source_evidence(unpacking.untar_file),
        "sqlite": {"version": sqlite3.sqlite_version, "module": _sqlite3.__file__,
                   "compile_options": compile_options,
                   "linked_shared_objects": sorted({line.split("=>")[0].strip()
                       for line in subprocess.check_output(["ldd", _sqlite3.__file__], text=True).splitlines()
                       if "libsqlite3" in line or "libc.so" in line})},
        "direct_references": scan_references(["/app/app", "/app/scripts"]),
        "scope": "Inventory and harmless feature checks only; no exploitation or reachability proof.",
    }


if __name__ == "__main__":
    print(json.dumps(probe(), sort_keys=True, indent=2))
