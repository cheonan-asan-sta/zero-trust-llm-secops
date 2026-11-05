"""Offline C03 evidence review. Never scan, fetch advisories, suppress, or remediate.

The caller pins a trusted pilot summary SHA-256; its manifest pins every input read.
Aliases are direct scanner claims scoped to the same package/version, not findings
of applicability. Even matched findings remain unreviewed.
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from scripts.compare_supply_chain import canonical_package, syft_packages, trivy_packages

MAX_JSON = 32 * 1024 * 1024
ADVISORY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}|TEMP-[A-Za-z0-9-]+)")


class ReviewError(ValueError):
    """A fixed, non-sensitive rejection code, never a value read from an input."""


def require(condition, code):
    if not condition:
        raise ReviewError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(data):
    def invalid(_):
        raise ValueError("nonfinite_json_number")

    require(len(data) <= MAX_JSON, "json_too_large")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def implementation_hashes():
    directory = Path(__file__).resolve().parent
    return {"scripts/" + name: digest((directory / name).read_bytes().replace(b"\r\n", b"\n"))
            for name in ["review_supply_chain.py", "compare_supply_chain.py"]}


def nonempty(value):
    require(isinstance(value, str) and 0 < len(value) <= 2048, "invalid_text_field")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), "invalid_text_field")
    return value


def strings(values):
    require(isinstance(values, list), "invalid_list_field")
    return sorted({nonempty(value) for value in values})


def normalized(document, scanner):
    """Keep selected structured evidence only; never mine descriptions/URLs for aliases."""
    rows = {}
    if scanner == "grype":
        require(isinstance(document.get("matches"), list), "missing_grype_matches")
        inputs = [(m, None) for m in document["matches"]]
    elif scanner == "trivy":
        require(isinstance(document.get("Results"), list), "missing_trivy_results")
        inputs = []
        for result in document["Results"]:
            require(isinstance(result, dict), "invalid_trivy_result")
            vulns = result.get("Vulnerabilities", [])
            require(isinstance(vulns, list), "invalid_trivy_vulnerabilities")
            inputs.extend((v, nonempty(result["Type"])) for v in vulns)
    else:
        raise ValueError("unknown_scanner")
    for item, kind in inputs:
        require(isinstance(item, dict), "invalid_finding")
        if scanner == "grype":
            artifact, vuln = item["artifact"], item["vulnerability"]
            package = canonical_package(nonempty(artifact["type"]),
                                        nonempty(artifact["name"]), nonempty(artifact["version"]))
            advisory = nonempty(vuln["id"])
            aliases = strings([v["id"] for v in item.get("relatedVulnerabilities", [])])
            severity = nonempty(vuln.get("severity", "Unknown")).upper()
            fixes = strings(vuln.get("fix", {}).get("versions", []))
            state = nonempty(vuln.get("fix", {}).get("state", "unknown"))
            provider = nonempty(vuln.get("namespace", "unknown"))
            purl = artifact.get("purl")
        else:
            package = canonical_package("deb" if kind == "debian" else kind,
                                        nonempty(item["PkgName"]), nonempty(item["InstalledVersion"]))
            advisory = nonempty(item["VulnerabilityID"])
            aliases = strings(item.get("VendorIDs", []))
            severity = nonempty(item.get("Severity", "UNKNOWN")).upper()
            fixes = strings([v.strip() for v in item.get("FixedVersion", "").split(",") if v.strip()])
            state = nonempty(item.get("Status", "unknown"))
            provider = nonempty(item.get("DataSource", {}).get("ID", "unknown"))
            purl = item.get("PkgIdentifier", {}).get("PURL")
        require(ADVISORY.fullmatch(advisory) is not None, "unsupported_advisory_id")
        # Unknown vendor IDs are retained, but cannot create an alias match.
        observation = {"severity": severity, "fix_versions": fixes, "provider_status": state,
                       "provider": provider, "purl": nonempty(purl) if purl else None,
                       "reported_aliases": aliases}
        key = (*package, advisory)
        existing = rows.setdefault(key, [])
        if observation not in existing:
            existing.append(observation)
    return {key: sorted(values, key=lambda v: json.dumps(v, sort_keys=True))
            for key, values in sorted(rows.items())}


def matching(left, right):
    """A one-to-one direct edge only. No global or transitive alias equivalence."""
    edges = {}
    reverse = {}
    for lkey, lvalues in left.items():
        laliases = {a for v in lvalues for a in v["reported_aliases"] if ADVISORY.fullmatch(a)}
        for rkey, rvalues in right.items():
            if lkey[:3] != rkey[:3]:
                continue
            raliases = {a for v in rvalues for a in v["reported_aliases"] if ADVISORY.fullmatch(a)}
            if lkey[-1] == rkey[-1] or rkey[-1] in laliases or lkey[-1] in raliases:
                edges.setdefault(lkey, []).append(rkey)
                reverse.setdefault(rkey, []).append(lkey)
    pairs = {l: rs[0] for l, rs in edges.items()
             if len(rs) == 1 and len(reverse[rs[0]]) == 1}
    ambiguous_left = set(edges) - set(pairs)
    ambiguous_right = set(reverse) - set(pairs.values())
    return pairs, ambiguous_left, ambiguous_right


def compare(left, right):
    pairs, ambiguous_left, ambiguous_right = matching(left, right)
    groups = []

    def append(lkey=None, rkey=None):
        key = lkey or rkey
        lv, rv = left.get(lkey, []), right.get(rkey, [])
        relation = ("same_native_id" if lkey[-1] == rkey[-1] else "direct_provider_alias") if (
            lkey and rkey) else "grype_only" if lkey else "trivy_only"
        flags = []
        if not lkey or not rkey:
            flags.append("missing_counterpart")
        if lkey in ambiguous_left or rkey in ambiguous_right:
            flags.append("ambiguous_alias")
        if key[0] == "binary":
            flags.append("binary_catalog_scope")
        if any(k and k[-1].startswith("TEMP-") for k in [lkey, rkey]):
            flags.append("temporary_advisory")
        if lv and rv:
            if {v["severity"] for v in lv} != {v["severity"] for v in rv}:
                flags.append("severity_disagreement")
            if {tuple(v["fix_versions"]) for v in lv} != {tuple(v["fix_versions"]) for v in rv}:
                flags.append("fix_versions_disagreement")
        for values in [lv, rv]:
            if len(values) > 1:
                flags.append("multiple_provider_observations")
        evidence = {}
        for scanner, skey, values in [("grype", lkey, lv), ("trivy", rkey, rv)]:
            if skey:
                evidence[scanner] = {"native_id": skey[-1], "observations": values}
        groups.append({"package": {"ecosystem": key[0], "name": key[1], "version": key[2]},
                       "relation": relation, "flags": sorted(set(flags)), "evidence": evidence,
                       "review_state": "unreviewed", "applicability": "not_assessed"})

    for key in left:
        append(key, pairs.get(key))
    for key in right.keys() - set(pairs.values()):
        append(rkey=key)
    groups.sort(key=lambda g: json.dumps([g["package"], g["evidence"]], sort_keys=True))
    for index, group in enumerate(groups, 1):
        group["id"] = f"C03-{index:04}"
    return groups


class Campaign:
    def __init__(self, summary_path, expected_sha256, raw_directory):
        require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256 or "") is not None,
                "invalid_summary_pin")
        path = Path(summary_path)
        require(path.stat().st_size <= MAX_JSON, "json_too_large")
        data = path.read_bytes()
        require(digest(data) == expected_sha256, "summary_digest_mismatch")
        self.summary = decode(data)
        self.pin = expected_sha256
        self.directory = Path(raw_directory).resolve(strict=True)
        self.manifest = {}
        self.used = {}
        for name, spec in self.summary["results"]["raw_artifacts"].items():
            normalized_name = name.replace("\\", "/")
            parts = normalized_name.split("/")
            require(len(parts) == 2 and parts[0] == "out" and parts[1] not in {"", ".", ".."}
                    and ":" not in parts[1] and "\x00" not in parts[1], "unsafe_manifest_path")
            require(normalized_name not in self.manifest, "duplicate_manifest_path")
            self.manifest[normalized_name] = spec

    def read(self, name):
        key = "out/" + name
        spec = self.manifest.get(key)
        require(isinstance(spec, dict), "missing_artifact_manifest")
        path = self.directory / PurePosixPath(key).name
        require(not path.is_symlink() and path.resolve(strict=True).parent == self.directory,
                "artifact_path_escape")
        require(path.stat().st_size <= MAX_JSON, "json_too_large")
        data = path.read_bytes()
        require(len(data) == spec.get("bytes") and digest(data) == spec.get("sha256"),
                "artifact_digest_mismatch")
        self.used[key] = {"sha256": digest(data), "bytes": len(data)}
        return decode(data)

    def checked(self, label):
        metrics = self.read(label + ".metrics.json")
        require(type(metrics.get("exit_code")) is int and metrics["exit_code"] == 0,
                "scanner_exit_not_zero")
        return self.read(label + ".json")

    def report(self):
        summary = self.summary
        require(summary.get("schema") == "c03-pilot-1" and summary.get("completed") is True,
                "campaign_incomplete")
        repeats = summary.get("repeats")
        require(type(repeats) is int and 3 <= repeats <= 20, "invalid_repeat_count")
        require(summary["conditions"].get("scan_network") == "none", "scan_not_offline")
        require(bool(summary["db_files"]) and summary["db_files"] == summary["db_files_after"]
                and summary["results"].get("database_files_unchanged_during_offline_scans") is True,
                "database_drift")
        image = summary["app_image_id"]
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image) is not None, "invalid_image_id")
        expected_versions = {tool["name"]: tool["tag"].removeprefix("v")
                             for tool in summary["tools"]["tools"]}
        inventory = self.read("installed.json")
        expected_inventory = {canonical_package("pypi", name, version)
                              for name, version in inventory["pypi"]}
        for line in inventory["deb"].splitlines():
            name, version, status = line.split("\t")
            if status == "installed":
                expected_inventory.add(canonical_package("deb", name, version))
        observed = {"grype": [], "trivy": []}
        for repeat in range(1, repeats + 1):
            for scanner in ["syft", "grype", "trivy"]:
                doc = self.checked(f"run-{repeat}-{scanner}")
                observed_image = (doc.get("Metadata", {}).get("ImageID") if scanner == "trivy"
                                  else doc.get("source", {}).get(
                                      "metadata" if scanner == "syft" else "target", {}).get("imageID"))
                require(observed_image == image, "scan_image_mismatch")
                version = (doc.get("Trivy", {}).get("Version") if scanner == "trivy"
                           else doc.get("descriptor", {}).get("version"))
                require(version == expected_versions[scanner], "scanner_version_mismatch")
                if scanner != "grype":
                    extractor = trivy_packages if scanner == "trivy" else syft_packages
                    require(extractor(doc) == expected_inventory, "inventory_mismatch")
                if scanner != "syft":
                    observed[scanner].append(normalized(doc, scanner))
        for scanner, runs in observed.items():
            require(all(run == runs[0] for run in runs), "repeat_metadata_drift")
            native = sorted([list(key) for key in runs[0]])
            require(native == summary["results"]["findings"][scanner]["rows"],
                    "summary_findings_mismatch")
            for version, present in [("2.31.0", True), ("2.32.0", False)]:
                rows = normalized(self.checked(f"control-{version}-{scanner}"), scanner)
                targets = {"CVE-2024-35195", "GHSA-9wx4-h78v-vm56"}
                found = any(key[:3] == ("pypi", "requests", version)
                            and (key[-1] in targets or any(
                                targets.intersection(v["reported_aliases"]) for v in values))
                            for key, values in rows.items())
                require(found == present, "advisory_control_failed")
        groups = compare(observed["grype"][0], observed["trivy"][0])
        return {"schema": "c03-findings-review-1", "basis": {
            "trusted_summary_sha256": self.pin, "scanned_source_commit": summary["source_commit"],
            "analysis_implementation_lf_sha256": implementation_hashes(),
            "app_image_id": image, "image_archive_sha256": summary["image_archive_sha256"],
            "tools": expected_versions, "db_files": summary["db_files"],
            "repeats_verified": repeats, "inventory_matched": len(expected_inventory),
            "verified_inputs": dict(sorted(self.used.items()))},
            "counts": {"grype_native": len(observed["grype"][0]),
                       "trivy_native": len(observed["trivy"][0]), "groups": len(groups),
                       "relations": dict(sorted(Counter(g["relation"] for g in groups).items())),
                       "flags": dict(sorted(Counter(f for g in groups for f in g["flags"]).items())),
                       "unreviewed": len(groups)},
            "review_complete": not groups, "groups": groups,
            "limits": ["Offline reanalysis of the pinned historical image; not a new scan.",
                       "Hashes require a separately trusted summary; not a signature or anti-rollback.",
                       "Direct provider alias claims are not independently confirmed equivalence.",
                       "Fix/severity differences are metadata differences, not applicability verdicts.",
                       "No finding suppressed, dependency changed, or scanner selected.",
                       "No reachability assessment, precision/recall, or independent team review."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--summary-sha256", required=True)
    parser.add_argument("--raw-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-reviewed", action="store_true")
    args = parser.parse_args()
    try:
        report = Campaign(args.summary, args.summary_sha256, args.raw_directory).report()
        # No existing evidence/report is overwritten, even when output aliases an input.
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        # Avoid dumping scanner contents, private paths, or malformed field values.
        print(json.dumps({"status": "rejected", "error_type": type(error).__name__,
                          "code": str(error) if isinstance(error, ReviewError) else "invalid_input"}))
        return 1
    print(json.dumps({"status": "reported", "counts": report["counts"],
                      "review_complete": report["review_complete"]}))
    return 2 if args.require_reviewed and not report["review_complete"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
