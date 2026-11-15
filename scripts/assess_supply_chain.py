"""Evidence-bound infrastructure review of the historical C03 image, never a waiver.

This offline reducer joins pinned inventory, selected vendor facts and the previous
finding groups. It does not fetch advisories, scan a new image or modify dependencies.
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from scripts.compare_supply_chain import canonical_package
from scripts.review_supply_chain import ReviewError, decode, digest, require

IMAGE = "sha256:5a64e8c43d9e1712996f29ff9bf6adbb3b19270f67facea535ee428ec754fe54"
ARCHIVE = "5d8dd0efd36b464767f465368d178d8a1ae692e7768d966188623cb5dc8940f7"
PIP_ADVISORIES = {"GHSA-4xh5-x5gv-qwph", "GHSA-58qw-9mgm-455v", "GHSA-6vgw-5pg2-w6jp",
                  "GHSA-jp4c-xjxw-mgf9", "GHSA-qwm4-qh6w-59xr", "GHSA-wf93-45jw-7689"}
PROFILES = {
    "CVE-2025-12781": ("application_boundary_review", "P2", "alternate_base64_alphabet"),
    "CVE-2025-15366": ("conditional_component_risk", "P2", "untrusted_imap_command"),
    "CVE-2025-15367": ("conditional_component_risk", "P2", "untrusted_pop3_command"),
    "CVE-2026-103995": ("runtime_patch_priority", "P1", "untrusted_http_response_framing"),
    "CVE-2026-114583": ("conditional_component_risk", "P1", "untrusted_archive_tar_filter"),
    "CVE-2026-115557": ("runtime_patch_priority", "P1", "compromised_intermediate_trust"),
    "CVE-2026-3446": ("application_boundary_review", "P2", "base64_padding_interpretation"),
    "CVE-2026-3479": ("upstream_disputed_design", "P2", "untrusted_resource_path"),
    "CVE-2026-6019": ("conditional_component_risk", "P2", "cookie_javascript_output"),
}
TEMP = {"TEMP-0841856-B18BAF": "local_bash_privilege_context",
        "TEMP-0628843-DBAD28": "interactive_su_terminal_context",
        "TEMP-0517018-A83CE6": "expert_installer_boot_context",
        "TEMP-0290435-0B57B5": "tar_remote_tape_helper"}


def version_key(value):
    """Only the release/pre-release grammar actually used in these vendor records."""
    if value == "0":
        return (0, 0, 0, 3, 0)
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:(a|b|rc)(\d+))?", value)
    require(match is not None, "unsupported_vendor_version")
    major, minor, patch, stage, serial = match.groups()
    return (int(major), int(minor), int(patch or 0),
            {"a": 0, "b": 1, "rc": 2, None: 3}[stage], int(serial or 0))


def python_affected(value, affected):
    key = version_key(value)
    matches = []
    require(bool(affected), "missing_python_affected")
    for product in affected:
        require(product.get("product") == "CPython" and product.get("defaultStatus") == "unaffected",
                "unexpected_python_product")
        for entry in product["versions"]:
            require(entry.get("status") == "affected" and entry.get("versionType") == "python"
                    and "changes" not in entry, "unsupported_python_range")
            start = version_key(entry["version"])
            if "lessThan" in entry:
                matches.append(start <= key < version_key(entry["lessThan"]))
            elif "lessThanOrEqual" in entry:
                matches.append(start <= key <= version_key(entry["lessThanOrEqual"]))
            else:
                matches.append(key == start)
    return any(matches)


def pip_affected(value, rule):
    match = re.fullmatch(r"(<=|<)\s*(\S+)", rule)
    require(match is not None, "unsupported_pip_range")
    bound = version_key(match[2])
    return version_key(value) <= bound if match[1] == "<=" else version_key(value) < bound


def index_unique(rows, field):
    result = {}
    for row in rows:
        require(row[field] not in result, "duplicate_evidence_row")
        result[row[field]] = row
    return result


def assess(packet, review):
    require(packet.get("schema") == "c03-impact-inputs-1", "unexpected_packet_schema")
    require(review.get("schema") == "c03-findings-review-1", "unexpected_review_schema")
    require(packet["image"]["id"] == review["basis"]["app_image_id"] == IMAGE
            and packet["archive_sha256"] == review["basis"]["image_archive_sha256"] == ARCHIVE,
            "historical_image_mismatch")
    probe = packet["runtime"]
    require(probe.get("schema") == "c03-runtime-probe-1" and probe["python_version"] == "3.12.15",
            "unexpected_runtime")
    require(probe["uid"] == probe["euid"] == 10001 and probe["rootfs_readonly"] is True,
            "unverified_runtime_controls")
    require(probe["process_security"]["NoNewPrivs"] == "1"
            and all(int(probe["process_security"][name], 16) == 0 for name in ["CapEff", "CapBnd", "CapPrm"]),
            "unverified_runtime_controls")
    campaign = packet["probe_campaign"]
    require(campaign["byte_identical"] is True and len(campaign["runs"]) == 3,
            "probe_repeats_unverified")
    output_hashes = {run["output_sha256"] for run in campaign["runs"]}
    require(len(output_hashes) == 1 and re.fullmatch(r"[a-f0-9]{64}", next(iter(output_hashes))) is not None,
            "probe_repeats_unverified")
    for run in campaign["runs"]:
        require(run["image_id"] == IMAGE and run["exit_code"] == 0 and run["network"] == "none"
                and run["readonly_rootfs"] is True and run["privileged"] is False
                and run["tty"] is False and run["uid"] == "10001:10001"
                and run["cap_drop"] == ["ALL"] and "no-new-privileges" in run["security_opt"],
                "unverified_probe_isolation")
    groups = index_unique(review["groups"], "id")
    require(bool(groups) and len(groups) == review["counts"]["groups"], "review_group_count_mismatch")
    facts = index_unique(packet["vendor_facts"], "group_id")
    require(groups.keys() == facts.keys(), "vendor_coverage_mismatch")
    installed = index_unique(probe["installed_deb"], "name")
    python_packages = {canonical_package("pypi", name, version)
                       for name, version in probe["installed_pypi"]}
    findings = []
    for identity, group in groups.items():
        fact, package = facts[identity], group["package"]
        native = {entry["native_id"] for entry in group["evidence"].values()}
        require(fact["advisory_id"] in native and fact["package"] == package,
                "vendor_finding_scope_mismatch")
        publisher = packet["vendor_sources"].get(fact["source_key"])
        require(publisher is not None and publisher.get("status") == 200
                and re.fullmatch(r"[a-f0-9]{64}", publisher.get("sha256", "")) is not None,
                "vendor_source_not_verified")
        advisory = fact["advisory_id"]
        context = "component_mapping_and_input_reachability"
        disposition, priority = "vendor_open_component_review", "P2"
        mitigations = []
        if package["ecosystem"] == "deb":
            require(fact["source_key"] == "debian-tracker" and publisher["url"] ==
                    "https://security-tracker.debian.org/tracker/data/json", "unexpected_debian_source")
            actual = installed.get(package["name"])
            require(actual is not None and actual["version"] == package["version"],
                    "installed_package_mismatch")
            require(fact["source_package"] == actual["source"]
                    and fact["source_version"] == actual["source_version"]
                    and fact["release"] == "trixie", "debian_source_mapping_mismatch")
            artifacts = probe["deb_package_artifacts"][package["name"]]
            if fact["release_record"]["status"] != "open":
                disposition = "vendor_state_changed_review_required"
            elif advisory in TEMP:
                context = TEMP[advisory]
                disposition = "conditional_local_or_maintenance_risk"
                if advisory == "TEMP-0517018-A83CE6" and not probe["commands"]["init"]["path"]:
                    disposition = "boot_precondition_absent_in_profile"
                    mitigations.append("image_has_no_init_executable_and_is_not_an_os_installer")
                else:
                    mitigations.extend(["nonroot_readonly_profile", "no_new_privileges_and_no_capabilities"])
            elif artifacts["only_doc_or_lint_metadata"] is True:
                disposition = "source_match_metadata_package"
                mitigations.append("this_binary_package_contains_only_documentation_or_lint_metadata")
                priority = "P3"
            elif actual["source"] == "sqlite3":
                disposition, priority, context = "runtime_database_application_review", "P1", "sql_database_wal_changeset_input"
            elif artifacts["shared_object_count"]:
                disposition, context = "vendor_open_shared_library", "native_library_function_and_input"
            else:
                disposition, context = "vendor_open_tool_or_data_component", "specific_command_or_data_path"
        elif package["ecosystem"] == "binary":
            year, number = advisory.split("-")[1:]
            require(fact["source_key"] == advisory and publisher["url"] ==
                    f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{number[:-3]}xxx/{advisory}.json",
                    "unexpected_python_source")
            require(package == {"ecosystem": "binary", "name": "python", "version": probe["python_version"]},
                    "python_inventory_mismatch")
            require(fact["state"] == "PUBLISHED" and fact["provider"] == "PSF" and
                    fact["provider_org_id"] == "28c92f92-d60d-412d-b760-e73465c3df22", "unexpected_python_publisher")
            affected = python_affected(probe["python_version"], fact["affected"])
            require(advisory in PROFILES, "unreviewed_python_advisory")
            disposition, priority, context = PROFILES[advisory]
            if not affected:
                disposition = "vendor_range_changed_review_required"
            if advisory == "CVE-2026-3479":
                require("disputed" in fact["tags"], "dispute_not_verified")
        elif package["ecosystem"] == "pypi":
            require(advisory in PIP_ADVISORIES and fact["source_key"] == advisory and publisher["url"] ==
                    "https://api.github.com/advisories/" + advisory, "unexpected_pip_source")
            require(("pypi", package["name"], package["version"]) in python_packages
                    and package["name"] == "pip", "pip_inventory_mismatch")
            require(fact["withdrawn_at"] is None and fact["ecosystem"] == "pip"
                    and fact["package_name"] == "pip", "unexpected_pip_advisory")
            require(pip_affected(package["version"], fact["vulnerable_version_range"]),
                    "pip_range_changed_review_required")
            disposition, context = "conditional_build_input_risk", "package_install_or_download_input"
            if advisory == "GHSA-4xh5-x5gv-qwph":
                feature = probe["features"]
                if (feature["tarfile_has_data_filter"] is True and feature["pip_benign_extract_ok"] is True
                        and feature["pip_invoked_data_filter"] is True):
                    disposition = "specific_pip_fallback_precondition_mitigated"
                    mitigations.append("actual_pip_extraction_invokes_pep706_data_filter")
            elif advisory == "GHSA-jp4c-xjxw-mgf9":
                if probe["features"]["pip_install_disables_version_check"] is True:
                    disposition = "specific_pip_self_check_precondition_mitigated"
                    mitigations.append("recorded_install_options_disable_version_check")
        else:
            raise ReviewError("unsupported_ecosystem")
        findings.append({"group_id": identity, "package": package, "advisory_ids": sorted(native),
                         "vendor_fact": fact, "original_flags": group["flags"],
                         "infra_disposition": disposition, "action_priority": priority,
                         "required_exposure_context": context, "observed_mitigations": mitigations,
                         "infra_review": "documented", "exploitability": "not_demonstrated",
                         "upstream_fixed_in_image": False, "waiver_or_suppression": False,
                         "independent_review": "pending"})
    return {"schema": "c03-impact-review-1", "historical_image_id": IMAGE,
            "archive_sha256": ARCHIVE, "scanned_source_commit": review["basis"]["scanned_source_commit"],
            "current_source_reference_commit": packet["current_source_references"]["source_commit"],
            "counts": {"findings": len(findings), "dispositions": dict(sorted(Counter(
                row["infra_disposition"] for row in findings).items())), "priorities": dict(sorted(Counter(
                row["action_priority"] for row in findings).items())), "vendor_coverage": len(facts),
                "confirmed_exploits": 0, "suppressed_findings": 0, "fixed_findings": 0},
            "security_gate_passed": False, "production_approved": False,
            "findings": findings,
            "limits": ["Historical application image only; no new scanner run or current image approval.",
                       "Vendor data is a captured snapshot; urgency/no-dsa never proves non-applicability.",
                       "Runtime controls are those of the isolated probe profile, not every deployment.",
                       "Direct AST references are not data-flow or whole-dependency reachability proof.",
                       "No exploit archive, privilege escalation, external service or live account test.",
                       "No dependencies, detection baseline, application policy or old evidence modified."]}


def pinned(path, expected):
    require(re.fullmatch(r"[a-f0-9]{64}", expected or "") is not None, "invalid_input_pin")
    path = Path(path)
    require(path.stat().st_size <= 32 * 1024 * 1024, "input_too_large")
    data = path.read_bytes()
    require(digest(data) == expected, "input_digest_mismatch")
    return decode(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        packet = pinned(args.input, args.input_sha256)
        require(packet["review_sha256"] == args.review_sha256, "review_binding_mismatch")
        report = assess(packet, pinned(args.review, args.review_sha256))
        report["evidence"] = {"input_sha256": args.input_sha256, "review_sha256": args.review_sha256,
                              "implementation_lf_sha256": hashlib.sha256(Path(__file__).read_bytes().replace(
                                  b"\r\n", b"\n")).hexdigest()}
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        print(json.dumps({"status": "rejected", "code": str(error) if isinstance(error, ReviewError)
                          else "invalid_input", "error_type": type(error).__name__}))
        return 1
    print(json.dumps({"status": "reported", "counts": report["counts"], "security_gate_passed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
