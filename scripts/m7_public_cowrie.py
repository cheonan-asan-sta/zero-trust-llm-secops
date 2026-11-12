"""Read the pinned Cowrie public lab capture and its separately published annotations."""

import json
import re
from collections import Counter, defaultdict
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from scripts.evaluate_m6 import canonical, digest, unique_fields

REPOSITORY = "https://github.com/danirzkpinho/cowrie-honeypot-llm-sentinel"
COMMIT = "441729542d953f920d4cd0ec7139ee655a5a3154"
ARCHIVE_SHA256 = "5da1df26decc9077ee6afd0b983b990bf64a4cb9798ebdaca871aed7217b88fc"
PREFIX = f"cowrie-honeypot-llm-sentinel-{COMMIT}/captures/"
ROLE_LABELS = {"benign": "normal", "malicious": "threat"}
NOTE = re.compile(r"round (\d+), [\w-]+ running ([a-z_]+) \(variant [\w-]+\)")
ANNOTATION_FIELDS = {"annotator", "ground_truth", "label", "labels", "expected_label"}
FACT_COUNTS = {
    "login_success_count": "cowrie.login.success",
    "login_failure_count": "cowrie.login.failed",
    "interactive_command_count": "cowrie.command.input",
    "file_download_count": "cowrie.session.file_download",
}


def _raw_observations(archive, round_number, seen_hashes, session_groups):
    """Group all recorded events by origin within the round, before reading labels."""
    by_origin = defaultdict(list)
    event_path = PREFIX + f"r{round_number:02}_cowrie.json"
    for line in archive.read(event_path).splitlines():
        row = json.loads(line, object_pairs_hook=unique_fields)
        required = ("session", "src_ip", "timestamp", "eventid")
        if (not isinstance(row, dict) or ANNOTATION_FIELDS & row.keys()
                or not all(isinstance(row.get(key), str) and row[key] for key in required)):
            raise ValueError("cowrie_invalid_raw_event")
        fingerprint = digest(canonical(row))
        if fingerprint in seen_hashes:
            raise ValueError("cowrie_duplicate_event")
        seen_hashes.add(fingerprint)
        origin = row["src_ip"]
        group = (round_number, origin)
        if session_groups.setdefault(row["session"], group) != group:
            raise ValueError("cowrie_session_crosses_groups")
        by_origin[origin].append((row, fingerprint))

    observations = {}
    for origin, entries in by_origin.items():
        counts = Counter(row["eventid"] for row, _ in entries)
        timestamps = [row["timestamp"] for row, _ in entries]
        observations[origin] = {
            "source": "cowrie",
            "original_group_id": digest(canonical(["cowrie", COMMIT, round_number, origin])),
            "event_hashes": sorted(fingerprint for _, fingerprint in entries),
            "observation": {
                "event_count": len(entries),
                "ssh_session_count": len({row["session"] for row, _ in entries}),
                "first_timestamp": min(timestamps),
                "last_timestamp": max(timestamps),
                **{field: counts[event_id] for field, event_id in FACT_COUNTS.items()},
            },
        }
    return observations


def _round_labels(archive, round_number):
    label_path = PREFIX + f"labels_r{round_number:02}.json"
    record = json.loads(archive.read(label_path), object_pairs_hook=unique_fields)
    if set(record) != {"by_ip"} or not isinstance(record["by_ip"], dict):
        raise ValueError("cowrie_invalid_annotation")
    labels = {}
    for origin, annotation in record["by_ip"].items():
        note = NOTE.fullmatch(annotation["notes"])
        if not note or int(note[1]) != round_number or annotation["label"] not in ROLE_LABELS:
            raise ValueError("cowrie_invalid_role_or_round")
        labels[origin] = (ROLE_LABELS[annotation["label"]], note[2])
    return labels


def load_cowrie(path: Path):
    """Return source observations plus attribution, using one case per round and origin.

    The authors reset the lab honeypot for each round and prescribe one role for
    each source within it. Connections within one scripted attempt stay together.
    Unannotated traffic stays unknown. Only explicit benign controls count as normal.
    """
    archive_bytes = path.read_bytes()
    if digest(archive_bytes) != ARCHIVE_SHA256:
        raise ValueError("cowrie_archive_sha256_mismatch")
    cases, seen_hashes, session_groups = [], set(), {}
    with ZipFile(BytesIO(archive_bytes)) as archive:
        for round_number in range(1, 25):
            observed = _raw_observations(archive, round_number, seen_hashes, session_groups)
            labels = _round_labels(archive, round_number)
            if labels.keys() - observed.keys():
                raise ValueError("cowrie_annotated_origin_without_events")
            for origin, case in observed.items():
                expected, family = labels.get(origin, ("unknown", None))
                cases.append(case | {
                    "expected_label": expected,
                    "families": [f"cowrie:{family}"] if family else [],
                })
    counts = Counter(case["expected_label"] for case in cases)
    if counts["normal"] != 28 or counts["threat"] != 24:
        raise ValueError("cowrie_publisher_count_mismatch")
    metadata = {
        "publication": REPOSITORY,
        "commit": COMMIT,
        "archive_sha256": ARCHIVE_SHA256,
        "archive_url": f"https://codeload.github.com/danirzkpinho/cowrie-honeypot-llm-sentinel/zip/{COMMIT}",
        "license": "CC BY-NC 4.0",
        "license_url": f"{REPOSITORY}/blob/{COMMIT}/LICENSE",
        "attribution": "Rúben Oliveira, Tiago Gomes, Daniel Pinho, and Fernando Almeida (2026)",
        "reference": (
            "An Integrated Honeypot and LLM-Based Framework for Near Real-Time "
            "Detection and Behavioral Analysis of Malicious Activities"
        ),
        "ground_truth_description": f"{REPOSITORY}/blob/{COMMIT}/scenarios/README.md#the-evaluation-unit",
        "capture": "Cowrie telemetry from experiments in an isolated lab honeypot",
        "unit": "source within round, preserving all child SSH connections",
        "rounds": 24,
        "raw_events": len(seen_hashes),
        "ssh_sessions": len(session_groups),
        "reference_counts": dict(counts),
        "threat_families": dict(Counter(
            family for case in cases if case["expected_label"] == "threat"
            for family in case["families"]
        )),
        "changes": "Grouped observed events and retained counts without identifiers or raw strings",
    }
    return sorted(cases, key=lambda case: case["original_group_id"]), metadata
