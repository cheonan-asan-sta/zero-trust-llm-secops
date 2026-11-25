"""Diagnose publisher-label sensitivity without changing labels or alerts."""

import argparse
import json
from collections import Counter
from pathlib import Path
from urllib.parse import unquote
from zipfile import ZipFile

import yaml

from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_apache_transfer import LABEL_MEMBER, SOURCE_SHA
from scripts.evaluate_public_web_target_crs import apache_logs


def normalize_decoded(text):
    return unquote(text).casefold()


MATCHERS = {
    "exact": lambda value: value,
    "casefold": str.casefold,
    "percent_decoded_casefold": normalize_decoded,
}


def analyze(source, reference, priority, baseline_sha, priority_sha):
    seal_path = priority / "seal.json"
    priorities = priority / "priorities.jsonl"
    seal = read(seal_path)
    if (
        fingerprint(seal_path) != priority_sha or seal["kind"] != "apache"
        or seal["baseline_seal"] != baseline_sha
        or fingerprint(priorities) != seal["priorities_sha256"]
    ):
        raise ValueError("priority evidence does not match the expected seal")
    if fingerprint(source) != SOURCE_SHA:
        raise ValueError("Apache source fingerprint mismatch")
    with ZipFile(source) as archive:
        publisher = archive.read(LABEL_MEMBER)
    rules = [row["filter"] for row in yaml.safe_load(publisher)]
    if not rules or not all(
        isinstance(rule, list) and rule and all(isinstance(term, str) and term for term in rule)
        for rule in rules
    ):
        raise ValueError("publisher truth filters missing")
    prepared = {
        name: tuple(tuple(normalize(term) for term in rule) for rule in rules)
        for name, normalize in MATCHERS.items()
    }
    totals = {name: Counter() for name in MATCHERS}
    population = {name: Counter() for name in MATCHERS}
    count = 0
    with priorities.open("rb") as stream:
        for count, ((line, earlier), observation) in enumerate(
            zip(apache_logs(source, reference, baseline_sha), map(json.loads, stream), strict=True), 1
        ):
            if observation["ordinal"] != count:
                raise ValueError("priority and source row order differ")
            matches = {}
            for name, normalize in MATCHERS.items():
                text = normalize(line)
                matches[name] = any(all(term in text for term in rule) for rule in prepared[name])
            for name, matched in matches.items():
                category = f"exact_{int(matches['exact'])}_alternative_{int(matched)}"
                population[name][category] += 1
                if earlier is False and observation["priority"] is True:
                    totals[name][category] += 1
    if count != seal["observations"] or fingerprint(priorities) != seal["priorities_sha256"]:
        raise ValueError("priority population changed")
    return {
        "baseline_seal": baseline_sha,
        "priority_seal": priority_sha,
        "sources": {"rows": count, "source_sha256": fingerprint(source)},
        "full_population": {name: dict(values) for name, values in population.items()},
        "new_priority_only": {name: dict(values) for name, values in totals.items()},
        "official_labels_changed": False,
        "purpose": "normalization sensitivity only; not relabeling or performance credit",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("source", "reference", "priority", "output"):
        parser.add_argument(field, type=Path)
    parser.add_argument("baseline_sha")
    parser.add_argument("priority_sha")
    args = parser.parse_args()
    report = analyze(args.source, args.reference, args.priority, args.baseline_sha, args.priority_sha)
    write(args.output, report)


if __name__ == "__main__":
    main()
