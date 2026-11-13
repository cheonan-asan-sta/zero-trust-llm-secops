"""Metadata-only physical rotation selection. Never join files or infer missing truth."""

import re
from pathlib import PurePosixPath

from scripts.f1_lab.line_truth import pair_members
from scripts.f1_lab.native_jsonl import require


def select(entries):
    names = [row['archive_name'] for row in entries]
    require(len(names) == len(set(names)), 'rotation_duplicate_member')
    indexed = dict(zip(names, entries, strict=True))
    selected, excluded = [], []
    for name in sorted(indexed):
        parts = PurePosixPath(name).parts
        if parts.count('gather') != 1:
            continue
        index = parts.index('gather')
        if len(parts) < index+4 or parts[index+2] != 'logs':
            continue
        matched = re.fullmatch(r'(.+)-(access|error)\.log(?:\.([1-9][0-9]{0,3}))?', parts[-1])
        if 'apache2' != parts[-2] or matched is None:
            continue
        label = PurePosixPath(*parts[:index], 'labels', *parts[index+1:]).as_posix()
        if label not in indexed:
            excluded.append({'member': name, 'reason': 'no_exact_mirrored_labels; truth unknown'})
            continue
        pair_members(name, label)
        require(indexed[name]['bounded_read_eligible'] and indexed[label]['bounded_read_eligible'],
                'rotation_ineligible_pair')
        facts = PurePosixPath(*parts[:index+2], 'facts.json').as_posix()
        require(facts in indexed and indexed[facts]['bounded_read_eligible'], 'rotation_missing_host_metadata')
        selected.append({'raw_member': name, 'label_member': label, 'facts_member': facts,
            'kind': matched[2], 'rotation': int(matched[3]) if matched[3] else 0,
            'context_scope': 'one physical file only; no cross-file history or deduplication'})
    require(0 < len(selected) <= 64, 'rotation_pair_population')
    return selected, excluded
