"""Frozen source intake: exact mirrored pairs, raw first, labels only after prediction seal."""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from scripts.f1_lab.bounded_zip import copy_member, inspect
from scripts.f1_lab.line_truth import annotations, pair_members
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import check_freeze, sha


def select_pairs(entries):
    by_name = {row['archive_name']: row for row in entries}
    pairs, excluded = [], []
    for name in sorted(by_name):
        parts = PurePosixPath(name).parts
        if parts.count('gather') != 1:
            continue
        index = parts.index('gather')
        if len(parts) < index+4 or parts[index+2] != 'logs':
            continue
        kind = ('vpn' if name.endswith('/openvpn.log') else 'access' if
                re.search(r'/apache2/[^/]+-access\.log$', name) else 'error' if
                re.search(r'/apache2/[^/]+-error\.log$', name) else None)
        if kind is None:
            continue
        label = PurePosixPath(*parts[:index], 'labels', *parts[index+1:]).as_posix()
        if label not in by_name:
            excluded.append({'member': name, 'reason': 'no_exact_publisher_label_pair; never inferred normal'})
            continue
        pair_members(name, label)
        require(by_name[name]['bounded_read_eligible'] and by_name[label]['bounded_read_eligible'],
                'transfer_pair_not_bounded')
        facts = PurePosixPath(*parts[:index+2], 'facts.json').as_posix()
        require(facts in by_name and by_name[facts]['bounded_read_eligible'], 'transfer_timezone_metadata_missing')
        pairs.append({'raw_member': name, 'label_member': label, 'facts_member': facts, 'kind': kind})
    require(0 < len(pairs) <= 64, 'transfer_pair_population')
    return pairs, excluded


def timezone(value):
    facts = value.get('ansible_facts', value)
    clock = facts.get('date_time', facts.get('ansible_date_time', {}))
    require(clock.get('tz') == 'UTC' and clock.get('tz_offset') == '+0000', 'transfer_timezone_not_verified_UTC')
    return 'UTC'


def access(archive, freeze_hash, phase):
    path = Path(archive).parent/'evaluation-access.json'
    state = decode(path.read_bytes()) if path.exists() else {
        'candidate_freeze_sha256': freeze_hash, 'raw_bodies_opened': 0, 'label_bodies_opened': 0,
        'first_access_utc': datetime.now(UTC).isoformat()}
    require(state['candidate_freeze_sha256'] == freeze_hash, 'transfer_source_already_exposed_to_other_candidate')
    if phase == 'raw':
        require(state['label_bodies_opened'] == 0, 'transfer_labels_already_exposed')
    state[phase+'_bodies_opened'] += 1
    path.write_bytes(canonical(state)+b'\n')


def prepare(root, archive, freeze_path, freeze_hash, output, *, freeze_checker=None, pair_selector=None):
    checker = check_freeze if freeze_checker is None else freeze_checker
    selector = select_pairs if pair_selector is None else pair_selector
    value = checker(root, freeze_path, freeze_hash)
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_raw_directory')
    inventory = inspect(archive, value['archive_sha256'])
    pairs, excluded = selector(inventory['entries'])
    output.mkdir(parents=True)
    report = {'schema': 'f1-frozen-transfer-raw-intake-1', 'completed': False,
        'scope': 'one-shot source-held-out Apache/OpenVPN transfer only',
        'candidate_freeze_sha256': freeze_hash, 'archive_sha256': value['archive_sha256'],
        'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'bounds_source': value['metadata_source'], 'pairs': [], 'excluded_unpaired': excluded,
        'label_bodies_opened': 0, 'labels_reviewed_by_independent_human': False,
        'original_six_domain_goal_qualified': False}
    hosts, total = {}, 0
    try:
        for index, pair in enumerate(pairs):
            facts_member = pair['facts_member']
            if facts_member not in hosts:
                path = output/f'host-{len(hosts)}.metadata'
                copied = copy_member(archive, value['archive_sha256'], facts_member, path, maximum_bytes=4*1024**2)
                hosts[facts_member] = {'sha256': copied['sha256'], 'timezone': timezone(decode(path.read_bytes()))}
            raw_path = output/f'pair-{index}-raw.source'
            access(archive, freeze_hash, 'raw')
            copied = copy_member(archive, value['archive_sha256'], pair['raw_member'], raw_path,
                                 maximum_bytes=512*1024**2 if pair['kind'] == 'access' else 64*1024**2)
            rows = 0
            with raw_path.open('rb') as stream:
                while raw := stream.readline(MAX_ROW+1):
                    rows += 1
                    require(len(raw) <= MAX_ROW and rows <= (2000000 if pair['kind'] == 'access' else 100000),
                            'transfer_intake_row_bound')
            require(rows > 0, 'transfer_empty_raw_source')
            total += rows
            require(total <= value['maximum_total_rows'], 'transfer_intake_population_bound')
            provenance = {**pair, 'raw_sha256': copied['sha256'], 'archive_sha256': value['archive_sha256'],
                'simulation_start': value['simulation_start'], 'simulation_end': value['simulation_end'],
                'source_timezone': 'UTC', 'label_body_opened': False,
                'publisher_trimmed_pair': True, 'timezone_metadata': hosts[facts_member]}
            report['pairs'].append({'pair_id': sha(raw_path), 'raw_rows': rows, 'provenance': provenance})
        checker(root, freeze_path, freeze_hash)
        require(len({p['provenance']['raw_sha256'] for p in report['pairs']}) == len(report['pairs']),
                'transfer_duplicate_physical_source')
        report.update(completed=True, population=total, timezone_metadata=hosts)
    finally:
        (output/'audit.json').write_bytes(canonical(report)+b'\n')
    return report


def truth_after_seal(root, archive, freeze_path, freeze_hash, raw_directory,
                     prediction_manifest, manifest_hash, output, *, freeze_checker=None):
    checker = check_freeze if freeze_checker is None else freeze_checker
    value = checker(root, freeze_path, freeze_hash)
    require(sha(prediction_manifest) == manifest_hash, 'transfer_prediction_seal_hash')
    sealed = decode(Path(prediction_manifest).read_bytes())
    require(sealed['phase'] == 'predictions_sealed' and sealed['candidate_freeze_sha256'] == freeze_hash,
            'transfer_predictions_not_sealed')
    prediction = Path(prediction_manifest).parent/'predictions.jsonl'
    require(sha(prediction) == sealed['predictions_sha256'], 'transfer_predictions_changed_before_labels')
    audit_path = Path(raw_directory)/'audit.json'
    require(sha(audit_path) == sealed['raw_manifest_sha256'], 'transfer_raw_manifest_changed')
    audit = decode(audit_path.read_bytes())
    require(audit['completed'] and audit['candidate_freeze_sha256'] == freeze_hash
            and audit['archive_sha256'] == value['archive_sha256'], 'transfer_truth_source_binding')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_truth')
    output.mkdir(parents=True)
    fingerprints = []
    with (output/'truth.jsonl').open('xb') as target:
        for index, pair in enumerate(audit['pairs']):
            provenance = pair['provenance']
            pair_members(provenance['raw_member'], provenance['label_member'])
            access(archive, freeze_hash, 'label')
            label_path = output/f'pair-{index}-labels.source'
            copied = copy_member(archive, value['archive_sha256'], provenance['label_member'], label_path)
            labels, _ = annotations(label_path, copied['sha256'])
            require(not labels or max(labels) <= pair['raw_rows'], 'transfer_labels_outside_population')
            for ordinal in range(1, pair['raw_rows']+1):
                case = hashlib.sha256((provenance['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                target.write(canonical({'case_id': case, 'malicious': ordinal in labels,
                                        'attack_labels': labels.get(ordinal, ())})+b'\n')
            fingerprints.append(copied)
    require(sha(prediction) == sealed['predictions_sha256'], 'transfer_predictions_changed_during_labels')
    return {'truth_sha256': sha(output/'truth.jsonl'), 'label_sources': fingerprints,
            'label_basis': 'publisher exact mirrored, trimmed line labels; not independent human adjudication'}
