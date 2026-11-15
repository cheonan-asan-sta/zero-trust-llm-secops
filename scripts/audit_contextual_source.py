"""Audit a pinned contextual CSV without exposing quarantined event bodies or fitting models."""

import argparse
import csv
import hashlib
import io
import json
import sqlite3
from collections import Counter
from pathlib import Path

from scripts.f1_lab.contextual_links import Components, links, truth
from scripts.f1_lab.line_truth import anchor
from scripts.f1_lab.native_jsonl import decode, require

MAX_BYTES = 1024**3
MAX_RECORDS = 500000
CLAIM_KEYS = {'mfa', 'multifactorauthenticated', 'amr', 'identityactive', 'isactive', 'accountactive',
              'devicemanaged', 'ismanaged', 'securityposture', 'devicehealthy', 'compliancestatus',
              'requiredrole', 'requiredroles', 'businessapproval', 'policyexception'}


def fingerprint(stream):
    stream.seek(0)
    sha, total = hashlib.sha256(), 0
    while body := stream.read(1024**2):
        total += len(body)
        require(total <= MAX_BYTES, 'context_csv_byte_bound')
        sha.update(body)
    return sha.hexdigest()


def declared_claim_fields(value, prefix='', depth=0):
    if depth > 4 or not isinstance(value, dict):
        return []
    result = []
    for key, child in value.items():
        # Untrusted request JSON is not a server/IdP assertion. Derived risk
        # flags and labels must not count as evidence for their own truth.
        if key in {'JSON', 'Suspicious', 'suspicious', 'SuspiciousDescription', 'Description', 'Fingerprint', 'RequestMetadata'}:
            continue
        name = prefix+'.'+key if prefix else key
        normalized = ''.join(c for c in key.casefold() if c.isalnum())
        if normalized in CLAIM_KEYS:
            result.append((name, type(child).__name__))
        result.extend(declared_claim_fields(child, name, depth+1))
    return result


def audit(path, expected_sha256, output, *, development_probe=128):
    path, output = Path(path), Path(output)
    anchor(expected_sha256)
    require(type(development_probe) is int and 0 <= development_probe <= 1000, 'context_probe_bound')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'context_csv_file')
    require(not output.exists() and not output.is_symlink(), 'fresh_context_audit')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-contextual-metadata-audit-1', 'completed': False, 'csv_sha256': expected_sha256,
              'mechanical_metadata_audit': True, 'later_bodies_displayed': 0, 'classifier_fitted': False,
              'development_probe': development_probe, 'final_partition_certified': False,
              'original_six_domain_goal_replaced': False, 'goal_qualified': False,
              'field_presence_is_authenticated_authority': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    components = {name: Components() for name in ('identity', 'identity_profile', 'identity_profile_template')}
    counters, sourcetypes, shapes, claim_fields = Counter(), Counter(), Counter(), Counter()
    database = sqlite3.connect(output/'metadata.sqlite3')
    database.execute('CREATE TABLE cases (ordinal INTEGER PRIMARY KEY, truth INTEGER, is_probe INTEGER, identity_links INTEGER, has_profile INTEGER, has_template INTEGER)')
    try:
        with path.open('rb') as binary:
            require(fingerprint(binary) == expected_sha256, 'context_csv_hash')
            binary.seek(0)
            csv.field_size_limit(2*1024**2)
            text = io.TextIOWrapper(binary, encoding='utf-8-sig', newline='')
            try:
                reader = csv.reader(text, strict=True)
                require(next(reader) == ['time', 'host', 'source', 'sourcetype', 'message'], 'context_csv_header')
                with database:
                    for ordinal, row in enumerate(reader, 1):
                        require(ordinal <= MAX_RECORDS and len(row) == 5
                                and sum(len(part) for part in row) <= 4*1024**2, 'context_csv_record_bound')
                        counters['records'] += 1
                        sourcetypes[row[3]] += 1
                        value, label = None, None
                        linkage = {'identity': [], 'profile': None, 'request_template': None, 'template_error': False}
                        try:
                            value = decode(row[4].encode('utf-8'))
                        except (ValueError, RecursionError):
                            counters['nonjson_or_invalid_json'] += 1
                        if isinstance(value, dict):
                            counters['json_objects'] += 1
                            label = truth(value)
                            linkage = links(value)
                            counters['template_parse_errors'] += linkage['template_error']
                            shape = tuple(sorted(value))
                            require(len(shapes) < 10000 or shape in shapes, 'context_schema_population_bound')
                            shapes[shape] += 1
                            claim_fields.update(declared_claim_fields(value))
                            for field in ('UserContext', 'ClientCertificate', 'ResourceContext', 'SessionId', 'Fingerprint'):
                                counters['present_'+field] += value.get(field) is not None
                        elif value is not None:
                            counters['nonobject_json'] += 1
                        counters['truth_unknown' if label is None else 'truth_attack' if label else 'truth_normal'] += 1
                        keys = set(linkage['identity'])
                        probe = ordinal <= development_probe
                        components['identity'].add(keys, development_probe=probe)
                        if linkage['profile']:
                            keys.add(linkage['profile'])
                        components['identity_profile'].add(keys, development_probe=probe)
                        if linkage['request_template']:
                            keys.add(linkage['request_template'])
                        components['identity_profile_template'].add(keys, development_probe=probe)
                        database.execute('INSERT INTO cases VALUES (?,?,?,?,?,?)',
                                         (ordinal, label, int(probe), len(linkage['identity']),
                                          int(bool(linkage['profile'])), int(bool(linkage['request_template']))))
            finally:
                text.detach()
            require(fingerprint(binary) == expected_sha256, 'context_csv_changed')
        report.update(counts=dict(counters), sourcetypes=dict(sourcetypes),
                      declared_claim_fields=[{'path': path, 'type': kind, 'records': count}
                                             for (path, kind), count in claim_fields.most_common()],
                      top_level_shapes=[{'keys': list(keys), 'records': count} for keys, count in shapes.most_common()],
                      linkage={name: group.summary() for name, group in components.items()}, completed=True)
    except (OSError, ValueError, TypeError, KeyError, csv.Error) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        database.close()
        report['metadata_db_sha256'] = hashlib.sha256((output/'metadata.sqlite3').read_bytes()).hexdigest()
        (output/'audit.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.csv, args.expected_sha256, args.output)
    print(json.dumps({key: report[key] for key in ('completed', 'counts', 'declared_claim_fields', 'linkage', 'goal_qualified')}))


if __name__ == '__main__':
    main()
