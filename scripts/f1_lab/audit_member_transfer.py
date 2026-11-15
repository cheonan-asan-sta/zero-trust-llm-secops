"""Prospective audit/auth member evaluation in already partly exposed archives.

This is not an entirely source-held-out or original six-domain final test.
Unpaired members remain excluded/unlabeled, never assumed benign.
"""

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from scripts.f1_lab.line_truth import pair_members
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha

POLICY = {
    'schema': 'audit-auth-member-transfer-policy-1',
    'scope': 'prospective member-scope transfer in already partly exposed AIT archives',
    'candidate_chain': ['frozen-v49-models', 'v67-audit-auth-observations', 'v85-apparmor-explicit-noop'],
    'selection': 'all exact mirrored /logs/auth.log and /logs/audit/audit.log pairs; no rotations or basename joins',
    'maximum_pairs': 64, 'maximum_source_rows': 100000,
    'maximum_source_bytes': 67108864, 'maximum_total_rows': 200000,
    'evaluation_unit': 'physical_log_line', 'alert_threshold': 0.95,
    'source_roles': {'wilson':'additional members of previously evaluated source',
                     'wardbeck':'additional members of predeclared calibration source'},
    'entire_archive_previously_unseen': False,
    'original_six_domain_goal_replaced': False, 'goal_qualified': False,
    'independent_human_review': False, 'models_refitted': False,
    'unpaired_members_assumed_benign': False, 'automatic_enforcement_allowed': False,
}


def select_pairs(entries, prior_pairs):
    by_name = {e['archive_name']:e for e in entries}
    require(len(by_name) == len(entries), 'audit_transfer_duplicate_member')
    consumed = {p['provenance'][k] for p in prior_pairs for k in ('raw_member','label_member')}
    selected, excluded = [], []
    for name in sorted(by_name):
        parts = PurePosixPath(name).parts
        if parts.count('gather') != 1:
            continue
        index = parts.index('gather')
        if len(parts) < index+4 or parts[index+2] != 'logs':
            continue
        kind = 'auth' if name.endswith('/logs/auth.log') else 'audit' if name.endswith('/logs/audit/audit.log') else None
        if kind is None:
            continue
        label = PurePosixPath(*parts[:index],'labels',*parts[index+1:]).as_posix()
        if label not in by_name:
            excluded.append({'raw_member':name,'reason':'no exact publisher label pair; not assumed benign'})
            continue
        pair_members(name,label)
        require(name not in consumed and label not in consumed, 'audit_transfer_member_already_selected')
        facts = PurePosixPath(*parts[:index+2],'facts.json').as_posix()
        require(facts in by_name and all(by_name[n]['bounded_read_eligible'] for n in (name,label,facts)),
                'audit_transfer_unbounded_pair')
        require(0 < by_name[name]['bytes'] <= POLICY['maximum_source_bytes']
                and by_name[label]['bytes'] <= POLICY['maximum_source_bytes'], 'audit_transfer_member_bytes')
        selected.append({'raw_member':name,'label_member':label,'facts_member':facts,'kind':kind,
                         'raw_bytes':by_name[name]['bytes'],'label_bytes':by_name[label]['bytes']})
    require(0 < len(selected) <= POLICY['maximum_pairs'] and {p['kind'] for p in selected} == {'auth','audit'},
            'audit_transfer_source_coverage')
    return selected,excluded


class MemberAccessLedger:
    """Append/fsync local provenance; trusted host, no external rollback proof."""
    def __init__(self,path,header):
        self.path = Path(path)
        require(not self.path.is_symlink() and set(header) == {
            'archive_sha256','candidate_freeze_sha256','prior_global_access_sha256',
            'prior_selected_manifest_sha256','selected_members_sha256'}, 'audit_member_ledger_header')
        require(all(isinstance(v,str) and len(v) == 64 and set(v) <= set('0123456789abcdef')
                    for v in header.values()), 'audit_member_ledger_header_pin')
        self.header = header
        if not self.path.exists():
            require(self.path.parent.is_dir(), 'audit_member_ledger_parent')
            with self.path.open('xb') as stream:
                stream.write(canonical({'kind':'header',**header})+b'\n')
                stream.flush()
                os.fsync(stream.fileno())
        self.read()

    def read(self):
        require(self.path.is_file() and not self.path.is_symlink() and self.path.stat().st_size <= 1024**2,
                'audit_member_ledger_file')
        rows = []
        with self.path.open('rb') as stream:
            while raw := stream.readline(MAX_ROW+1):
                require(raw.endswith(b'\n') and len(raw) <= MAX_ROW and len(rows) < 512,
                        'audit_member_ledger_truncated_or_bound')
                rows.append(decode(raw))
        require(rows and rows[0] == {'kind':'header',**self.header}, 'audit_member_ledger_foreign_freeze')
        previous = hashlib.sha256(canonical(rows[0])).hexdigest()
        raw_seen, sealed = False,None
        for n,row in enumerate(rows[1:],1):
            require(type(row) is dict and set(row) == {'index','previous_sha256','phase','member','artifact_sha256','observed_at'}
                    and type(row['index']) is int and row['index'] == n and row['previous_sha256'] == previous
                    and row['phase'] in {'raw','sealed','label'}
                    and isinstance(row['member'],str) and 0 < len(row['member']) <= 4096,
                    'audit_member_ledger_chain')
            if row['phase'] == 'raw':
                require(sealed is None and row['artifact_sha256'] is None, 'audit_member_ledger_phase_order')
                raw_seen = True
            elif row['phase'] == 'sealed':
                require(raw_seen and sealed is None and isinstance(row['artifact_sha256'],str)
                        and len(row['artifact_sha256']) == 64 and set(row['artifact_sha256']) <= set('0123456789abcdef'),
                        'audit_member_ledger_phase_order')
                sealed = row['artifact_sha256']
            else:
                require(sealed is not None and row['artifact_sha256'] == sealed, 'audit_member_ledger_phase_order')
            previous = hashlib.sha256(canonical(row)).hexdigest()
        return rows,previous

    def append(self,phase,member,artifact_sha256=None):
        require(phase in {'raw','sealed','label'} and isinstance(member,str) and 0 < len(member) <= 4096,
                'audit_member_access_event')
        rows,previous = self.read()
        labels = [r for r in rows[1:] if r['phase'] == 'label']
        seals = [r for r in rows[1:] if r['phase'] == 'sealed']
        if phase == 'raw':
            require(not labels and not seals and artifact_sha256 is None, 'audit_member_raw_after_seal')
        elif phase == 'sealed':
            require(not seals and not labels and any(r.get('phase') == 'raw' for r in rows),
                    'audit_member_seal_order')
            require(isinstance(artifact_sha256,str) and len(artifact_sha256) == 64
                    and set(artifact_sha256) <= set('0123456789abcdef'), 'audit_member_seal_pin')
        else:
            require(len(seals) == 1 and artifact_sha256 == seals[0]['artifact_sha256'], 'audit_member_label_before_seal')
        row = {'index':len(rows),'previous_sha256':previous,'phase':phase,'member':member,
               'artifact_sha256':artifact_sha256,'observed_at':datetime.now(UTC).isoformat()}
        with self.path.open('ab') as stream:
            stream.write(canonical(row)+b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        self.read()


def header_for(spec,freeze_sha256):
    return {'archive_sha256':spec['archive_sha256'],'candidate_freeze_sha256':freeze_sha256,
            'prior_global_access_sha256':spec['prior_global_access_sha256'],
            'prior_selected_manifest_sha256':spec['prior_selected_manifest_sha256'],
            'selected_members_sha256':hashlib.sha256(canonical(spec['selected'])).hexdigest()}


def check_prior_access(spec,previous_access):
    require(sha(previous_access) == spec['prior_global_access_sha256'], 'audit_member_original_access_changed')
