"""Partial archive exposure may not be relabeled as a fresh source holdout."""

import json

import pytest

from scripts.f1_lab.audit_member_transfer import POLICY, MemberAccessLedger, select_pairs
from scripts.f1_lab.operation_context import canonical


def entries():
    names = [f'example/gather/host/logs/{suffix}' for suffix in ('auth.log','audit/audit.log')]
    names += [n.replace('/gather/','/labels/') for n in names]
    names += ['example/gather/host/facts.json']
    return [{'archive_name':n,'bounded_read_eligible':True,'bytes':100} for n in names]


def header():
    return {k:'a'*64 for k in ('archive_sha256','candidate_freeze_sha256','prior_global_access_sha256',
                              'prior_selected_manifest_sha256','selected_members_sha256')}


def test_all_exact_audit_and_auth_pairs_selected_without_opening_bodies():
    chosen,excluded = select_pairs(entries(),[])
    assert {p['kind'] for p in chosen} == {'audit','auth'} and len(chosen) == 2
    assert not excluded and POLICY['goal_qualified'] is False
    assert not POLICY['entire_archive_previously_unseen']
    assert POLICY['source_roles']['wardbeck'].endswith('calibration source')


def test_unpaired_member_is_explicitly_excluded_without_normal_label():
    rows = entries()+[{'archive_name':'example/gather/other/logs/auth.log','bounded_read_eligible':True,'bytes':100}]
    chosen,excluded = select_pairs(rows,[])
    assert len(chosen) == 2 and len(excluded) == 1
    assert excluded[0]['reason'] == 'no exact publisher label pair; not assumed benign'


def test_different_host_basename_cannot_supply_a_label():
    rows = [e for e in entries() if not e['archive_name'].endswith('/labels/host/logs/auth.log')]
    rows.append({'archive_name':'example/labels/other/logs/auth.log','bounded_read_eligible':True,'bytes':100})
    with pytest.raises(ValueError,match='audit_transfer_source_coverage'):
        select_pairs(rows,[])


@pytest.mark.parametrize('member_kind',['raw_member','label_member'])
def test_previously_consumed_exact_member_cannot_be_selected_as_unseen(member_kind):
    prior = {'raw_member':'old/gather/host/logs/access.log','label_member':'old/labels/host/logs/access.log'}
    prior[member_kind] = 'example/'+('gather' if member_kind == 'raw_member' else 'labels')+'/host/logs/auth.log'
    with pytest.raises(ValueError,match='audit_transfer_member_already_selected'):
        select_pairs(entries(),[{'provenance':prior}])


@pytest.mark.parametrize('damage',['duplicate','unbounded','oversize','missing_facts','no_audit'])
def test_selection_rejects_ambiguous_unbounded_or_missing_required_metadata(damage):
    rows = entries()
    if damage == 'duplicate':rows += [rows[0]]
    elif damage == 'unbounded':rows[0]['bounded_read_eligible'] = False
    elif damage == 'oversize':rows[0]['bytes'] = 64*1024**2+1
    elif damage == 'missing_facts':rows = [r for r in rows if not r['archive_name'].endswith('facts.json')]
    else:rows = [r for r in rows if not r['archive_name'].endswith('audit/audit.log')]
    with pytest.raises(ValueError,match='audit_transfer_'):
        select_pairs(rows,[])


def test_access_ledger_seals_before_label_and_preserves_original_exposure_header(tmp_path):
    p = tmp_path/'members.jsonl'
    book = MemberAccessLedger(p,header())
    book.append('raw','example/gather/host/logs/auth.log')
    book.append('sealed','prediction-manifest.json','b'*64)
    book.append('label','example/labels/host/logs/auth.log','b'*64)
    rows,_ = MemberAccessLedger(p,header()).read()
    assert rows[0] == {'kind':'header',**header()}
    assert [r['phase'] for r in rows[1:]] == ['raw','sealed','label']


@pytest.mark.parametrize('violation',['label_first','seal_first','raw_after_seal','double_seal','wrong_seal','foreign_candidate'])
def test_access_ledger_rejects_false_prospective_or_unsealed_label_access(violation,tmp_path):
    p = tmp_path/'members.jsonl'
    book = MemberAccessLedger(p,header())
    with pytest.raises(ValueError,match='audit_member_'):
        if violation == 'label_first':book.append('label','label','b'*64)
        elif violation == 'seal_first':book.append('sealed','manifest','b'*64)
        elif violation == 'foreign_candidate':
            MemberAccessLedger(p,{**header(),'candidate_freeze_sha256':'c'*64})
        else:
            book.append('raw','raw')
            book.append('sealed','manifest','b'*64)
            if violation == 'raw_after_seal':book.append('raw','other')
            elif violation == 'double_seal':book.append('sealed','manifest','b'*64)
            else:book.append('label','label','c'*64)


@pytest.mark.parametrize('damage',['partial','modified','missing_middle','unknown_phase','duplicate_index'])
def test_partial_or_modified_ledger_is_never_reset_or_reused(damage,tmp_path):
    p = tmp_path/'members.jsonl'
    book = MemberAccessLedger(p,header())
    book.append('raw','raw')
    book.append('sealed','manifest','b'*64)
    old = p.read_bytes()
    if damage == 'partial':p.write_bytes(old[:-1])
    else:
        rows = [json.loads(raw) for raw in old.splitlines()]
        if damage == 'modified':rows[1]['member'] = 'other'
        elif damage == 'missing_middle':rows.pop(1)
        elif damage == 'unknown_phase':rows[1]['phase'] = 'normal'
        else:rows[2]['index'] = 1
        p.write_bytes(b''.join(canonical(r)+b'\n' for r in rows))
    damaged = p.read_bytes()
    with pytest.raises(ValueError,match='audit_member_'):
        MemberAccessLedger(p,header())
    assert p.read_bytes() == damaged
