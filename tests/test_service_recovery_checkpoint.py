"""Current private checkpoint authentication must precede service admission."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts import service_recovery_store as store
from scripts.ca_recovery_state import TABLES, digest, sealed
from scripts.certificate_controller import LifecycleError


def fixture(tmp_path,monkeypatch):
    key=b'x'*32;cfg={'authority':{'providers':['current']}}
    authority=hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()
    tables={name:[] for name in TABLES};sha=digest(tables)
    state={'sequence':3,'pending':{},'error':None,'checkpoint_sequence':3,'checkpoint_hash':sha,'checkpoint_lsn':'0/A',
        'incarnation':'123456789','authority':authority,'frozen':False,'enabled':['a','b'],'checkpoint':'security.sealed'}
    envelope=sealed({'tables':tables},key,{'sequence':3,'authority':authority,'incarnation':'123456789','lsn':'0/A','sha256':sha})
    for site in ['a','b']:
        root=tmp_path/site;(root/'witness').mkdir(parents=True);(root/'ca').mkdir()
        (root/'witness/state.json').write_text(json.dumps(state),encoding='utf-8')
        (root/'witness/security.sealed').write_text(json.dumps(envelope),encoding='utf-8')
        (root/'witness/security.key').write_bytes(key);(root/'ca/ca.json').write_text(json.dumps(cfg),encoding='utf-8')
    proof={'phase':'idle','epoch':2,'tree_sha256':'current-private-state','database_incarnation':'123456789','plan_hash':None}
    monkeypatch.setattr(store,'validate',lambda *a,**k:copy.deepcopy(proof))
    monkeypatch.setattr(store,'Path',lambda p:tmp_path/str(p).removeprefix('/source').lstrip('/') if str(p).startswith('/source') else Path(p))
    return state,envelope,proof


def contents(root):return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_current_authenticated_checkpoint_is_read_only_and_public(tmp_path,monkeypatch):
    state,_,_=fixture(tmp_path,monkeypatch);before=contents(tmp_path)
    result=store.private_proof({'role':'current'})
    assert result['witness']['checkpoint_hash']==state['checkpoint_hash'] and contents(tmp_path)==before
    assert 'security.key' not in json.dumps(result) and 'ciphertext' not in json.dumps(result)


@pytest.mark.parametrize('fault',['pending','error','sequence','missing_hash','incarnation','hash','lsn','authority','path','key','tag','replica','private_tree'])
def test_uncertain_or_unauthenticated_state_cannot_open_admission(tmp_path,monkeypatch,fault):
    state,envelope,proof=fixture(tmp_path,monkeypatch)
    if fault=='pending':state['pending']={'unacknowledged':{}}
    elif fault=='error':state['error']='unknown_write'
    elif fault=='sequence':state['checkpoint_sequence']=2
    elif fault=='missing_hash':state['checkpoint_hash']=None
    elif fault=='incarnation':state['incarnation']='other'
    elif fault=='hash':state['checkpoint_hash']='0'*64
    elif fault=='lsn':state['checkpoint_lsn']='0/B'
    elif fault=='authority':state['authority']='other'
    elif fault=='path':state['checkpoint']='../private.key'
    elif fault=='key':
        for site in ['a','b']:(tmp_path/site/'witness/security.key').write_bytes(b'y'*32)
    elif fault=='tag':
        envelope['ciphertext']='invalid'
        for site in ['a','b']:(tmp_path/site/'witness/security.sealed').write_text(json.dumps(envelope),encoding='utf-8')
    elif fault=='private_tree':
        def changed(roots,expected):
            value=copy.deepcopy(proof)
            if roots['ca'].parent.name=='b':value['tree_sha256']='other'
            return value
        monkeypatch.setattr(store,'validate',changed)
    for site in ['a','b']:
        value=copy.deepcopy(state)
        if fault=='replica' and site=='b':value['sequence']=4
        (tmp_path/site/'witness/state.json').write_text(json.dumps(value),encoding='utf-8')
    before=contents(tmp_path)
    with pytest.raises(LifecycleError):store.private_proof({'role':'current'})
    assert contents(tmp_path)==before
