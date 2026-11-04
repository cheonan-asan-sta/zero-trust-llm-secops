"""Network-none private validation and public service-recovery journal I/O."""

import hashlib
import json
import sys
from pathlib import Path

from scripts import executor_transition as op
from scripts.certificate_controller import LifecycleError
from scripts.control_store import COMPONENTS, validate


def private_proof(expected):
    proofs=[validate({k:Path('/source')/s/k for k in COMPONENTS},expected) for s in ['a','b']]
    if proofs[0]!=proofs[1]:raise LifecycleError('services_private_replicas_diverged')
    states=[json.loads((Path('/source')/s/'witness/state.json').read_bytes()) for s in ['a','b']]
    if states[0]!=states[1]:raise LifecycleError('services_witness_replicas_diverged')
    s=states[0]
    if (s['pending'] or s['error'] or s['checkpoint_sequence']!=s['sequence'] or not s['checkpoint_hash']
            or s['incarnation']!=proofs[0]['database_incarnation']):
        raise LifecycleError('services_security_checkpoint_uncertain')
    from scripts.ca_recovery_state import digest, opened, validate_rows
    witness=Path('/source/a/witness');name=s['checkpoint']
    if not isinstance(name,str) or Path(name).name!=name:raise LifecycleError('services_checkpoint_path')
    envelope=json.loads((witness/name).read_bytes());body=opened(envelope,(witness/'security.key').read_bytes());m=envelope['manifest']
    validate_rows(body['tables'])
    cfg=json.loads(Path('/source/a/ca/ca.json').read_bytes())
    if (any(m[k]!=s[k] for k in ['sequence','authority','incarnation']) or m['sha256']!=s['checkpoint_hash']
            or digest(body['tables'])!=s['checkpoint_hash'] or m['lsn']!=s['checkpoint_lsn']
            or hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()!=s['authority']):
        raise LifecycleError('services_authenticated_checkpoint_mismatch')
    return {**proofs[0],'witness':{k:s[k] for k in ['sequence','checkpoint_sequence','checkpoint_hash','checkpoint_lsn','authority','incarnation','frozen','enabled']}}


def read_record(path):
    try:
        if path.is_symlink() or path.stat().st_size>4*1024**2:raise ValueError
        value=json.loads(path.read_bytes());checksum=value.pop('sha256')
        if checksum!=op.digest(value):raise ValueError
        return value
    except (OSError,ValueError,KeyError,TypeError):raise LifecycleError('services_journal_invalid') from None


def write_record(path,value):op.write_path(path,{**value,'sha256':op.digest(value)})


def main():
    req=json.load(sys.stdin)
    if req['operation']=='private-proof':result=private_proof(req['expected'])
    else:
        path=Path('/data/services.json')
        if req['operation']=='initialize':
            if path.exists():raise LifecycleError('services_journal_already_exists')
            write_record(path,req['value']);result={'initialized':True}
        elif req['operation']=='read':result=read_record(path)
        elif req['operation']=='bind':
            value=read_record(path)
            if value['actor'] is not None and value['phase']!='complete' and value['actor']!=req['actor']:
                raise LifecycleError('services_actor_identity_changed')
            value['actor']=req['actor'];write_record(path,value);result={'bound':True}
        else:raise LifecycleError('services_journal_operation')
    print(json.dumps(result))


if __name__=='__main__':main()
