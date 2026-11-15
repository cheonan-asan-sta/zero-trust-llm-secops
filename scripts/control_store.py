"""Network-none management storage jobs; only public receipts leave the job."""

import hashlib
import json
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts.authority_custodian import (
    load_key,
    public_jwk,
    unseal,
    verify_plan,
    verify_private_bundle,
)
from scripts.certificate_controller import LifecycleError, atomic, replace_file, save
from scripts.control_mirror import durable_parent, guard

COMPONENTS = ('ca', 'vault', 'leaf', 'renewal', 'witness', 'backups', 'backup_key', 'reader', 'control')
PROMOTION_PHASES = {'idle', 'prepared'}


def files(directory):
    result = {}
    for p in sorted(directory.rglob('*')):
        if directory.name == 'ca' and p.relative_to(directory).parts[0] == 'db':
            continue  # Unused bootstrap Badger files; authoritative CA DB is PostgreSQL.
        if p.is_symlink():
            raise LifecycleError('control_storage_symlink')
        if p.is_file() and not p.name.endswith(('.lock', '.new')):
            if p.stat().st_size > 128 * 1024**2:
                raise LifecycleError('control_storage_limit')
            result[str(p.relative_to(directory))] = p
    return result


def tree_digest(roots):
    hashes = {label:{name:hashlib.sha256(p.read_bytes()).hexdigest() for name,p in files(root).items()}
              for label,root in roots.items()}
    raw = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def validate(roots, expected):
    if json.loads((roots['control']/'role.json').read_bytes()) != expected:
        raise LifecycleError('control_candidate_role_mismatch')
    control = json.loads((roots['control']/'coordinator.json').read_bytes())
    if control['phase'] not in PROMOTION_PHASES:
        raise LifecycleError('control_unproven_transition_phase')
    operation = json.loads((roots['control']/'operation.json').read_bytes())
    activity_path = roots['leaf']/'management-activity.json'
    if operation['busy'] or (activity_path.exists() and json.loads(activity_path.read_bytes())['busy']):
        raise LifecycleError('control_unfinished_operation')
    state = json.loads((roots['leaf']/'state.json').read_bytes())
    if state['transaction']:
        raise LifecycleError('control_leaf_publication_pending')
    vault = roots['vault']
    vs = json.loads((vault/'state.json').read_bytes())
    bundle = unseal((vault/vs['bundle']).read_bytes(), (vault/'password').read_bytes())
    ca = roots['ca']; cfg = json.loads((ca/'ca.json').read_bytes())
    issuer = x509.load_pem_x509_certificate((ca/Path(cfg['crt']).name).read_bytes())
    issuer_key = serialization.load_pem_private_key((ca/Path(cfg['key']).name).read_bytes(), password=(ca/'password.txt').read_bytes())
    if (vs['generation'] != control['epoch'] or bundle['root'] != control['root']
            or public_jwk(issuer.public_key()) != public_jwk(issuer_key.public_key())
            or public_jwk(issuer.public_key()) != public_jwk(load_key(bundle['issuer_key']).public_key())
            or cfg['authority']['provisioners'] != bundle['providers']):
        raise LifecycleError('control_authority_state_mismatch')
    if control['phase'] == 'prepared':
        plan = control['plan']
        verify_plan(plan, control['root'], epoch=control['epoch']+1, previous=control['manifest_hash'])
        candidate = unseal((vault/f"authority-g{plan['epoch']}.sealed").read_bytes(), (vault/'password').read_bytes())
        verify_private_bundle(plan, candidate)
    return {'phase':control['phase'], 'epoch':control['epoch'], 'tree_sha256':tree_digest(roots),
            'database_incarnation':json.loads((roots['witness']/'state.json').read_bytes())['incarnation'],
            'plan_hash':control.get('plan') and hashlib.sha256(json.dumps(control['plan'],sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def copy_replica(sources, targets, *, expected=None):
    source_digest = tree_digest(sources)
    if expected is not None and source_digest != expected:
        raise LifecycleError('control_replica_source_changed')
    for n, source in sources.items():
        target = targets[n]
        known = files(source); existing = files(target)
        if expected is None and any(target.iterdir()):
            raise LifecycleError('control_target_not_empty')
        for name,p in existing.items():
            if name not in known or p.read_bytes() != known[name].read_bytes():
                raise LifecycleError('control_replica_partial_conflict')
        for name,p in known.items():
            dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            replace_file(dest,p.read_bytes());durable_parent(dest)
    if tree_digest(targets) != source_digest:
        raise LifecycleError('control_replica_copy_mismatch')
    return {'copied':True,'tree_sha256':source_digest}


def dispatch(req):
    op = req['operation']
    if op in {'copy','copy_resume'}:
        if op == 'copy_resume' and not isinstance(req.get('expected'),str):
            raise LifecycleError('control_replica_expected_digest')
        return copy_replica({n:Path('/source')/n for n in COMPONENTS},
            {n:Path('/target')/n for n in COMPONENTS},expected=req.get('expected') if op=='copy_resume' else None)
    if op == 'validate':
        return validate({n:Path('/source')/n for n in COMPONENTS},req['expected'])
    if op == 'initialize':
        for base in [Path('/active'),Path('/peer')]:
            for name,value in req['files'].items():
                if name not in {'role.json','coordinator.json','operation.json','profile.json'}:
                    raise LifecycleError('control_initialization_scope')
                replace_file(base/name,json.dumps(value,sort_keys=True));durable_parent(base/name)
        return {'initialized':True}
    guard()
    if op == 'guard':
        return {'valid':True}
    if op == 'read_control':
        return json.loads(Path('/control/coordinator.json').read_bytes())
    if op == 'write_control':
        save(Path('/control/coordinator.json'),req['state']);return {'saved':True}
    if op == 'operation':
        if req['busy'] and json.loads(Path('/control/operation.json').read_bytes())['busy']:
            raise LifecycleError('control_unfinished_operation')
        save(Path('/control/operation.json'),{'busy':req['busy']});return {'saved':True}
    if op == 'write_profile':
        save(Path('/control/profile.json'),req['profile']);return {'saved':True}
    if op == 'pause_leaf':
        path=Path('/state/config.json');cfg=json.loads(path.read_bytes());cfg['paused']=True
        atomic(path,json.dumps(cfg));return {'paused':True}
    raise LifecycleError('control_storage_operation')


def main():
    if len(sys.argv)>1 and sys.argv[1]=='standby':
        while True:
            # A standby has read-only mounts and no publishing command or socket.
            json.loads(Path('/role/role.json').read_bytes())
            json.loads(Path('/state/state.json').read_bytes())
            time.sleep(1)
    else:
        print(json.dumps(dispatch(json.load(sys.stdin))))


if __name__=='__main__':
    main()
