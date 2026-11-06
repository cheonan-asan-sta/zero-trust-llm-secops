"""Public signed-plan validation and guarded CA startup for the opt-in graph."""

import argparse
import http.client
import json
import os
import ssl
import struct
import sys
import time
from email.utils import parsedate_to_datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from scripts import authority_custodian as custody
from scripts import authority_runtime_assets as assets
from scripts import rekey_runtime_control as rekey
from scripts.authority_rotation_runtime import signer_paths
from scripts.certificate_controller import LifecycleError
from scripts.certificate_key_rotation import public_hash

PHASES = {'idle', 'quiescing', 'prepared', 'trust_staged', 'ca_activated', 'leaf_activating',
          'migrating', 'quiescing_retirement', 'trust_retired', 'committing'}


def read(path, limit=4 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise LifecycleError('authority_public_file_required')
    with path.open('rb') as stream:
        body = stream.read(limit + 1)
    if not 0 < len(body) <= limit:
        raise LifecycleError('authority_public_file_required')
    return body


def journal(value, initial_ca, initial_root):
    """Validate every public plan from the original approved anchor, never reseal."""
    if (value.get('schema') != 'authority-coordinator-1' or value.get('phase') not in PHASES
            or not isinstance(value.get('history'), list) or len(value['history']) > 64):
        raise LifecycleError('authority_journal_shape')
    root, ca, manifest, epoch = initial_root, initial_ca, None, 0
    last = None
    for entry in value['history']:
        plan = entry['plan']
        verify_signed_plan(plan, root, epoch + 1, manifest)
        if plan['before_ca'] != ca or entry['epoch'] != plan['epoch'] or entry['plan_hash'] != custody.digest(plan):
            raise LifecycleError('authority_journal_chain')
        root, ca, epoch, manifest, last = plan['root'], plan['final_ca'], plan['epoch'], custody.digest(plan), plan
    if (value['epoch'] != epoch or value['root'] != root or value['manifest_hash'] != manifest
            or (value['phase'] in {'idle', 'quiescing'}) != (value.get('plan') is None)):
        raise LifecycleError('authority_journal_checkpoint')
    pending = value.get('plan')
    if pending is not None:
        verify_signed_plan(pending, root, epoch + 1, manifest)
        if pending['before_ca'] != ca:
            raise LifecycleError('authority_journal_policy')
    return {'epoch': epoch, 'manifest': manifest, 'root': root, 'ca': ca, 'last': last, 'pending': pending}


def verify_signed_plan(plan, root, epoch, previous):
    try:
        custody.verify_plan(plan, root, epoch=epoch, previous=previous)
    except InvalidSignature:
        raise LifecycleError('authority_journal_signature') from None


def initial_journal(root):
    return {'schema': 'authority-coordinator-1', 'phase': 'idle', 'epoch': 0, 'root': root,
            'manifest_hash': None, 'history': [], 'plan': None, 'last_error': None}


def configuration_variants(base, checked, phase):
    current = dict(base)
    current.update(authority_epoch=checked['epoch'], authority_manifest_hash=checked['manifest'])
    if checked['last']:
        current['server_signers'] = signer_paths(base, checked['last']['signers'])
    variants = [current]
    pending = checked['pending']
    if pending and phase in {'leaf_activating', 'migrating', 'quiescing_retirement', 'trust_retired', 'committing'}:
        changed = current | {'authority_epoch': pending['epoch'], 'server_signers': signer_paths(base, pending['signers'])}
        variants = [current, changed] if phase == 'leaf_activating' else [changed]
        if phase == 'committing':
            variants.append(changed | {'authority_manifest_hash': custody.digest(pending)})
    return variants


def verify(request, directory=Path('/state'), ca_directory=Path('/ca')):
    base, initial_ca = request['initial_configuration'], request['initial_ca']
    if custody.digest(assets.fixed_configuration(base)) != request['initial_configuration_sha256']:
        raise LifecycleError('authority_initial_configuration_changed')
    state = request['journal']
    checked = journal(state, initial_ca, request['initial_root'])
    phase, pending = state['phase'], checked['pending']
    cfg = json.loads(read(directory / 'config.json', 131072))
    if not assets.configuration_valid(cfg) or not any(
            assets.fixed_configuration(cfg) == assets.fixed_configuration(v)
            for v in configuration_variants(base, checked, phase)):
        raise LifecycleError('authority_controller_configuration_changed')
    configurations = [checked['ca']]
    if pending:
        if phase == 'trust_staged':
            configurations.append(pending['overlap_ca'])  # Lost response after install/restart.
        elif phase in {'ca_activated', 'leaf_activating', 'migrating'}:
            configurations = [pending['overlap_ca']]
        elif phase == 'quiescing_retirement':
            configurations = [pending['overlap_ca'], pending['final_ca']]
        elif phase in {'trust_retired', 'committing'}:
            configurations = [pending['final_ca']]
    actual_ca = json.loads(read(ca_directory / 'ca.json', 131072))
    if actual_ca not in configurations:
        raise LifecycleError('authority_ca_configuration_changed')
    # Check active public files and encrypted issuer-key correspondence without
    # returning private bytes. This helper is one-shot and network=none.
    plan = pending if pending and actual_ca != checked['ca'] else checked['last']
    issuer_pem = plan['issuer'] if plan else request['initial_issuer']
    root_pem = plan['root'] if plan else request['initial_root']
    for field, expected in [('crt', issuer_pem)]:
        path = ca_directory / Path(actual_ca[field]).name
        if read(path, 65536).decode() != expected:
            raise LifecycleError('authority_public_certificate_changed')
    roots = actual_ca['root'] if isinstance(actual_ca['root'], list) else [actual_ca['root']]
    expected_roots = [checked['root'], root_pem] if isinstance(actual_ca['root'], list) else [root_pem]
    if [read(ca_directory / Path(name).name, 65536).decode() for name in roots] != expected_roots:
        raise LifecycleError('authority_ca_root_changed')
    key = serialization.load_pem_private_key(read(ca_directory / Path(actual_ca['key']).name, 65536),
                                             password=read(ca_directory / 'password.txt', 1024))
    issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
    if public_hash(key.public_key()) != public_hash(issuer.public_key()):
        raise LifecycleError('authority_ca_key_changed')
    current_issuer = checked['last']['issuer'] if checked['last'] else request['initial_issuer']
    before = checked['root'] + current_issuer
    final = pending['root'] + pending['issuer'] if pending else before
    overlap = ''.join(dict.fromkeys([checked['root'], current_issuer, pending['root'], pending['issuer']])) if pending else before
    paths = [directory / 'root.pem', *[Path(p) / 'ca.pem' for p in base['roots'] if (Path(p) / 'ca.pem').exists()]]
    allowed = {before}
    if pending:
        ledger = json.loads(read(directory / 'authority-transition.json')) if (directory / 'authority-transition.json').exists() else None
        if phase not in {'prepared'} or ledger and ledger['plan_hash'] == custody.digest(pending):
            if not ledger or ledger['plan_hash'] != custody.digest(pending) or sorted(v['path'] for v in ledger['trust']) != sorted(str(p) for p in paths):
                raise LifecycleError('authority_transition_ledger_required')
            for entry in ledger['trust']:
                original = checked['root'] if checked['epoch'] == 0 and entry['path'] == str(directory / 'root.pem') else before
                if entry['before'] != original or entry['overlap'] != overlap:
                    raise LifecycleError('authority_transition_ledger_changed')
            allowed = {overlap}
            if phase == 'prepared':
                allowed.add(before)
            if phase in {'quiescing_retirement', 'trust_retired', 'committing'}:
                allowed = {overlap, final} if phase == 'quiescing_retirement' else {final}
    if any(read(path, 65536).decode() not in (allowed | {checked['root']} if checked['epoch'] == 0
           and path == directory / 'root.pem' and phase in {'idle', 'quiescing', 'prepared'} else allowed) for path in paths):
        raise LifecycleError('authority_trust_bundle_changed')
    issuers = [current_issuer]
    if pending and phase not in {'prepared', 'trust_staged', 'ca_activated'}:
        issuers.append(pending['issuer'])
    if read(directory / 'issuer.pem', 65536).decode() not in issuers:
        raise LifecycleError('authority_controller_issuer_changed')
    if pending and phase in {'quiescing_retirement', 'trust_retired', 'committing'}:
        leaf_state = json.loads(read(directory / 'state.json'))
        active = [c for uid, c in leaf_state['credentials'].items()
                  if uid not in cfg['disabled'] and not c.get('inhibited') and c['not_after'] > time.time()]
        if not active or any(c.get('authority_epoch') != pending['epoch'] for c in active):
            raise LifecycleError('authority_migration_incomplete')
        issuers = [pending['issuer']]
    providers = {p['name']: p for p in (pending if pending and cfg['authority_epoch'] == pending['epoch'] else checked['last'] or
                 {'final_ca': initial_ca})['final_ca']['authority']['provisioners']}
    expected_signers = {name: public_hash(serialization.load_pem_private_key(read(Path(path), 65536), None).public_key())
        for name, path in cfg['server_signers'].items()}
    for name, path in cfg['server_signers'].items():
        public = serialization.load_pem_private_key(read(Path(path), 65536), None).public_key()
        from scripts.certificate_authority import public_jwk
        if public_jwk(public) != providers['server-renewal-' + name]['key']:
            raise LifecycleError('authority_signer_not_authorized')
    historical = [request['initial_issuer'], *[e['plan']['issuer'] for e in state['history']]]
    if pending:
        historical.append(pending['issuer'])
    rekey.verify(request['rekey'] | {'signers': expected_signers, 'issuers': ''.join(dict.fromkeys(issuers)),
                                    'retired_issuers': ''.join(dict.fromkeys(historical))})
    return {'verified': True, 'epoch': checked['epoch'], 'phase': phase}


def health():
    connection = None
    try:
        cfg = json.loads(read(Path('/ca/ca.json'), 131072))
        roots = cfg['root'] if isinstance(cfg['root'], list) else [cfg['root']]
        trust = ''.join(read(Path(p), 65536).decode() for p in roots)
        context = ssl.create_default_context(cadata=trust)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection('ca', 9000, context=context, timeout=2)
        # Prove this particular replica over loopback, preserving CA DNS identity.
        import socket
        raw = socket.create_connection(('127.0.0.1', 9000), timeout=2)
        connection.sock = context.wrap_socket(raw, server_hostname='ca')
        connection.request('GET', '/health')
        response = connection.getresponse()
        body = response.read(1025)
        date = parsedate_to_datetime(response.getheader('Date') or '')
        stamp = int(date.timestamp())
        if (response.status != 200 or len(body) > 1024 or json.loads(body) != {'status': 'ok'}
                or date.utcoffset() is None or date.utcoffset().total_seconds() != 0 or abs(stamp - time.time()) > 5):
            raise ValueError('health')
        return {'healthy': True, 'server_time': stamp}
    except (OSError, ValueError, TypeError, http.client.HTTPException):
        return {'healthy': False}
    finally:
        if connection:
            connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('verify', 'ca', 'health'))
    args = parser.parse_args()
    try:
        if args.mode == 'verify':
            raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('size')
            result = verify(json.loads(raw))
        elif args.mode == 'health':
            result = health()
        else:
            from scripts.authority_database_guard import verify as database_verify
            database_verify()
            os.execv('/tools/step-ca', ['/tools/step-ca', '/ca/ca.json', '--password-file', '/ca/password.txt'])
            return 1
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration, struct.error, InvalidSignature):
        print(json.dumps({'verified': False, 'reason': 'persistent_authority_validation_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
