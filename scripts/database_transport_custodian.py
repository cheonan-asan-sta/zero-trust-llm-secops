"""Isolated DB transport CA/key ceremony; signed public chain, sealed candidates."""

import base64
import hashlib
import json
import math
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import authority_custodian as custody
from scripts import database_transport_preflight as preflight
from scripts.certificate_controller import LifecycleError, atomic, remove_file, save

POLICY = {'period_seconds': 86400, 'margin_seconds': 86400, 'root_days': 30, 'leaf_days': 7}
FILES = {name: ('root.pem', 'server.pem', 'server.key') if index == 0 else ('root.pem', 'client.pem', 'client.key')
         for index, name in enumerate(preflight.VOLUMES)}
PHASES = {'idle', 'quiescing', 'prepared', 'stopped', 'installed', 'started', 'committing', 'resuming'}


def file_hash(body):
    return hashlib.sha256(body.encode().replace(b'\r\n', b'\n')).hexdigest()


def manifest(files):
    if set(files) != set(FILES) or any(set(files[v]) != set(names) for v, names in FILES.items()):
        raise LifecycleError('transport_file_inventory')
    return {v: {n: file_hash(files[v][n]) for n in names} for v, names in FILES.items()}


def generate():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = custody.ca_certificate(root_key, 'Independent rotating database transport', None,
                                  days=POLICY['root_days'], depth=0)
    root_pem, files, now = custody.pem_cert(root), {}, datetime.now(UTC)
    for index, volume in enumerate(FILES):
        server = index == 0
        name, stem = ('ca-db', 'server') if server else ('secops_ca', 'client')
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30)).not_valid_after(now + timedelta(days=POLICY['leaf_days']))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .sign(root_key, hashes.SHA256()))
        files[volume] = {'root.pem': root_pem, stem + '.pem': custody.pem_cert(cert), stem + '.key': custody.pem_key(key)}
    return {'root': root_pem, 'root_key': custody.pem_key(root_key), 'files': files, 'created_at': time.time()}


def seed():
    bundle, password = generate(), secrets.token_urlsafe(48).encode()
    bundle['epoch'] = 0
    anchor = {'schema': 'transport-anchor-1', 'root': bundle['root'], 'files': manifest(bundle['files']), 'policy': POLICY}
    state = {'schema': 'transport-custodian-1', 'epoch': 0, 'current': 'g0.sealed', 'manifest': None,
             'pending': None, 'anchor': anchor, 'last_at': bundle['created_at']}
    return bundle['files'], {'password': password.decode(), 'g0.sealed': custody.seal(bundle, password).decode(),
                              'state.json': json.dumps(state)}, anchor


def hash_inventory(value):
    return (isinstance(value, dict) and set(value) == set(FILES)
            and all(isinstance(value[v], dict) and set(value[v]) == set(names)
                and all(isinstance(h, str) and len(h) == 64 and set(h) <= set('0123456789abcdef')
                        for h in value[v].values()) for v, names in FILES.items()))


def verify_plan(plan, root, before, epoch, previous):
    fields = {'schema', 'epoch', 'previous', 'before', 'after', 'root', 'created_at', 'policy', 'proof'}
    if (not isinstance(plan, dict) or set(plan) != fields or plan['schema'] != 'transport-plan-1'
            or type(plan['epoch']) is not int or plan['epoch'] != epoch or plan['previous'] != previous
            or plan['before'] != before or not hash_inventory(plan['after']) or plan['policy'] != POLICY
            or type(plan['created_at']) not in {int, float} or not math.isfinite(plan['created_at'])):
        raise LifecycleError('transport_plan_scope')
    old = x509.load_pem_x509_certificate(root.encode())
    try:
        old.public_key().verify(base64.b64decode(plan['proof'], validate=True),
            custody.canonical({k: v for k, v in plan.items() if k != 'proof'}), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise LifecycleError('transport_plan_signature') from None
    stamp = datetime.fromtimestamp(plan['created_at'], UTC)
    new = preflight.certificate(plan['root'].encode(), stamp, ca=True)
    new.verify_directly_issued_by(new)
    if (not old.not_valid_before_utc <= stamp < old.not_valid_after_utc
            or new.not_valid_after_utc > stamp + timedelta(days=POLICY['root_days'], seconds=5)
            or preflight.public_key(new.public_key()) == preflight.public_key(old.public_key())
            or any(plan['after'][v]['root.pem'] != file_hash(plan['root']) for v in FILES)
            or any(plan['after'][v][n] == before[v][n] for v, names in FILES.items() for n in names)):
        raise LifecycleError('transport_plan_key_or_root')


def initial(anchor):
    return {'schema': 'transport-journal-1', 'epoch': 0, 'manifest': None, 'history': [], 'plan': None,
            'phase': 'idle', 'restore_paused': True, 'profile_digest': None, 'last_error': None}


def checked(anchor, journal):
    if (anchor.get('schema') != 'transport-anchor-1' or anchor.get('policy') != POLICY
            or not hash_inventory(anchor.get('files')) or journal.get('schema') != 'transport-journal-1'
            or journal.get('phase') not in PHASES or not isinstance(journal.get('history'), list)
            or len(journal['history']) > 64 or type(journal.get('epoch')) is not int):
        raise LifecycleError('transport_journal_shape')
    root, files, previous = anchor['root'], anchor['files'], None
    for epoch, plan in enumerate(journal['history'], 1):
        verify_plan(plan, root, files, epoch, previous)
        root, files, previous = plan['root'], plan['after'], custody.digest(plan)
    if journal['epoch'] != len(journal['history']) or journal['manifest'] != previous:
        raise LifecycleError('transport_journal_sequence')
    pending = journal.get('plan')
    if (journal['phase'] in {'prepared', 'stopped', 'installed', 'started', 'committing'}) != (pending is not None):
        raise LifecycleError('transport_journal_pending')
    if pending:
        verify_plan(pending, root, files, journal['epoch'] + 1, previous)
    return {'root': root, 'files': files, 'manifest': previous, 'epoch': journal['epoch'], 'pending': pending}


def verify_files(anchor, journal, directories, *, partial=False):
    state = checked(anchor, journal)
    pending = state['pending']
    target = pending['after'] if pending and (partial or journal['phase'] in {'installed', 'started', 'committing'}) else state['files']
    # Mixtures are admitted only while all transport services are fenced by the host.
    for volume, names in FILES.items():
        for name in names:
            body = preflight.read(directories[volume] / name, private=name.endswith('.key'))
            actual = hashlib.sha256(body.replace(b'\r\n', b'\n')).hexdigest()
            allowed = {target[volume][name]}
            if pending and partial:
                allowed.add(state['files'][volume][name])
            if actual not in allowed:
                raise LifecycleError('transport_published_file_changed')
    root = pending['root'] if pending and journal['phase'] in {'installed', 'started', 'committing'} else state['root']
    if partial:
        root = pending['root'] if pending else state['root']
    result = None if partial else preflight.inspect_transport(directories, file_hash(root))
    return {'verified': True, 'epoch': state['epoch'], 'pending': bool(pending), 'transport': result}


class Custodian:
    def __init__(self, directory=Path('/vault'), directories=None):
        self.directory = directory
        self.directories = directories or {v: Path('/transport') / v for v in FILES}
        self.state = json.loads(preflight.read(directory / 'state.json', private=True))
        self.password = preflight.read(directory / 'password', private=True)
        if (self.state.get('schema') != 'transport-custodian-1' or type(self.state.get('epoch')) is not int
                or not 0 <= self.state['epoch'] <= 64 or self.state.get('current') != f"g{self.state['epoch']}.sealed"
                or self.state.get('pending') is not None and self.state['pending'].get('name') != f"g{self.state['epoch'] + 1}.sealed"
                or not 32 <= len(self.password) <= 256):
            raise LifecycleError('transport_vault_scope')

    def persist(self):
        save(self.directory / 'state.json', self.state)

    def bundle(self, name):
        if name not in {self.state['current'], f"g{self.state['epoch'] + 1}.sealed"}:
            raise LifecycleError('transport_sealed_scope')
        return custody.unseal(preflight.read(self.directory / name, private=True), self.password)

    def admit(self, request):
        state = checked(request['anchor'], request['journal'])
        if request['anchor'] != self.state['anchor']:
            raise LifecycleError('transport_anchor_changed')
        # Lost host response after commit is safe to resume with the same pending plan.
        committed = (state['pending'] and self.state['epoch'] == state['epoch'] + 1
                     and self.state['manifest'] == custody.digest(state['pending']) and not self.state['pending'])
        if not committed and (self.state['epoch'] != state['epoch'] or self.state['manifest'] != state['manifest']):
            raise LifecycleError('transport_vault_journal_mismatch')
        return state, committed

    def prepare(self, request):
        state, committed = self.admit(request)
        if committed:
            raise LifecycleError('transport_commit_resume_required')
        current = self.bundle(self.state['current'])
        if manifest(current['files']) != state['files'] or current['root'] != state['root']:
            raise LifecycleError('transport_sealed_bundle_changed')
        now = time.time()
        preflight.certificate(current['root'].encode(), datetime.now(UTC), ca=True)
        due = now - self.state['last_at'] >= POLICY['period_seconds']
        for v in FILES:
            stem = 'server' if v == preflight.VOLUMES[0] else 'client'
            cert = x509.load_pem_x509_certificate(current['files'][v][stem + '.pem'].encode())
            if cert.not_valid_after_utc.timestamp() <= now:
                raise LifecycleError('transport_expired_requires_explicit_recovery')
            due |= cert.not_valid_after_utc.timestamp() - now <= POLICY['margin_seconds']
        if self.state['pending']:
            return {'due': True, 'plan': self.state['pending']['plan']}
        if not due:
            return {'due': False, 'next_due_at': min(self.state['last_at'] + POLICY['period_seconds'],
                *[x509.load_pem_x509_certificate(current['files'][v]['server.pem' if i == 0 else 'client.pem'].encode())
                    .not_valid_after_utc.timestamp() - POLICY['margin_seconds'] for i, v in enumerate(FILES)])}
        candidate = generate() | {'epoch': state['epoch'] + 1}
        plan = {'schema': 'transport-plan-1', 'epoch': candidate['epoch'], 'previous': state['manifest'],
                'before': state['files'], 'after': manifest(candidate['files']), 'root': candidate['root'],
                'created_at': candidate['created_at'], 'policy': POLICY}
        plan['proof'] = base64.b64encode(custody.load_key(current['root_key']).sign(custody.canonical(plan), ec.ECDSA(hashes.SHA256()))).decode()
        verify_plan(plan, state['root'], state['files'], state['epoch'] + 1, state['manifest'])
        name = f"g{candidate['epoch']}.sealed"
        atomic(self.directory / name, custody.seal(candidate, self.password))
        self.state['pending'] = {'name': name, 'plan': plan}
        self.persist()
        return {'due': True, 'plan': plan}

    def install(self, request):
        state, committed = self.admit(request)
        plan = state['pending']
        if not plan or committed or self.state['pending']['plan'] != plan:
            raise LifecycleError('transport_pending_plan_required')
        verify_files(request['anchor'], request['journal'], self.directories, partial=True)
        candidate = self.bundle(self.state['pending']['name'])
        if manifest(candidate['files']) != plan['after'] or candidate['root'] != plan['root']:
            raise LifecycleError('transport_candidate_changed')
        for volume, names in FILES.items():
            for name in names:
                atomic(self.directories[volume] / name, candidate['files'][volume][name])
        return verify_files(request['anchor'], request['journal'] | {'phase': 'installed'}, self.directories)

    def commit(self, request):
        state, committed = self.admit(request)
        plan = state['pending']
        if not plan:
            raise LifecycleError('transport_pending_plan_required')
        verify_files(request['anchor'], request['journal'], self.directories)
        if not committed:
            if self.state['pending']['plan'] != plan:
                raise LifecycleError('transport_pending_plan_changed')
            self.state.update(epoch=plan['epoch'], current=self.state['pending']['name'], manifest=custody.digest(plan),
                              pending=None, last_at=plan['created_at'])
            self.persist()
        for path in self.directory.glob('g*.sealed'):
            if path.name != self.state['current']:
                remove_file(path)
        return {'committed': True, 'epoch': plan['epoch'], 'sealed_bundles': len(list(self.directory.glob('g*.sealed')))}


def main():
    try:
        raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('size')
        request = json.loads(raw)
        operation = request.pop('operation')
        if set(request) != {'anchor', 'journal'}:
            raise ValueError('scope')
        if operation == 'verify':
            result = verify_files(request['anchor'], request['journal'], {v: Path('/transport') / v for v in FILES},
                                  partial=request['journal']['phase'] == 'stopped')
        elif operation in {'prepare', 'install', 'commit'}:
            result = getattr(Custodian(), operation)(request)
        else:
            raise ValueError('operation')
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, InvalidSignature,
            UnsupportedAlgorithm, x509.ExtensionNotFound, x509.DuplicateExtension):
        # Library and filesystem errors may include key bytes/paths; fixed output only.
        print(json.dumps({'verified': False, 'reason': 'database_transport_ceremony_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
