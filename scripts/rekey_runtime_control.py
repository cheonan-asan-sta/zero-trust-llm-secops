"""Container-only validation/audit of journal-authorized rekey references."""

import argparse
import json
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from scripts.certificate_controller import bindings, metadata
from scripts.certificate_key_rotation import public_hash


def allowed_pairs(state, identity, volume):
    if state is None:
        return [{'cert': f'/managed/{volume}/{identity}.pem', 'key': f'/managed/{volume}/{identity}.key'}]
    found = [c for c in state['credentials'].values() if c['name'] == identity]
    if len(found) != 1:
        raise ValueError('rekey_identity_inventory')
    c = found[0]
    pairs = c['assets'] + (c.get('pending_key') or {}).get('assets', [])
    result = []
    for pair in pairs:
        certificate, key = Path(pair['cert']), Path(pair['key'])
        if certificate.parent != Path('/managed') / volume:
            continue
        if (key.parent != certificate.parent or key.stem != certificate.stem
                or certificate.suffix != '.pem' or key.suffix != '.key'
                or not re.fullmatch(re.escape(identity) + r'(?:-r[a-f0-9]{24})?', certificate.stem)):
            raise ValueError('rekey_asset_scope')
        result.append(pair)
    if not result:
        raise ValueError('rekey_volume_inventory')
    return result


def configuration_matches(actual, template, volume, state):
    """Only a recorded complete cert/key pair may replace each source binding."""
    names = set(re.findall(r'/service-tls/([A-Za-z0-9_-]+)\.key', template))
    expected = template
    for name in sorted(names):
        pairs = allowed_pairs(state, name, volume)
        matches = [pair for pair in pairs if all('/service-tls/' + Path(pair[field]).name in actual
                                                 for field in ('cert', 'key'))]
        if not matches:
            return False
        pair = matches[0]
        expected = expected.replace('/service-tls/' + name + '.pem', '/service-tls/' + Path(pair['cert']).name)
        expected = expected.replace('/service-tls/' + name + '.key', '/service-tls/' + Path(pair['key']).name)
    return expected == actual


def retired_without_bindings(state, identity, disabled):
    """An explicitly disabled client is an archive only after every pin is gone."""
    if state is None:
        return False
    found = [(uid, c) for uid, c in state['credentials'].items() if c['name'] == identity]
    if len(found) != 1:
        return False
    uid, c = found[0]
    if (uid not in disabled or c.get('status') != 'disabled' or c.get('purpose') != 'clientAuth'
            or c.get('candidate') or c.get('pending_key') or not c.get('bindings')):
        return False
    for binding in c['bindings']:
        path = Path(binding['path'])
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536:
            return False
        if bindings(json.loads(path.read_bytes()), c['fingerprint']):
            return False
    return True


def verify_pair(pair, identity, issuer, state, allowed, *, disabled=()):
    certificate, key = Path(pair['cert']), Path(pair['key'])
    for path in (certificate, key):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('rekey_asset_file')
    body = certificate.read_text()
    info = metadata(body)
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    leaf = x509.load_pem_x509_certificate(body.encode())
    issuers = issuer if isinstance(issuer, list) else [issuer]
    for authority in issuers:
        try:
            leaf.verify_directly_issued_by(authority)
            break
        except (ValueError, TypeError, InvalidSignature):
            pass
    else:
        raise ValueError('rekey_unapproved_issuer')
    now = datetime.now(UTC)
    if (info['name'] != identity or identity + '-' + info['purpose'] not in allowed
            or now < leaf.not_valid_before_utc
            or now >= leaf.not_valid_after_utc and not retired_without_bindings(state, identity, disabled)
            or public_hash(leaf.public_key()) != public_hash(private.public_key())
            or stat.S_IMODE(key.stat().st_mode) != 0o600):
        raise ValueError('rekey_asset_identity')
    if state is not None:
        c = next(c for c in state['credentials'].values() if c['name'] == identity)
        accepted = {c['fingerprint']}
        if c.get('candidate'):
            accepted.add(metadata(c['candidate'])['fingerprint'])
        if info['fingerprint'] not in accepted:
            raise ValueError('rekey_asset_not_published_or_pending')


def verify(request):
    path = Path('/state/state.json')
    state = json.loads(path.read_bytes()) if path.exists() else None
    if request['initialized'] and state is None:
        raise ValueError('rekey_state_required')
    cfg = json.loads(Path('/state/config.json').read_bytes())
    issuer = (x509.load_pem_x509_certificates(request['issuers'].encode()) if 'issuers' in request else
              x509.load_pem_x509_certificate(Path('/state/issuer.pem').read_bytes()))
    def issuers_for(identity):
        credential = next(((uid, c) for uid, c in (state or {}).get('credentials', {}).items() if c['name'] == identity), None)
        if credential and (credential[0] in cfg.get('disabled', []) or credential[1].get('inhibited')) and request.get('retired_issuers'):
            return x509.load_pem_x509_certificates(request['retired_issuers'].encode())
        return issuer
    for volume, files in request['templates'].items():
        for name, template in files.items():
            actual = (Path('/managed') / volume / name).read_text()
            if not configuration_matches(actual, template, volume, state):
                raise ValueError('rekey_configuration_not_authorized')
            for identity in set(re.findall(r'/service-tls/([A-Za-z0-9_-]+)\.key', template)):
                for pair in allowed_pairs(state, identity, volume):
                    if all('/service-tls/' + Path(pair[field]).name in actual for field in ('cert', 'key')):
                        verify_pair(pair, identity, issuers_for(identity), state, cfg['allowed_provisioners'], disabled=cfg.get('disabled', []))
                        break
    for relative, identity in request['profiles'].items():
        volume, filename = relative.split('/')
        root = Path('/managed') / volume
        profile = json.loads((root / filename).read_bytes())
        pair = {'cert': str(root / profile['cert']), 'key': str(root / profile['key'])}
        if pair not in allowed_pairs(state, identity, volume):
            raise ValueError('rekey_profile_identity_or_generation')
        verify_pair(pair, identity, issuers_for(identity), state, cfg['allowed_provisioners'], disabled=cfg.get('disabled', []))
    for name, expected in request['signers'].items():
        key = serialization.load_pem_private_key(Path(cfg['server_signers'][name]).read_bytes(), password=None)
        if public_hash(key.public_key()) != expected:
            raise ValueError('rekey_delegation_signer_drift')
    return {'verified': True}


def audit():
    state = json.loads(Path('/state/state.json').read_bytes())
    result = {}
    for uid, c in state['credentials'].items():
        assets = c['assets']
        hashes = [public_hash(serialization.load_pem_private_key(Path(a['key']).read_bytes(), password=None).public_key())
                  for a in assets]
        pending = c.get('pending_key')
        result[uid] = {'name': c['name'], 'key_generation': c.get('key_generation', 0),
            'public_key_sha256': hashes[0], 'copies_match': len(set(hashes)) == 1,
            'pairs_match': all(public_hash(x509.load_pem_x509_certificate(Path(a['cert']).read_bytes()).public_key()) == h
                               for a, h in zip(assets, hashes, strict=True)),
            'private_modes': sorted({stat.S_IMODE(Path(a['key']).stat().st_mode) for a in assets}), 'assets': assets,
            'pending': {'public_key_sha256': public_hash(serialization.load_pem_private_key(Path(pending['key']).read_bytes(), password=None).public_key()),
                        'assets': pending['assets']} if pending else None}
    return {'phase': (state.get('transaction') or {}).get('phase'), 'credentials': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('verify', 'audit'))
    args = parser.parse_args()
    try:
        if args.mode == 'verify':
            raw = sys.stdin.buffer.read(131073)
            if len(raw) > 131072:
                raise ValueError('rekey_control_size')
            result = verify(json.loads(raw))
        else:
            result = audit()
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration, InvalidSignature):
        print(json.dumps({'verified': False, 'reason': 'rekey_validation_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
