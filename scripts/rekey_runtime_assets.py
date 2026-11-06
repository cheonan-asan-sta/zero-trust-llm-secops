"""Rekey material reusing the persistent CA; delegation keys remain separate."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scripts import authority_runtime_assets as authority
from scripts import certificate_authority as ca
from scripts import monitoring_runtime_assets as monitoring
from scripts.continuous_mtls_runtime import ROOT

INPUT = 'infra/mtls/nginx-rekey.sh'
PREFIX = '/service-tls/'


def templates():
    result = monitoring.configurations()
    for files in result.values():
        for name in files:
            files[name] = files[name].replace('/tls/', PREFIX)
    result['proxy-tls'] = {'nginx-rekey.conf': (ROOT / 'infra/mtls/all-hops-nginx.conf').read_text(encoding='utf-8')}
    return result


def material(*, hierarchy=None):
    result, provisioners = authority.material() if hierarchy is None else authority.material(hierarchy=hierarchy)
    cfg = json.loads(result['certificate-state']['config.json'])
    online = json.loads(result['ca-state']['ca.json'])
    delegated = {}
    for name in authority.SERVERS:
        key = ec.generate_private_key(ec.SECP256R1())
        delegated['server-renewal-' + name] = ca.server_renewal_provisioner(name, key.public_key())
        result['renewal-tls']['sign-' + name + '.key'] = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    online['authority']['provisioners'] = [delegated.get(p['name'], p) for p in online['authority']['provisioners']]
    result['ca-state']['ca.json'] = json.dumps(online)
    cfg['server_signers'] = {name: '/managed/renewal-tls/sign-' + name + '.key' for name in authority.SERVERS}
    # The reload probe is a regular same-volume profile, so the existing rotation
    # publisher can switch both its key/cert paths together without relaxing scope.
    result['renewal-tls'].pop('probe-bridge-auth.json')
    from scripts.certificate_controller import fingerprint
    result['proxy-tls']['bridge-auth-probe.json'] = json.dumps({
        'ca': 'ca.pem', 'cert': 'proxy-auth.pem', 'key': 'proxy-auth.key',
        'host': 'bridge', 'port': 8081, 'server_name': 'bridge-auth',
        'server_pins': [fingerprint(result['bridge-tls']['bridge-auth.pem'])]})
    cfg['policies'].append('/managed/proxy-tls/bridge-auth-probe.json')
    next(p for p in cfg['probes'] if p['server_name'] == 'bridge-auth')['profile'] = '/managed/proxy-tls/bridge-auth-probe.json'
    configs = templates()
    for volume, files in configs.items():
        result[volume].update(files)
    cfg['reload_groups'] = [
        {'root': '/managed/' + name + '-tls', 'ack': '/ack/' + name + '/ack', 'resolve_tls': True,
         'files': ['/managed/' + name + '-tls/' + file for file in
                   (['nginx-rekey.conf'] if name == 'proxy' else ['config.yml', 'web.yml'])]}
        for name in authority.RELOADS]
    cfg['key_rotation'] = {'interval_seconds': 600, 'cleanup_grace_seconds': 3,
                           'configuration_files': [file for group in cfg['reload_groups'] for file in group['files']]}
    result['certificate-state']['config.json'] = json.dumps(cfg)
    result['config']['nginx-rekey.sh'] = (ROOT / INPUT).read_text(encoding='utf-8')
    return result, provisioners


def profile_identities(material):
    result = {}
    for volume in authority.MANAGED:
        for name, body in material[volume].items():
            if name.endswith('.json'):
                document = json.loads(body)
                if 'cert' in document:
                    result[f'{volume}/{name}'] = document['cert'].removesuffix('.pem')
    return result
