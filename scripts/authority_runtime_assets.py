"""CA and controller material for the optional persistent, monitored local graph."""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from scripts import certificate_authority as authority
from scripts import continuous_mtls_assets as base
from scripts import monitoring_runtime_assets as monitoring
from scripts.mtls_fixtures import leaf

SERVERS = ('core-a', 'gateway', 'bridge-auth', 'bridge-consume', 'resource', 'proxy', *monitoring.SERVERS)
MANAGED = ('core-tls', 'gateway-tls', 'bridge-tls', 'resource-tls', 'proxy-tls', 'collector-tls',
           'operator-tls', 'reader-tls', 'exporter-tls', 'prometheus-tls', 'alertmanager-tls',
           'sink-tls', 'monitor-operator-tls', 'renewal-tls')
RELOADS = {'proxy': ('proxy', 'proxy-auth', 'proxy-resource'),
           'prometheus': ('prometheus', 'scrape-agent', 'monitor-alert'),
           'alertmanager': ('alertmanager', 'alert-manager')}
INPUTS = ('infra/mtls/ca-tools.lock.json', 'infra/mtls/nginx-renewal.sh')
# These are the only mutable local management controls. All other configuration
# is sealed before startup; this does not authenticate a malicious Docker host.
CONTROLS = {'paused', 'disabled', 'renew_before'}


def fixed_configuration(value):
    return {key: body for key, body in value.items() if key not in CONTROLS}


def configuration(material):
    policies, pairs = [], []
    identities = {}
    for volume in MANAGED:
        for name in material[volume]:
            if name.endswith('.json'):
                policies.append(f'/managed/{volume}/{name}')
            if name.endswith('.key'):
                certificate = name[:-4] + '.pem'
                pairs.append((f'/managed/{volume}/{certificate}', f'/managed/{volume}/{name}'))
                from scripts.certificate_controller import metadata
                info = metadata(material[volume][certificate])
                identities[info['name']] = info['purpose']
    # The probe uses an already-authorized service identity, not the renewal
    # identity. References remain inside the controller's explicitly managed roots.
    probe = {'ca': '../proxy-tls/ca.pem', 'cert': '../proxy-tls/proxy-auth.pem',
             'key': '../proxy-tls/proxy-auth.key'}
    material['renewal-tls']['probe-bridge-auth.json'] = json.dumps(probe)
    profiles = [
        ('core-a', 'core', 8000, 'operator-tls/core.json'),
        ('gateway', 'gateway', 8443, 'collector-tls/profile.json'),
        ('bridge-auth', 'bridge', 8081, 'renewal-tls/probe-bridge-auth.json'),
        ('bridge-consume', 'bridge', 8082, 'resource-tls/consume.json'),
        ('resource', 'resource', 8083, 'operator-tls/resource.json'),
        ('proxy', 'proxy', 8080, 'operator-tls/frontend.json'),
        ('reader', 'reader', 8000, 'exporter-tls/reader.json'),
        ('exporter', 'exporter', 9101, 'monitor-operator-tls/exporter.json'),
        ('prometheus', 'prometheus', 9090, 'monitor-operator-tls/prometheus.json'),
        ('alertmanager', 'alertmanager', 9093, 'monitor-operator-tls/alertmanager.json'),
        ('sink', 'sink', 9001, 'monitor-operator-tls/sink.json'),
    ]
    return {'roots': ['/managed/' + name for name in MANAGED], 'policies': policies,
            'extra_certificates': pairs, 'allowed_provisioners': sorted(name + '-' + purpose for name, purpose in identities.items()),
            'probes': [{'server_name': name, 'host': host, 'port': port, 'profile': '/managed/' + path}
                       for name, host, port, path in profiles],
            'reload_groups': [{'root': '/managed/' + name,
                               'files': [f'/managed/{name}/{identity}.pem' for identity in names],
                               'ack': '/ack/' + name + '/ack'} for name, names in RELOADS.items()],
            'server_renewal': {name: 'renew-' + name for name in SERVERS},
            'renew_before': {name: 1200 if name.startswith('renew-') else 400 for name in identities},
            'interval_seconds': 2, 'overlap_seconds': 1, 'disabled': [], 'paused': False}


def material():
    root, issuer = authority.hierarchy()
    bundle = ''.join(pair[1].public_bytes(serialization.Encoding.PEM).decode() for pair in (root, issuer))
    result = base.assets(monitoring=True, issuer=issuer, trust_bundle=bundle)
    renewal = {'ca.pem': bundle}
    provisioners = {}
    for name in SERVERS:
        info = leaf(issuer, 'renew-' + name)
        renewal.update({f'renew-{name}.pem': info['cert'], f'renew-{name}.key': info['key']})
    result['renewal-tls'] = renewal
    cfg = configuration(result)
    for identity in cfg['allowed_provisioners']:
        name, purpose = identity.rsplit('-', 1)
        entry, key = authority.provisioner(name, purpose)
        provisioners[entry['name']] = (entry, key)
    delegated = []
    for name in SERVERS:
        key = serialization.load_pem_private_key(renewal[f'renew-{name}.key'].encode(), password=None)
        delegated.append(authority.server_renewal_provisioner(name, key.public_key()))
    result['ca-state'] = authority.ca_files(root, issuer, [p[0] for p in provisioners.values()] + delegated)
    result['ca-state']['initialize.once'] = 'approved-new-local-ca\n'
    result['certificate-state'] = {'config.json': json.dumps(cfg),
        'root.pem': root[1].public_bytes(serialization.Encoding.PEM).decode(),
        'issuer.pem': issuer[1].public_bytes(serialization.Encoding.PEM).decode()}
    result['config']['nginx-renewal.sh'] = (base.ROOT / INPUTS[1]).read_text(encoding='utf-8')
    for name in RELOADS:
        result['ack-' + name] = {'ack': 'starting'}
    # Only exact-CSR bootstrap signing keys remain briefly in the host driver's
    # RAM. Root/intermediate key objects are not returned to the caller.
    return result, provisioners


def configuration_valid(value):
    return (isinstance(value, dict) and type(value.get('paused')) is bool and isinstance(value.get('disabled'), list)
            and all(isinstance(uid, str) and len(uid) == 64 and all(c in '0123456789abcdef' for c in uid)
                    for uid in value['disabled'])
            and isinstance(value.get('renew_before'), dict)
            and all(type(n) in {int, float} and 0 <= n <= 3600 for n in value['renew_before'].values()))


def require_existing_database(directory):
    directory = Path(directory)
    marker, db = directory / 'require-existing-db', directory / 'db'
    files = (marker, db / 'MANIFEST', db / 'KEYREGISTRY')
    if (not db.is_dir() or db.is_symlink() or (directory / 'initialize.once').exists()
            or any(not path.is_file() or path.is_symlink() or path.stat().st_size == 0 for path in files)):
        raise ValueError('authority_database_required')


def prepare_ca_start(directory):
    directory = Path(directory)
    permit, marker = directory / 'initialize.once', directory / 'require-existing-db'
    if permit.exists():
        if (not permit.is_file() or permit.is_symlink() or not 0 < permit.stat().st_size <= 128
                or marker.exists() or (directory / 'db').exists()):
            raise ValueError('authority_initialization_conflict')
        # Consume once before exec, not after the CA might already have accepted
        # a sign/revoke request. Interrupted first creation needs new approval.
        os.replace(permit, marker)
        if os.name == 'posix':
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    else:
        require_existing_database(directory)


def ca_service():
    try:
        prepare_ca_start(Path('/ca'))
        os.execv('/tools/step-ca', ['/tools/step-ca', '/ca/ca.json', '--password-file', '/ca/password.txt'])
    except (OSError, ValueError):
        print(json.dumps({'ca': 'unavailable', 'reason': 'authority_database_required'}), flush=True)
        raise SystemExit(1) from None


if __name__ == '__main__':
    ca_service()
