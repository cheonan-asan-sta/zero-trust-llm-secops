"""Fresh opt-in PKI graph; retain authority secrets only in a sealed vault."""

import json
import secrets

from cryptography.hazmat.primitives import serialization

from scripts import authority_custodian as custody
from scripts import authority_runtime_assets as authority
from scripts import certificate_authority as ca
from scripts import rekey_runtime_assets as rekey
from scripts.mtls_fixtures import authority as transport_authority
from scripts.mtls_fixtures import leaf

INPUTS = ('infra/mtls/ca-ha-tools.lock.json', 'infra/mtls/authority-policy.example.json')
VOLUMES = ('authority-vault', 'authority-db-data', 'authority-db-tls', 'authority-ca-a-db', 'authority-ca-b-db')
PUBLIC_FILES = {'config': ('nginx-renewal.sh', 'nginx-rekey.sh'),
                'certificate-state': ('ca-endpoints.json',), 'ca-state': ('database-anchor.json',),
                'authority-db-tls': ('root.pem', 'server.pem', 'start.sh', 'pg_hba.conf', 'postgresql.conf'),
                'authority-ca-a-db': ('root.pem', 'client.pem'), 'authority-ca-b-db': ('root.pem', 'client.pem')}
DATABASE_SOURCE = ('postgresql://secops_ca@ca-db:5432/stepca?sslmode=verify-full&sslrootcert=/db-tls/root.pem'
                   '&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key&connect_timeout=2')
POSTGRES_START = '''set -eu
if [ ! -s /pgdata/db/PG_VERSION ]; then
  test -f /pgdata/initialize.once && test ! -e /pgdata/initialized
  mv /pgdata/initialize.once /pgdata/initialized
  initdb -D /pgdata/db -U postgres --auth-local=trust --auth-host=reject >/dev/null
fi
test -f /pgdata/initialized && test ! -e /pgdata/initialize.once
exec postgres -D /pgdata/db -c config_file=/pg-tls/postgresql.conf
'''


def material(policy, *, last_at=None):
    root, issuer = ca.hierarchy()
    result, provisioners = rekey.material(hierarchy=(root, issuer))
    cfg = json.loads(result['certificate-state']['config.json'])
    cfg.update(authority_epoch=0, authority_manifest_hash=None, authority_signer_root='/managed/renewal-tls')
    result['certificate-state']['config.json'] = json.dumps(cfg)
    result['certificate-state']['ca-endpoints.json'] = json.dumps({
        'schema': 'ca-endpoints-1', 'hosts': ['ca-a', 'ca-b'], 'connect_timeout_seconds': 1})
    online = json.loads(result['ca-state']['ca.json'])
    online.update(dnsNames=['ca', 'ca-a', 'ca-b'], db={'type': 'postgresql', 'database': 'stepca', 'dataSource': DATABASE_SOURCE})
    result['ca-state']['ca.json'] = json.dumps(online)
    result['ca-state'].pop('initialize.once')
    result['ca-state']['database-anchor.json'] = json.dumps({'identifier': secrets.token_hex(24)})
    keys = {name: pair[1] for name, pair in provisioners.items()}
    keys.update({'server-renewal-' + name: serialization.load_pem_private_key(
        result['renewal-tls']['sign-' + name + '.key'].encode(), password=None) for name in authority.SERVERS})
    result['authority-vault'] = custody.seed_files(root, issuer, online['authority']['provisioners'], keys,
        {name: 'sign-' + name + '.key' for name in authority.SERVERS}, policy=policy, last_at=last_at)
    # Independent transport PKI; rotation of the workload CA never replaces DB trust.
    transport = transport_authority('Independent local CA database transport')
    transport_root = transport[1].public_bytes(serialization.Encoding.PEM).decode()
    server = leaf(transport, 'ca-db', server=True)
    result['authority-db-tls'] = {'root.pem': transport_root, 'server.pem': server['cert'], 'server.key': server['key'],
        'start.sh': POSTGRES_START,
        'pg_hba.conf': 'local all postgres trust\nhostssl stepca secops_ca 0.0.0.0/0 cert\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n',
        'postgresql.conf': "listen_addresses='*'\nport=5432\nunix_socket_directories='/tmp'\nssl=on\nssl_min_protocol_version='TLSv1.2'\n"
        "ssl_cert_file='/pg-tls/server.pem'\nssl_key_file='/pg-tls/server.key'\nssl_ca_file='/pg-tls/root.pem'\nhba_file='/pg-tls/pg_hba.conf'\n"
        "max_connections=50\nshared_buffers='32MB'\n"}
    for name in ('a', 'b'):
        client = leaf(transport, 'secops_ca')
        result['authority-ca-' + name + '-db'] = {'root.pem': transport_root, 'client.pem': client['cert'], 'client.key': client['key']}
    result['authority-db-data'] = {'initialize.once': 'approved-new-local-database\n'}
    return result, provisioners
