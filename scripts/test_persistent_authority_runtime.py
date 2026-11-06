"""One combined local acceptance for persistent authority rotation and CA HA."""

import argparse
import copy
import json
import secrets
import subprocess
import time
from pathlib import Path

import jwt

from scripts import authority_custodian as custody
from scripts.authority_rotation_coordinator import Coordinator, lease
from scripts.certificate_authority import bootstrap_token
from scripts.certificate_controller import LifecycleError
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.persistent_authority_runtime import GraphBackend, PersistentAuthorityRuntime
from scripts.test_authority_mtls_runtime import AuthorityChecks
from scripts.test_monitored_mtls_runtime import MonitoredChecks


class AcceptanceRuntime(PersistentAuthorityRuntime):
    seed_last_at = 0

    def helper(self, program, payload=None, **options):
        result = super().helper(program, payload, **options)
        if program == ['-m', 'scripts.certificate_controller', 'init']:
            self._test_inventory = json.loads(result)
        return result

    def write_volume(self, label, files):
        if label == 'certificate-state' and 'bootstrap.json' in files:
            uid = next(uid for uid, c in self._test_inventory.items() if c['name'] == 'collector')
            self._test_signer = self._bootstrap_provisioners['collector-clientAuth']
            self._test_used_grant = {'csr': self._test_inventory[uid]['csr'], 'ott': json.loads(files['bootstrap.json'])[uid]['token']}
        return super().write_volume(label, files)


class Checks(AuthorityChecks):
    expected_volumes = 36

    def __init__(self, directory, *, runtime_class=AcceptanceRuntime):
        MonitoredChecks.__init__(self, directory, runtime_class=runtime_class)
        self.report['schema'] = 'persistent-authority-ha-verification-1'
        self._ca_floor = 0

    def ready(self, *, issuance=False):
        def healthy():
            if self.runtime.sql('SELECT 1;') != '1':
                return False
            status = self.runtime.authority_health()
            if status.get('healthy'):
                self._ca_floor = status['server_time']
                return True
            return False
        self.wait(healthy, 'persistent_authority_replicas_not_ready', timeout=45)
        if issuance:
            self.wait(lambda: all(self.ca(self.fresh(), endpoint=node)['status'] == 201 for node in ('ca-a', 'ca-b')),
                      'persistent_authority_issuance_not_recovered', timeout=45)

    def fresh(self):
        entry, key = self.runtime._test_signer  # Test-driver RAM only, before JWK retirement.
        return {'csr': self.csr, 'ott': bootstrap_token(entry, key, self.csr, seconds=60,
                    now=max(int(time.time()), self._ca_floor)), 'notAfter': '20m'}

    def ca(self, payload=None, *, endpoint=None, mode='sign', store=False):
        return json.loads(self.runtime.execute('certificate-controller', ['python', '-c', '''import json,sys,http.client
from pathlib import Path
from scripts.certificate_controller import ca_post,issued_chain,metadata,atomic
p=json.load(sys.stdin);d=Path('/state');s=json.loads((d/'state.json').read_bytes())
c=next(c for c in s['credentials'].values() if c['name']=='collector')
identity={'certificates':['/state/probe-revoked.pem'],'key':'/state/probe-revoked.key'} if p['mode'] in {'revoke','renew_revoked'} else c if p['mode']=='renew' else None
target='/1.0/revoke' if p['mode']=='revoke' else '/1.0/renew' if p['mode'] in {'renew','renew_revoked'} else '/1.0/sign'
try:
 code,response=ca_post(d,target,p['payload'],identity=identity,endpoint=p['endpoint'])
 out={'status':code}
 if code==201 and p['mode']=='sign':
  chain=issued_chain(response);out['serial']=metadata(chain)['serial']
  if p['store']:
   atomic(d/'probe-revoked.pem',chain);atomic(d/'probe-revoked.key',Path(c['key']).read_bytes())
 print(json.dumps(out))
except (OSError,ValueError,KeyError,http.client.HTTPException):print(json.dumps({'status':0}))
'''], json.dumps({'payload': payload or {}, 'endpoint': endpoint, 'mode': mode, 'store': store})))

    def same_nonce(self):
        request = self.runtime._test_used_grant
        claims = jwt.decode(request['ott'], options={'verify_signature': False})
        self.ready()
        now = self._ca_floor
        claims.update(iat=now, nbf=now - 2, exp=now + 60)
        entry, key = self.runtime._test_signer
        for host in ('ca-a', 'ca-b'):
            def signed(values):
                return {'csr': request['csr'], 'ott': jwt.encode(values, key, algorithm='ES256', headers={'kid': entry['key']['kid']})}
            self.require(self.ca(signed(claims | {'jti': secrets.token_hex(24)}), endpoint=host)['status'] == 201,
                         'persistent_authority_replay_positive_control_failed')
            self.require(self.ca(signed(claims), endpoint=host)['status'] in {400, 401, 403},
                         'persistent_authority_shared_nonce_lost')

    def database_controls(self):
        r = self.runtime
        rows = json.loads(r.sql("SELECT coalesce(json_agg(x),'[]') FROM (SELECT s.ssl,s.version,s.client_serial::text FROM pg_stat_activity a JOIN pg_stat_ssl s USING(pid) WHERE a.usename='secops_ca') x;"))
        self.require(len(rows) >= 2 and all(row['ssl'] for row in rows) and len({row['client_serial'] for row in rows}) == 2,
                     'persistent_authority_database_mtls_missing')
        self.add('both_ca_nodes_use_distinct_client_certificates_and_verified_database_tls', connections=rows)
        role = json.loads(r.sql("SELECT row_to_json(x) FROM (SELECT rolsuper,rolcreatedb,rolcreaterole,rolconfig FROM pg_roles WHERE rolname='secops_ca') x;"))
        self.require(not any(role[k] for k in ('rolsuper', 'rolcreatedb', 'rolcreaterole'))
                     and 'default_transaction_isolation=serializable' in role['rolconfig'], 'persistent_authority_database_role')
        self.add('shared_database_role_unprivileged_and_serializable')
        directory = r.state['volumes']['authority-ca-a-db']
        prefix = ['docker', 'run', '--rm', '--network', 'container:' + r.container('ca-db'), '--read-only', '--user', '10001:10001',
                  '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount', 'type=volume,src=' + directory + ',dst=/db-tls,readonly',
                  '--entrypoint', 'psql', r.state['authority_database_image_id']]
        options = {'valid': 'sslmode=verify-full&host=ca-db&hostaddr=127.0.0.1&sslrootcert=/db-tls/root.pem&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key',
                   'plaintext': 'sslmode=disable', 'no_client_certificate': 'sslmode=verify-full&host=ca-db&hostaddr=127.0.0.1&sslrootcert=/db-tls/root.pem',
                   'wrong_server_name': 'sslmode=verify-full&host=wrong-name&hostaddr=127.0.0.1&sslrootcert=/db-tls/root.pem&sslcert=/db-tls/client.pem&sslkey=/db-tls/client.key'}
        for name, option in options.items():
            result = subprocess.run([*prefix, 'postgresql://secops_ca@127.0.0.1:5432/stepca?connect_timeout=2&' + option,
                                     '-X', '-q', '-c', 'SELECT 1'], capture_output=True, timeout=12, check=False)
            self.require((result.returncode == 0) == (name == 'valid'), 'persistent_authority_database_tls_control')
            self.add('database_tls_' + name + '_positive_or_negative_control')

    def transport_admission(self):
        r = self.runtime
        result = r.preflight()
        transport = result['database_transport']
        self.require(result['verified'] and result['offline'] and transport['verified']
                     and len(transport['credentials']) == 3 and transport['minimum_remaining_seconds'] > 0,
                     'database_transport_offline_admission_missing')
        self.report['database_transport_preflight'] = result
        self.add('offline_preflight_verifies_db_transport_identity_key_permissions_and_expiry')

        def fault(mode):
            r.verify_owned_volumes()
            command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
                'type=volume,src=' + r.state['volumes']['authority-ca-a-db'] + ',dst=/a,readonly', '--mount',
                'type=volume,src=' + r.state['volumes']['authority-ca-b-db'] + ',dst=/b',
                '--entrypoint', 'python', '-i', r.state['authority_image_id'], '-c', '''import json,os,sys
from pathlib import Path
mode=json.load(sys.stdin);key=Path('/b/client.key');held=Path('/b/held.key')
if mode=='permissions':key.chmod(0o644)
elif mode=='mismatch':
 os.replace(key,held);key.write_bytes(Path('/a/client.key').read_bytes());key.chmod(0o600)
elif mode=='restore':
 if held.exists():os.replace(held,key)
 key.chmod(0o600)
else:raise ValueError('fixed_test_fault')
'''], payload=json.dumps(mode))

        for mode in ('permissions', 'mismatch'):
            self.stopped_gate('database_private_key_' + mode + '_refuses_all_services_before_start',
                              lambda mode=mode: fault(mode), lambda: fault('restore'),
                              expected='database_transport_preflight_failed')
        self.ready()

    def force_due(self, part):
        backend = self.backend
        backend.runtime.verify_owned_volumes()
        # Test-only fault injection into last_at; policy periods stay unchanged.
        command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
            'type=volume,src=' + backend.profile['volumes']['vault'] + ',dst=/vault', '--entrypoint', 'python', '-i',
            backend.profile['image'], '-c', "import json,sys;from pathlib import Path;from scripts.certificate_controller import save;p=Path('/vault/state.json');s=json.loads(p.read_bytes());s['last_at'][json.load(sys.stdin)]=0;save(p,s)"], payload=json.dumps(part))
        state = self.runtime.journal()
        state['next_due_at'] = 0
        from scripts.certificate_controller import save
        save(self.runtime.journal_path, state)

    def drive(self, epoch, *, interrupt=False):
        r = self.runtime
        deadline, restarted = time.monotonic() + 540, False
        with lease(r.directory):
            coordinator = Coordinator(self.backend.profile, r.directory, self.backend)
            while time.monotonic() < deadline:
                coordinator.tick()
                state = coordinator.state
                if interrupt and not restarted and state['phase'] == 'prepared':
                    digest = custody.digest(state['plan'])
                    command(['docker', 'restart', r.container('certificate-controller')])
                    coordinator = Coordinator(self.backend.profile, r.directory, self.backend)
                    self.require(custody.digest(coordinator.state['plan']) == digest, 'persistent_authority_pending_plan_changed')
                    restarted = True
                    self.add('host_coordinator_recreation_and_leaf_controller_restart_reuse_same_signed_pending_plan')
                if state['phase'] == 'idle' and state['epoch'] == epoch:
                    self.pause()
                    record = copy.deepcopy(state['history'][-1])
                    custody_status = self.backend.custodian('status')
                    self.require(custody_status == {'epoch': epoch, 'pending': False, 'only_current_sealed_bundle': True,
                        'ca_private_key_files': 1, 'server_signing_key_files': 11}, 'persistent_authority_retired_secret_files_remain')
                    record['custody_after_commit'] = custody_status
                    self.add('authority_epoch_' + str(epoch) + '_keeps_only_current_sealed_bundle_issuer_key_and_eleven_signers')
                    self.report.setdefault('ceremonies', []).append(record)
                    return record
                time.sleep(.3)
        raise RuntimeFailure('persistent_authority_ceremony_timeout')

    def old_root(self, *, save=False):
        r = self.runtime
        return json.loads(r.execute('certificate-controller', ['python', '-c', '''import json,time
from pathlib import Path
from scripts.certificate_controller import atomic,metadata
from scripts.mtls_transport import request
d=Path('/state');p=Path('/managed/operator-tls/core.json')
if json.loads(__import__('sys').stdin.read()):
 c=json.loads(p.read_bytes());root=p.parent
 atomic(d/'authority-old-core.pem',(root/c['cert']).read_bytes());atomic(d/'authority-old-core.key',(root/c['key']).read_bytes())
 c.update(ca='root.pem',cert='authority-old-core.pem',key='authority-old-core.key');atomic(d/'authority-old-core.json',json.dumps(c))
 print(json.dumps({'saved':True}));raise SystemExit
alive=metadata((d/'authority-old-core.pem').read_text())['not_after']>time.time()+5
c=json.loads((d/'authority-old-core.json').read_bytes());c['server_pins']=json.loads(p.read_bytes())['server_pins']
atomic(d/'authority-old-core.json',json.dumps(c))
try:code,_=request(d/'authority-old-core.json','/health/live',None,{},method='GET')
except (OSError,ValueError):code=0
print(json.dumps({'status':code,'unexpired':alive}))
'''], json.dumps(save)))

    def stopped_gate(self, label, mutate, restore, *, expected=None):
        r = self.runtime
        r.compose('stop', '--timeout', '2')
        mutate()
        try:
            try:
                r.up()
            except (ValueError, RuntimeFailure) as error:
                if expected:
                    self.require(str(error) == expected, 'persistent_authority_wrong_admission_denial')
            else:
                raise RuntimeFailure('persistent_authority_drift_started_services')
            self.require(not any(row['running'] for row in r.status()['services'].values()), 'persistent_authority_drift_started_service')
            self.add(label)
        finally:
            restore()
        r.up()

    def run(self):
        r = self.runtime
        r.up()
        self.pause()
        self.ready()
        self.backend = GraphBackend(r, json.loads(r.profile_path.read_bytes()))
        for name, key in {'project': 'project', 'image_id': 'image_id', 'source_commit': 'source_commit', 'source_dirty': 'source_dirty',
                'source_input_sha256': 'source_sha256', 'configuration_sha256': 'configuration_sha256', 'image_source_verified': 'image_source_verified',
                'release_lock': 'release', 'release_image_payload_verified': 'release_image_payload_verified'}.items():
            self.report[name] = copy.deepcopy(r.state[key])
        self.report['authority'] = {key: copy.deepcopy(r.state[key]) for key in ('authority_image_id', 'authority_tools', 'authority_binary_sha256',
            'authority_database_image_id', 'authority_database_reference', 'authority_database_tools')}
        spec = r.definition(r.state['project'], 'app', 'nginx')
        self.require(len(spec['services']) == 18 and len(spec['networks']) == 10 and len(spec['volumes']) == self.expected_volumes,
                     'persistent_authority_topology')
        self.add('eighteen_services_ten_internal_networks_' + str(self.expected_volumes) + '_owned_volumes')
        for name in r.services:
            info = self.inspect(name)
            self.require(info['Config']['User'] == '10001:10001' and info['HostConfig']['ReadonlyRootfs']
                         and not info['HostConfig'].get('PortBindings') and not any(m['Destination'] == '/vault' or m['Type'] == 'bind' for m in info['Mounts']),
                         'persistent_authority_online_custody_exposure')
        self.add('all_online_services_non_root_read_only_without_vault_socket_or_host_binds')
        initial = r.controller_status()
        self.require(len(initial['credentials']) == 39 and len(initial['server_observations']) == 11, 'persistent_authority_initial_inventory')
        self.add('all_39_identities_enrolled_and_eleven_native_servers_observed')
        self.transport_admission()
        current = json.loads(r.execute('certificate-controller', ['python', '-c', "import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next({'id':u,'csr':c['csr']} for u,c in s['credentials'].items() if c['name']=='collector'))) "]))
        self.csr, self.collector = current['csr'], current['id']
        self.database_controls()
        self.same_nonce()
        self.add('current_iat_new_nonce_accepted_and_consumed_nonce_denied_by_both_nodes')
        races = []
        for _ in range(6):
            payload = self.fresh()
            codes = json.loads(r.execute('certificate-controller', ['python', '-c', '''import json,sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from scripts.certificate_controller import ca_post
p=json.load(sys.stdin)
with ThreadPoolExecutor(max_workers=2) as pool:codes=list(pool.map(lambda host:ca_post(Path('/state'),'/1.0/sign',p,endpoint=host)[0],['ca-a','ca-b']))
print(json.dumps(codes))'''], json.dumps(payload)))
            self.require(codes.count(201) == 1 and all(c in {201, 400, 401, 403, 500} for c in codes), 'persistent_authority_nonce_double_winner')
            races.append(codes)
        self.add('six_simultaneous_cross_node_nonce_races_have_exactly_one_winner', races=races)
        issued = self.ca(self.fresh(), endpoint='ca-a', store=True)
        self.require(issued['status'] == 201 and self.ca({'serial': issued['serial'], 'passive': True}, endpoint='ca-a', mode='revoke')['status'] == 200,
                     'persistent_authority_revocation_control')
        self.require(self.ca(endpoint='ca-b', mode='renew_revoked')['status'] in {401, 403}
                     and self.ca(endpoint='ca-b', mode='renew')['status'] == 201, 'persistent_authority_shared_revocation')
        self.add('revocation_on_primary_denies_same_unexpired_certificate_on_secondary_with_current_identity_control')
        ca_a, ca_b, db = (r.container(n) for n in ('ca', 'ca-secondary', 'ca-db'))
        for fault in ('stop', 'pause', 'disconnect'):
            network = r.state['project'] + '_ca'
            command(['docker', 'network', 'disconnect', network, ca_a] if fault == 'disconnect' else
                    ['docker', fault, *(['--time', '2'] if fault == 'stop' else []), ca_a])
            try:
                self.require(self.ca(self.fresh())['status'] == 201 and self.ca(mode='renew')['status'] == 201, 'persistent_authority_primary_failover')
                self.add('fresh_issuance_and_managed_mtls_renewal_survive_primary_' + fault)
                if fault == 'stop':
                    before = r.controller_status()
                    original = r.controller_configuration()['renew_before']
                    self.configure(paused=False, renew_before={c['name']: 3599 if c['name'].startswith('renew-') else 1199 for c in before['credentials'].values()})
                    self.wait(lambda before=before: (s := r.controller_status())['phase'] is None and all(c['generation'] > before['credentials'][uid]['generation'] for uid, c in s['credentials'].items()),
                              'persistent_authority_survivor_rekey_failed', timeout=240)
                    self.pause()
                    self.configure(renew_before=original)
                    self.add('all_39_leaf_keys_and_pins_rotate_with_only_secondary_ca_available')
            finally:
                command(['docker', 'network', 'connect', '--alias', 'ca', '--alias', 'ca-a', network, ca_a] if fault == 'disconnect' else
                        ['docker', 'start' if fault == 'stop' else 'unpause', ca_a])
            self.ready(issuance=True)
        for service, nodes in [('both_ca', [ca_a, ca_b]), ('database', [db])]:
            for node in nodes:
                command(['docker', 'stop', '--time', '2', node])
            try:
                self.require(self.ca(self.fresh())['status'] != 201 and r.probe({'profile': 'core', 'path': '/health/live', 'method': 'GET'})['status'] == 200,
                             'persistent_authority_outage_fail_closed')
                self.add(service + '_outage_denies_new_issuance_while_existing_protected_access_remains_available')
            finally:
                for node in nodes:
                    command(['docker', 'start', node])
            self.ready(issuance=True)
        command(['docker', 'restart', '--time', '2', ca_a, ca_b, db])
        self.ready(issuance=True)
        self.same_nonce()
        self.require(self.ca(endpoint='ca-b', mode='renew_revoked')['status'] in {401, 403} and self.ca(mode='renew')['status'] == 201,
                     'persistent_authority_database_security_state_lost')
        self.add('both_ca_and_database_restart_preserve_nonce_and_revocation_state_with_current_positive_controls')
        self.old_root(save=True)
        old_positive = self.old_root()
        self.require(old_positive['unexpired'] and old_positive['status'] == 200, 'persistent_authority_old_client_positive_control')
        first = self.drive(1, interrupt=True)
        self.require(first['changed'] == {'root': True, 'issuer': True, 'jwk': True}, 'persistent_authority_all_timer_dependencies')
        self.require(first['evidence']['old_jwks']['total_denied'] == 100, 'persistent_authority_old_jwk_coverage')
        self.require(first['evidence']['custody'] == {'uid': 10001, 'interfaces': ['lo'], 'vault_mode': 384, 'docker_socket': False},
                     'persistent_authority_custodian_isolation')
        self.add('authority_secret_job_runs_uid_10001_network_none_mode_0600_without_docker_socket')
        self.add('root_issuer_and_all_50_jwks_rotate_on_both_nodes_after_all_39_leaves_migrate')
        old = self.old_root()
        self.require(old['unexpired'] and old['status'] == 0 and r.probe({'profile': 'core', 'path': '/health/live', 'method': 'GET'})['status'] == 200,
                     'persistent_authority_old_root_not_rejected_at_tls')
        self.add('unexpired_old_root_client_rejected_at_tls_with_new_client_positive_control')
        self.force_due('jwk')
        second = self.drive(2)
        self.require(second['changed'] == {'root': False, 'issuer': False, 'jwk': True} and second['evidence']['old_jwks']['total_denied'] == 100,
                     'persistent_authority_jwk_only_timer')
        self.add('jwk_only_timer_rotates_all_50_keys_and_both_nodes_deny_all_retired_jwks')
        self.require(self.rpc('revoke', id=self.collector)['revoked'], 'persistent_authority_retirement_revoke')
        self.configure(disabled=[self.collector])
        profile = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        retired = r.controller_status()['credentials'][self.collector]
        self.require(profile['peers'].pop(retired['fingerprint'], None) == 'collector', 'persistent_authority_retirement_binding')
        r.write_volume('gateway-tls', {'profile.json': json.dumps(profile)})
        self.force_due('issuer')
        third = self.drive(3)
        self.require(third['changed'] == {'root': False, 'issuer': True, 'jwk': False}, 'persistent_authority_issuer_only_timer')
        current = r.controller_status()
        self.require(current['credentials'][self.collector]['fingerprint'] == retired['fingerprint']
                     and all(c.get('authority_epoch') == 3 for uid, c in current['credentials'].items() if uid != self.collector),
                     'persistent_authority_retired_identity_reissued')
        self.add('issuer_only_timer_migrates_38_active_identities_without_reissuing_retired_collector')
        event = 'authority-retired-' + secrets.token_hex(5)
        self.require(self.collector_request(event)['status'] in {0, 403} and self.receipt(event)['status'] == 404,
                     'persistent_authority_retired_identity_reached_inbox')
        self.add('retired_collector_and_removed_peer_pin_stay_denied_after_authority_rotations')
        self.backend.before_authority_tick()
        snapshot = r.controller_status()
        r.down()
        r.up()
        self.backend = GraphBackend(r, json.loads(r.profile_path.read_bytes()))
        self.require({u: c['fingerprint'] for u, c in r.controller_status()['credentials'].items()} ==
                     {u: c['fingerprint'] for u, c in snapshot['credentials'].items()}, 'persistent_authority_resume_reissued')
        self.add('clean_down_up_preserves_signed_epoch_certificates_database_and_retired_identity')
        original_ca = r.journal()['history'][-1]['plan']['final_ca']
        changed = copy.deepcopy(original_ca)
        changed['authority']['disableIssuedAtCheck'] = True
        self.stopped_gate('unsigned_ca_policy_change_refuses_all_services_before_start',
            lambda: r.write_volume('ca-state', {'ca.json': json.dumps(changed)}),
            lambda: r.write_volume('ca-state', {'ca.json': json.dumps(original_ca)}))
        original = r.journal_path.read_bytes()
        bad = json.loads(original)
        bad['history'][-1]['plan']['proof'] = 'AAAA'
        self.stopped_gate('tampered_signed_authority_history_refuses_all_services_before_start',
            lambda: r.journal_path.write_text(json.dumps(bad)), lambda: r.journal_path.write_bytes(original))
        # Preserve the original table under another name in the same Linux DB;
        # neither host startup nor the CA entrypoint may recreate it empty.
        r.compose('stop', '--timeout', '2', *[n for n in r.services if n != 'ca-db'])
        r.sql('ALTER TABLE used_ott RENAME TO held_used_ott;')
        try:
            try:
                r.up()
            except (RuntimeFailure, ValueError):
                pass
            else:
                raise RuntimeFailure('persistent_authority_empty_database_started')
            self.require(not any(v['running'] for k, v in r.status()['services'].items() if k != 'ca-db'), 'persistent_authority_db_loss_started_ca')
            self.add('missing_nonce_table_refuses_host_start_before_any_ca_or_workload')
            node = r.container('ca')
            command(['docker', 'start', node])
            self.wait(lambda: json.loads(command(['docker', 'inspect', node]))[0]['State']['ExitCode'] == 1,
                      'persistent_authority_ca_entrypoint_ignored_database_loss', timeout=20)
            command(['docker', 'stop', '--time', '2', node])
            self.require(r.sql("SELECT to_regclass('public.used_ott') IS NULL;") == 't', 'persistent_authority_db_recreated')
            self.add('ca_container_entrypoint_refuses_empty_database_even_without_host_preflight')
        finally:
            r.sql('ALTER TABLE held_used_ott RENAME TO used_ott;')
        r.up()
        self.ready()
        control = next(uid for uid, c in r.controller_status()['credentials'].items() if c['name'] == 'core-operator')
        self.wait(lambda: self.rpc('renew_attempt', id=control)['allowed'], 'persistent_authority_restore_positive_control')
        self.require(not self.rpc('renew_attempt', id=self.collector)['allowed'], 'persistent_authority_revocation_lost_after_restore')
        self.add('original_database_restore_retains_retired_collector_revocation_and_signed_epoch')
        self.report['final_certificates'] = r.controller_status()
        self.report['final_epoch'] = r.journal()['epoch']
        self.report['completed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/persistent-authority-acceptance')
    args = parser.parse_args()
    checks = Checks(args.directory)
    try:
        checks.run()
    except (RuntimeFailure, LifecycleError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, failure=str(error) if isinstance(error, (RuntimeFailure, LifecycleError)) else type(error).__name__)
        checks.record_authority_failure()
    finally:
        try:
            checks.cleanup()
        except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            checks.report.update(completed=False, cleanup_failed=True)
            checks.save()
    print(json.dumps({'completed': checks.report['completed'], 'checks': len(checks.report['checks'])}))
    return 0 if checks.report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
