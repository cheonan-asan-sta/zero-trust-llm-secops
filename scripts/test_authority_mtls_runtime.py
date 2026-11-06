"""Real CA integration acceptance on the persistent monitored mTLS graph."""

import argparse
import copy
import json
import secrets
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

import jwt

from scripts import authority_runtime_assets as assets
from scripts.authority_mtls_runtime import AuthorityRuntime
from scripts.certificate_authority import bootstrap_token
from scripts.continuous_mtls_assets import DEVICES, OTHER
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.test_monitored_mtls_runtime import MonitoredChecks


def certificate_probe(profile, certificate, key, payload, *, target='/zero-trust/signals/inbox', method='POST'):
    """Test only: preserve the production loader's Path and sibling-asset rules."""
    from scripts import mtls_transport as tls
    profile = Path(profile)
    cfg = json.loads(profile.read_bytes())
    with tempfile.TemporaryDirectory(prefix='ca-probe-') as directory:
        folder = Path(directory)
        for name, source in [('ca.pem', Path(tls.asset(profile, cfg['ca']))),
                             ('identity.pem', Path(certificate)), ('identity.key', Path(key))]:
            body = source.read_bytes()
            if len(body) > 65536:
                raise ValueError('acceptance_probe_asset_size')
            (folder / name).write_bytes(body)
            (folder / name).chmod(0o600)
        cfg.update(ca='ca.pem', cert='identity.pem', key='identity.key')
        path = folder / 'profile.json'
        path.write_text(json.dumps(cfg))
        status, _ = tls.request(path, target, payload, {'X-API-Key': 'synthetic-invalid-api-key'}, method=method)
        return status


class AcceptanceRuntime(AuthorityRuntime):
    """Keep one limited signer in test-driver RAM for paired issuance controls."""
    def helper(self, program, payload=None, **options):
        result = super().helper(program, payload, **options)
        if program == ['-m', 'scripts.certificate_controller', 'init']:
            self._acceptance_inventory = json.loads(result)
        return result

    def write_volume(self, label, files):
        if label == 'certificate-state' and 'bootstrap.json' in files:
            grants = json.loads(files['bootstrap.json'])
            uid = next(uid for uid, c in self._acceptance_inventory.items() if c['name'] == 'collector')
            credential = self._acceptance_inventory[uid]
            entry, key = self._bootstrap_provisioners['collector-clientAuth']
            self._acceptance_signer = (entry, key)  # Test-only RAM; never a runtime/volume field.
            started = command(['docker', 'inspect', '--format', '{{.State.StartedAt}}', self.container('ca')]).strip()
            self._ca_container_started = int(datetime.fromisoformat(started).timestamp())
            self._pre_start_grant = {'csr': credential['csr'], 'ott': bootstrap_token(entry, key,
                credential['csr'], seconds=3600, now=self._ca_container_started - 1)}
            self._consumed_grant = {'csr': self._acceptance_inventory[uid]['csr'], 'ott': grants[uid]['token']}
        return super().write_volume(label, files)


class AuthorityChecks(MonitoredChecks):
    def __init__(self, directory):
        super().__init__(directory, runtime_class=AcceptanceRuntime)
        self.report['schema'] = 'authority-continuous-mtls-verification-1'

    def record_authority_failure(self):
        # Diagnostics must preserve the original failure, including startup errors
        # raised inside Runtime.up before the first acceptance assertion.
        try:
            from scripts.authority_diagnostics import collect
            if 'authority_failure_diagnostics' not in self.report:
                self.report['authority_failure_diagnostics'] = collect(self.runtime)
            self.record_monitoring_failure('authority_runtime_failure')
            self.save()
        except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, subprocess.SubprocessError):
            self.report.setdefault('authority_failure_diagnostics', {'snapshot': {'available': False}})

    def wait(self, predicate, label, timeout=90):
        try:
            self.runtime.wait(predicate, timeout=timeout)
        except RuntimeFailure:
            self.record_monitoring_failure(label)
            raise RuntimeFailure(label) from None

    def rpc(self, operation, **data):
        return json.loads(self.runtime.execute('certificate-controller',
            ['python', '-m', 'scripts.certificate_controller', 'rpc'], json.dumps({'operation': operation, **data})))

    def configure(self, **changes):
        cfg = self.runtime.controller_configuration()
        cfg.update(changes)
        self.runtime.write_volume('certificate-state', {'config.json': json.dumps(cfg)})
        return cfg

    def pause(self):
        self.configure(paused=True)
        self.wait(lambda: (s := self.runtime.controller_status())['paused'] and s['phase'] is None,
                  'authority_pause_not_acknowledged', timeout=120)
        return self.runtime.controller_status()

    def public_keys(self):
        program = """import hashlib,json
from pathlib import Path
from cryptography.hazmat.primitives import serialization as s
print(json.dumps({str(p):hashlib.sha256(s.load_pem_private_key(p.read_bytes(),password=None).public_key().public_bytes(s.Encoding.DER,s.PublicFormat.SubjectPublicKeyInfo)).hexdigest() for p in Path('/managed').rglob('*.key')}))
"""
        return json.loads(self.runtime.helper(['-c', program]))

    def timer_round(self, before):
        self.configure(paused=False, renew_before={c['name']: 3590 if c['name'].startswith('renew-') else 1190
                                                   for c in before['credentials'].values()})
        self.wait(lambda: (s := self.runtime.controller_status())['phase'] is None
                  and all(c['generation'] > before['credentials'][uid]['generation']
                          for uid, c in s['credentials'].items()), 'authority_timer_round_incomplete', timeout=180)
        after = self.pause()
        self.require(all(c['fingerprint'] != before['credentials'][uid]['fingerprint'] for uid, c in after['credentials'].items()),
                     'authority_reused_old_leaf')
        return after

    def replay_denied(self):
        r = self.runtime
        claims = jwt.decode(r._consumed_grant['ott'], options={'verify_signature': False})
        health = r.authority_health()
        self.require(health['healthy'], 'authority_replay_control_ca_not_healthy')
        now = health['server_time']
        claims.update(iat=now, nbf=now - 2, exp=now + 60)
        entry, key = r._acceptance_signer
        def signed(values):
            return jwt.encode(values, key, algorithm='ES256', headers={'kid': entry['key']['kid']})
        # Fresh iat avoids CA-start rejection masking a missing replay DB. The
        # positive and negative requests differ only in their one-time jti.
        positive = self.rpc('ca_post', path='/1.0/sign', payload={
            'csr': r._consumed_grant['csr'], 'ott': signed(claims | {'jti': secrets.token_hex(24)})})
        self.require(positive['status'] == 201, 'authority_replay_fresh_nonce_control_failed')
        result = self.rpc('ca_post', path='/1.0/sign', payload={'csr': r._consumed_grant['csr'], 'ott': signed(claims)})
        self.require(result['status'] in {400, 401, 403}, 'authority_bootstrap_replay_accepted')
        return result['status']

    def pre_start_denied(self):
        r = self.runtime
        claims = jwt.decode(r._pre_start_grant['ott'], options={'verify_signature': False})
        self.require(claims['exp'] > time.time() + 5 and claims['iat'] < r._ca_container_started,
                     'authority_pre_start_control_not_unexpired_or_old')
        denied = self.rpc('ca_post', path='/1.0/sign', payload=r._pre_start_grant)
        health = r.authority_health()
        self.require(health['healthy'], 'authority_pre_start_control_ca_not_healthy')
        entry, key = r._acceptance_signer
        current = jwt.encode(claims | {'iat': health['server_time']}, key, algorithm='ES256', headers={'kid': entry['key']['kid']})
        control = self.rpc('ca_post', path='/1.0/sign', payload={'csr': r._pre_start_grant['csr'], 'ott': current})
        self.require(denied['status'] in {400, 401, 403} and control['status'] == 201,
                     'authority_pre_start_iat_boundary_not_proven')
        self.add('unexpired_pre_ca_iat_denied_same_nonce_and_csr_current_iat_accepted')

    def collector_request(self, event_id):
        signed = self.signed_observation(event_id)
        return json.loads(self.runtime.execute('collector', ['python', '-c', """import json,sys
from pathlib import Path
from scripts.mtls_transport import request
try:
 status,body=request(Path('/tls/profile.json'),'/zero-trust/signals/inbox',json.load(sys.stdin),{'X-API-Key':Path('/auth/api-key.txt').read_text().strip()})
 print(json.dumps({'status':status}))
except (OSError,ValueError):print(json.dumps({'status':0}))
"""], json.dumps(signed)))

    def prior_leaf_denial(self, certificate):
        r = self.runtime
        r.write_volume('certificate-state', {'prior-collector.pem': certificate})
        result = json.loads(r.execute('certificate-controller', ['python', '-c', """import json,time,sys
from pathlib import Path
from scripts.certificate_controller import metadata
from scripts.test_authority_mtls_runtime import certificate_probe
statuses={};body=json.load(sys.stdin)
for label,cert in [('current','/managed/collector-tls/collector.pem'),('prior','/state/prior-collector.pem')]:
 statuses[label]=certificate_probe('/managed/collector-tls/profile.json',cert,'/managed/collector-tls/collector.key',body)
statuses['prior_unexpired']=metadata(Path('/state/prior-collector.pem').read_text())['not_after']>time.time()
print(json.dumps(statuses))
"""], json.dumps(self.signed_observation('ca-old-leaf-probe-' + secrets.token_hex(5)))))
        self.require(result == {'current': 401, 'prior': 403, 'prior_unexpired': True}, 'authority_old_leaf_denial_not_proven')
        self.add('still_valid_prior_leaf_rejected_with_current_leaf_positive_transport_control')

    def renewal_identity_no_role(self):
        result = json.loads(self.runtime.execute('certificate-controller', ['python', '-c', """import json
from pathlib import Path
from scripts.test_authority_mtls_runtime import certificate_probe
status=certificate_probe('/managed/operator-tls/core.json','/managed/renewal-tls/renew-core-a.pem','/managed/renewal-tls/renew-core-a.key',None,target='/health/live',method='GET')
print(json.dumps({'status':status}))
"""]))
        self.require(result['status'] == 403 and self.runtime.probe({'profile':'core','path':'/health/live'})['status'] == 200,
                     'authority_renewal_identity_received_business_role')
        self.add('valid_ca_renewal_identity_has_no_business_role_with_authorized_control')

    def ca_volume(self, program):
        r = self.runtime
        return json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
            '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/data:size=1m',
            '--mount', f"type=volume,src={r.state['volumes']['ca-state']},dst=/ca",
            '--entrypoint', 'python', r.state['authority_image_id'], '-c', program]))

    def database_loss_gate(self, revoked, control):
        r = self.runtime
        digest = """from pathlib import Path
import hashlib,json
d=Path('/ca/db')
files={p.relative_to(d).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.rglob('*')) if p.is_file()}
print(json.dumps({'sha256':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()}))
"""
        original = self.ca_volume(digest)
        self.ca_volume("""from pathlib import Path
import json
source=Path('/ca/db');target=Path('/ca/db-preserved-for-acceptance')
if not source.is_dir() or source.is_symlink() or target.exists():raise ValueError('ca_db_scope')
source.rename(target)
print(json.dumps({'preserved':True}))
""")
        try:
            try:
                r.up()
            except RuntimeFailure as error:
                self.require(str(error) == 'authority_database_required', 'authority_wrong_db_loss_denial')
            else:
                raise RuntimeFailure('authority_missing_ca_db_started_services')
            self.require(all(not value['running'] for value in r.status()['services'].values()), 'authority_db_loss_started_workloads')
            self.add('missing_ca_database_refuses_host_start_before_any_service')
            # Bypass the host driver as Docker's own restart manager would.
            # The container entrypoint must independently refuse a fresh DB.
            r.compose('up', '--detach', 'ca')
            self.wait(lambda: self.inspect('ca')['RestartCount'] >= 1, 'authority_ca_missing_db_did_not_fail_closed')
            self.require(not self.ca_volume("from pathlib import Path;import json;print(json.dumps({'exists':Path('/ca/db').exists()}))")['exists'],
                         'authority_ca_silently_recreated_empty_database')
            self.add('ca_container_entrypoint_refuses_db_recreation_even_without_host_preflight')
        finally:
            r.compose('stop', '--timeout', '2', 'ca')
            self.ca_volume("""from pathlib import Path
import json
source=Path('/ca/db-preserved-for-acceptance');target=Path('/ca/db')
if not source.is_dir() or source.is_symlink() or target.exists():raise ValueError('ca_db_restore_scope')
source.rename(target)
print(json.dumps({'restored':True}))
""")
        self.require(self.ca_volume(digest) == original, 'authority_preserved_db_changed')
        r.up()
        self.wait(lambda: self.rpc('renew_attempt', id=control)['allowed'], 'authority_restored_db_control_not_ready')
        self.require(not self.rpc('renew_attempt', id=revoked)['allowed'], 'authority_restored_db_lost_revocation')
        self.add('same_preserved_ca_db_resumes_with_positive_control_and_revocation_still_enforced')

    def run(self):
        r = self.runtime
        r.up()
        for name, state_name in {'project': 'project', 'image_id': 'image_id', 'source_commit': 'source_commit',
                                 'source_dirty': 'source_dirty', 'source_input_sha256': 'source_sha256',
                                 'configuration_sha256': 'configuration_sha256', 'image_source_verified': 'image_source_verified',
                                 'release_lock': 'release', 'release_image_payload_verified': 'release_image_payload_verified'}.items():
            self.report[name] = copy.deepcopy(r.state[state_name])
        self.report['authority'] = {name: copy.deepcopy(r.state[name]) for name in (
            'authority_image_id', 'authority_tools', 'authority_binary_sha256', 'authority_base_layers_sha256',
            'authority_configuration_sha256', 'authority_public_sha256')}
        self.report['monitoring'] = {'tools': r.state['monitoring_tools'], 'image_id': r.state['monitoring_image_id'],
                                     'binary_sha256': r.state['monitoring_binary_sha256']}
        before = self.pause()
        self.require(len(before['credentials']) == 39 and all(c['generation'] >= 1 for c in before['credentials'].values()),
                     'authority_initial_enrollment_missing')
        self.add('all_39_registered_identities_enrolled_by_real_ca', generations={uid: c['generation'] for uid, c in before['credentials'].items()})
        files = json.loads(r.helper(['-c', "from pathlib import Path;import json;print(json.dumps([p.name for p in Path('/state').iterdir()]))"]))
        self.require('bootstrap.json' not in files and 'root.key' not in files and 'issuer.key' not in files,
                     'authority_controller_bootstrap_or_ca_private_key_retained')
        self.add('used_bootstrap_grants_erased_and_no_ca_signing_key_on_controller')
        self.add('used_exact_csr_bootstrap_replay_denied', status=self.replay_denied())
        self.pre_start_denied()

        spec = r.definition(r.state['project'], 'app', 'nginx')
        for name in r.services:
            info = self.inspect(name)
            host = info['HostConfig']
            self.require(info['Config']['User'] == '10001:10001' and host['ReadonlyRootfs']
                         and 'ALL' in host['CapDrop'] and 'no-new-privileges:true' in host['SecurityOpt']
                         and not host.get('PortBindings') and all(m['Type'] != 'bind' for m in info['Mounts']),
                         'authority_actual_service_hardening')
        controller = self.inspect('certificate-controller')
        actual = {v['Name'] for v in controller['Mounts'] if v['Type'] == 'volume'}
        self.require(not actual & {r.state['volumes'][v] for v in ('ca-state', 'data', 'operator-auth', 'collector-state', 'core-auth')},
                     'authority_controller_has_business_authority')
        self.require(len(spec['networks']) == 9 and all(v['internal'] for v in spec['networks'].values()), 'authority_network_definition')
        self.add('sixteen_hardened_services_with_isolated_ca_and_no_business_db_or_api_keys_on_controller')
        key_hashes = self.public_keys()
        prior_leaf = r.execute('collector', ['python', '-c', "from pathlib import Path;print(Path('/tls/collector.pem').read_text())"])
        renewed = self.timer_round(before)
        self.require(self.public_keys() == key_hashes, 'authority_same_key_renewal_changed_private_key')
        self.add('all_39_identities_renew_by_timer_without_private_key_replacement')
        servers = {c['name']: c for c in renewed['credentials'].values() if c['purpose'] == 'serverAuth'}
        self.require(set(servers) == set(assets.SERVERS) and all(
            renewed['server_observations'][name]['fingerprint'] == c['fingerprint'] for name, c in servers.items()),
            'authority_current_native_tls_observation_missing')
        self.add('all_eleven_native_nginx_go_servers_present_current_renewed_leaf', observations=renewed['server_observations'])
        pins = json.loads(r.helper(['-c', """import json,sys
from pathlib import Path
cfg=json.loads(Path('/state/config.json').read_text())
text=json.dumps([json.loads(Path(p).read_text()) for p in cfg['policies']])
print(json.dumps({'old_pin_present':any(fp in text for fp in json.load(sys.stdin))}))
"""], json.dumps([c['fingerprint'] for c in before['credentials'].values()])))
        self.require(not pins['old_pin_present'], 'authority_old_pin_not_retired')
        self.add('old_leaf_pins_retired_after_reload_ack_and_native_tls_probes')
        self.prior_leaf_denial(prior_leaf)
        self.renewal_identity_no_role()
        self.access(self.mint('ca-renewed-document', user_id=OTHER, device_id=DEVICES[1]), True,
                    'document_enforcement_succeeds_after_ca_renewal')
        self.scrape = r.execute('exporter', ['python', '-c', "from pathlib import Path;print(Path('/auth/scrape.token').read_text())"]).strip()
        self.notify = r.execute('sink', ['python', '-c', "from pathlib import Path;print(Path('/tls/notify.token').read_text())"]).strip()
        self.wait(lambda: 'secops_signal_collection_success 1' in self.metric(), 'authority_metrics_after_renewal')
        self.add('authenticated_metrics_work_after_ca_renewal')
        self.require(self.reader_request(method='POST')['status'] == 403 and self.reader_request(bad_key=True)['status'] == 401,
                     'authority_issued_viewer_crossed_app_authorization_boundary')
        self.add('ca_issued_viewer_still_requires_api_auth_and_cannot_write')
        for target in ('exporter', 'prometheus'):
            result = self.refused_transport(target, 'wrong-role')
            self.require(result['denied'], 'authority_issued_wrong_role_was_admitted')
        self.add('ca_issued_wrong_role_denied_by_native_and_go_monitoring_services')
        floor = self.begin_episode()
        worker = r.container('worker')
        command(['docker', 'stop', '--time', '2', worker])
        event_id = 'ca-backlog-' + secrets.token_hex(5)
        try:
            self.submit(event_id)
            firing = self.await_episode('C01SignalQueueBacklog', 'firing', floor)
            self.add('fresh_backlog_notification_delivered_with_renewed_credentials')
        finally:
            command(['docker', 'start', worker])
        self.wait(lambda: self.receipt(event_id).get('body', {}).get('state') == 'completed', 'authority_backlog_not_processed')
        self.await_episode('C01SignalQueueBacklog', 'resolved', floor, firing)
        self.add('same_post_renewal_alert_episode_resolves_after_worker_recovery')

        ca = r.container('ca')
        command(['docker', 'stop', '--time', '2', ca])
        self.access(self.mint('ca-offline-document', user_id=OTHER, device_id=DEVICES[1]), True,
                    'valid_workload_mtls_continues_during_ca_outage')
        outage_before = r.controller_status()
        self.configure(paused=False)
        self.wait(lambda: all(c['failures'] > outage_before['credentials'][uid]['failures']
                             for uid, c in r.controller_status()['credentials'].items()),
                  'authority_outage_did_not_attempt_renewal', timeout=120)
        failed = self.pause()
        self.require(all(c['fingerprint'] == outage_before['credentials'][uid]['fingerprint']
                         for uid, c in failed['credentials'].items()), 'authority_outage_replaced_leaf')
        self.add('ca_outage_records_renewal_failure_without_self_signed_or_plaintext_fallback')
        command(['docker', 'start', ca])
        command(['docker', 'restart', r.container('certificate-controller')])
        self.wait(lambda: r.controller_status()['paused'], 'authority_restart_pause_not_preserved')
        restored = self.timer_round(failed)
        self.add('ca_and_controller_restart_resume_renewal_from_persisted_state_without_bootstrap')
        self.add('bootstrap_replay_remains_denied_after_ca_db_restart', status=self.replay_denied())

        collector = next(uid for uid, c in restored['credentials'].items() if c['name'] == 'collector')
        control = next(uid for uid, c in restored['credentials'].items() if c['name'] == 'core-operator')
        allowed_id = 'ca-before-retirement-' + secrets.token_hex(5)
        self.require(self.collector_request(allowed_id)['status'] == 202, 'authority_collector_positive_transport_control_failed')
        self.wait(lambda: self.receipt(allowed_id).get('body', {}).get('state') == 'completed', 'authority_collector_control_not_processed')
        self.add('same_collector_transport_admits_signed_observation_before_retirement')
        self.require(self.rpc('revoke', id=collector).get('revoked') is True, 'authority_client_revocation_failed')
        self.require(not self.rpc('renew_attempt', id=collector)['allowed'] and self.rpc('renew_attempt', id=control)['allowed'],
                     'authority_revoked_client_renewal_or_control_wrong')
        self.add('ca_revocation_denies_client_renewal_with_positive_control')
        command(['docker', 'restart', ca])
        self.wait(lambda: self.rpc('renew_attempt', id=control)['allowed'], 'authority_ca_restart_control_not_ready')
        self.require(not self.rpc('renew_attempt', id=collector)['allowed'], 'authority_ca_revocation_db_lost')
        self.add('ca_database_restart_preserves_revoked_client_renewal_denial')
        cfg = self.configure(disabled=[collector])
        policy = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        retired_fp = restored['credentials'][collector]['fingerprint']
        self.require(policy['peers'].pop(retired_fp, None) == 'collector', 'authority_retirement_binding_not_found')
        r.write_volume('gateway-tls', {'profile.json': json.dumps(policy)})
        command(['docker', 'restart', r.container('certificate-controller')])
        self.wait(lambda: r.controller_status()['paused'], 'authority_retirement_restart_not_paused')
        self.configure(paused=False)
        self.wait(lambda: r.controller_status()['credentials'][collector]['status'] == 'disabled', 'authority_disabled_identity_not_retained')
        self.pause()
        current = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        self.require(retired_fp not in current['peers'], 'authority_controller_restored_retired_pin')
        self.add('disabled_identity_and_removed_peer_pin_not_restored_by_controller_restart')
        # Probe the ordinary collector's exact TLS profile and API key. A valid
        # signed observation that was admitted before retirement must now fail
        # in transport before it reaches the API inbox.
        denied_id = 'ca-retired-' + secrets.token_hex(5)
        result = self.collector_request(denied_id)
        self.require(result['status'] in {0, 403} and self.receipt(denied_id)['status'] == 404, 'authority_retired_peer_reached_inbox')
        self.add('retired_collector_mtls_denied_before_new_observation_reaches_inbox')
        self.configure(renew_before={name: 1200 if name.startswith('renew-') else 400 for name in cfg['renew_before']})
        original_status = self.pause()
        r.down()
        r.up()
        after_resume = r.controller_status()
        self.require({uid: c['fingerprint'] for uid, c in after_resume['credentials'].items()}
                     == {uid: c['fingerprint'] for uid, c in original_status['credentials'].items()}
                     and after_resume['paused'], 'authority_clean_resume_reinitialized_certificates')
        self.add('clean_resume_preserves_ca_db_certificates_disabled_identity_and_pause')
        # Refuse a modified, fixed controller trust configuration before starting
        # any service; dynamic disabled/pause controls are deliberately distinct.
        original_cfg = r.controller_configuration()
        r.compose('stop', '--timeout', '2')
        changed = copy.deepcopy(original_cfg)
        changed['server_signers'] = {'core-a': '/managed/renewal-tls/foreign.key'}
        r.write_volume('certificate-state', {'config.json': json.dumps(changed)})
        try:
            try:
                r.up()
            except RuntimeFailure as error:
                self.require(str(error) == 'authority_configuration_drift', 'authority_wrong_configuration_denial')
            else:
                raise RuntimeFailure('authority_modified_trust_configuration_started')
            self.require(all(not row['running'] for row in r.status()['services'].values()), 'authority_drift_started_service')
            self.add('modified_controller_trust_configuration_refuses_all_services_before_start')
        finally:
            r.write_volume('certificate-state', {'config.json': json.dumps(original_cfg)})
        self.database_loss_gate(collector, control)
        self.report['final_certificates'] = r.controller_status()
        self.report['completed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/authority-acceptance')
    args = parser.parse_args()
    checks = AuthorityChecks(args.directory)
    try:
        checks.run()
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        checks.report.update(completed=False, failure=str(error) if isinstance(error, RuntimeFailure) else type(error).__name__)
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
