"""Real local leaf-rekey acceptance, including outage and interrupted publication."""

import argparse
import copy
import json
import secrets
import subprocess
from pathlib import Path

from scripts.authority_runtime_assets import SERVERS
from scripts.continuous_mtls_assets import DEVICES, OTHER
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.rekey_mtls_runtime import RekeyRuntime
from scripts.test_authority_mtls_runtime import AuthorityChecks
from scripts.test_monitored_mtls_runtime import MonitoredChecks


class RekeyChecks(AuthorityChecks):
    def __init__(self, directory):
        MonitoredChecks.__init__(self, directory, runtime_class=RekeyRuntime)
        self.report['schema'] = 'persistent-leaf-rekey-verification-1'

    def audit(self):
        return json.loads(self.runtime.execute('certificate-controller',
            ['python', '-m', 'scripts.rekey_runtime_control', 'audit']))

    def start_round(self):
        cfg = self.runtime.controller_configuration()
        self.configure(paused=False, renew_before={name: 0 for name in cfg['renew_before']},
                       key_rotation=cfg['key_rotation'] | {'interval_seconds': 15})

    def finish_round(self, before):
        self.wait(lambda: (s := self.runtime.controller_status())['phase'] is None
                  and all((c.get('key_generation') or 0) > before['credentials'][uid]['key_generation']
                          for uid, c in s['credentials'].items() if uid not in self.disabled),
                  'rekey_round_incomplete', timeout=240)
        self.pause()
        return self.audit()

    def files_exist(self, paths):
        return json.loads(self.runtime.execute('certificate-controller', ['python', '-c',
            "import json,sys;from pathlib import Path;print(json.dumps([Path(p).exists() for p in json.load(sys.stdin)]))"],
            json.dumps(paths)))

    def retired_paths(self, before):
        return [path for uid, c in before['credentials'].items() if uid not in self.disabled
                for asset in c['assets'] for path in asset.values()]

    def validate_round(self, before, after, label):
        for uid, c in after['credentials'].items():
            if uid in self.disabled:
                self.require(c['public_key_sha256'] == before['credentials'][uid]['public_key_sha256'],
                             'rekey_disabled_key_changed')
                continue
            self.require(c['key_generation'] > before['credentials'][uid]['key_generation']
                         and c['public_key_sha256'] != before['credentials'][uid]['public_key_sha256']
                         and c['copies_match'] and c['pairs_match'] and c['private_modes'] == [384]
                         and c['pending'] is None, 'rekey_pair_or_generation_not_proven')
        self.require(not any(self.files_exist(self.retired_paths(before))), 'rekey_retired_files_retained')
        self.add(label, identities=39 - len(self.disabled))

    def run(self):
        r = self.runtime
        self.disabled = set()
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
        original_cfg = copy.deepcopy(r.controller_configuration())
        self.pause()
        before = self.audit()
        self.require(len(before['credentials']) == 39, 'rekey_inventory_missing')
        spec = r.definition(r.state['project'], 'app', 'nginx')
        self.require(len(spec['services']) == 16 and len(spec['networks']) == 9
                     and len(spec['volumes']) == 31 and all(n['internal'] for n in spec['networks'].values()),
                     'rekey_topology_changed')
        self.add('same_sixteen_service_nine_internal_network_thirty_one_volume_graph')
        self.add('all_39_identities_enrolled_in_real_ca_before_rekey')
        for name in r.services:
            info = self.inspect(name)
            host = info['HostConfig']
            self.require(info['Config']['User'] == '10001:10001' and host['ReadonlyRootfs']
                         and 'ALL' in host['CapDrop'] and 'no-new-privileges:true' in host['SecurityOpt']
                         and not host.get('PortBindings') and all(m['Type'] != 'bind' for m in info['Mounts']),
                         'rekey_service_hardening_failed')
        self.add('all_actual_services_non_root_read_only_without_host_ports_or_binds')
        # A negative-test copy stays inside the controller's private Linux volume.
        collector = next(uid for uid, c in before['credentials'].items() if c['name'] == 'collector')
        r.execute('certificate-controller', ['python', '-c', """import json,sys
from pathlib import Path
c=json.loads(Path('/state/state.json').read_bytes())['credentials'][json.load(sys.stdin)['id']]
for field,suffix in [('key','key'),('cert','pem')]:
 p=Path('/state/prior-collector.'+suffix);p.write_bytes(Path(c['assets'][0][field]).read_bytes());p.chmod(0o600)
"""], json.dumps({'id': collector}))
        signer_before = r.state['rekey_signer_public_sha256'].copy()
        self.start_round()
        after = self.finish_round(before)
        self.validate_round(before, after, 'all_39_keys_replaced_matching_copies_mode_0600_old_managed_files_removed')
        status = r.controller_status()
        servers = {c['name']: c for c in status['credentials'].values() if c['purpose'] == 'serverAuth'}
        self.require(set(servers) == set(SERVERS) and all(
            status['server_observations'][name]['fingerprint'] == c['fingerprint'] for name, c in servers.items()),
            'rekey_native_tls_observation_missing')
        self.add('eleven_native_tls_servers_present_rotated_leaf_after_reload_ack')
        self.require(self.rpc('renew_attempt', id=collector)['allowed'], 'rekey_current_client_control_failed')
        denial = json.loads(r.execute('certificate-controller', ['python', '-c', """import json,time
from pathlib import Path
from scripts.certificate_controller import ca_post,metadata
from scripts.test_authority_mtls_runtime import certificate_probe
p=Path('/managed/collector-tls/profile.json');c=json.loads(p.read_bytes())
old={'certificates':['/state/prior-collector.pem'],'key':'/state/prior-collector.key'}
code,_=ca_post(Path('/state'),'/1.0/renew',{},identity=old)
print(json.dumps({'old_ca_status':code,'unexpired':metadata(Path('/state/prior-collector.pem').read_text())['not_after']>time.time(),
 'current_transport':certificate_probe(p,p.parent/c['cert'],p.parent/c['key'],{}),
 'old_transport':certificate_probe(p,'/state/prior-collector.pem','/state/prior-collector.key',{})}))
"""]))
        self.require(denial['unexpired'] and denial['old_ca_status'] in (400, 401, 403)
                     and denial['current_transport'] == 401 and denial['old_transport'] == 403,
                     'rekey_unexpired_old_identity_denial_not_proven')
        self.add('still_valid_old_client_denied_by_ca_and_peer_with_current_positive_controls', **denial)
        self.access(self.mint('rekey-document', user_id=OTHER, device_id=DEVICES[1]), True,
                    'document_enforcement_succeeds_after_private_key_rotation')
        self.scrape = r.execute('exporter', ['python', '-c', "from pathlib import Path;print(Path('/auth/scrape.token').read_text())"]).strip()
        self.notify = r.execute('sink', ['python', '-c', "from pathlib import Path;print(Path('/tls/notify.token').read_text())"]).strip()
        self.wait(lambda: 'secops_signal_collection_success 1' in self.metric(), 'rekey_metrics_unavailable')
        self.add('authenticated_metrics_succeed_after_private_key_rotation')
        floor = self.begin_episode()
        worker = r.container('worker')
        command(['docker', 'stop', '--time', '2', worker])
        event_id = 'rekey-backlog-' + secrets.token_hex(5)
        try:
            self.submit(event_id)
            firing = self.await_episode('C01SignalQueueBacklog', 'firing', floor)
            self.add('fresh_backlog_alert_delivered_after_private_key_rotation')
        finally:
            command(['docker', 'start', worker])
        self.wait(lambda: self.receipt(event_id).get('body', {}).get('state') == 'completed', 'rekey_backlog_not_processed')
        self.await_episode('C01SignalQueueBacklog', 'resolved', floor, firing)
        self.add('same_post_rekey_alert_episode_resolves_after_worker_recovery')
        ca = r.container('ca')
        controller = r.container('certificate-controller')
        before = self.audit()
        command(['docker', 'stop', '--time', '2', ca])
        try:
            self.start_round()
            self.wait(lambda: all(c['pending'] for c in self.audit()['credentials'].values()),
                      'rekey_outage_pending_keys_missing', timeout=120)
            self.pause()
            pending = self.audit()
            self.require(all(c['public_key_sha256'] == before['credentials'][uid]['public_key_sha256']
                             for uid, c in pending['credentials'].items()), 'rekey_outage_replaced_active_key')
            self.add('ca_outage_keeps_current_keys_and_persists_pending_keys')
            command(['docker', 'restart', controller])
            self.wait(lambda: r.controller_status()['paused'], 'rekey_outage_restart_not_paused')
            self.start_round()
            self.wait(lambda: any(c['failures'] for c in r.controller_status()['credentials'].values()),
                      'rekey_outage_retry_missing')
            self.pause()
            again = self.audit()
            self.require({uid: c['pending'] for uid, c in again['credentials'].items()}
                         == {uid: c['pending'] for uid, c in pending['credentials'].items()}, 'rekey_outage_regenerated_pending_key')
            self.add('controller_restart_during_ca_outage_reuses_exact_pending_keys')
        finally:
            command(['docker', 'start', ca])
        self.start_round()
        recovered = self.finish_round(before)
        self.require(all(c['public_key_sha256'] == pending['credentials'][uid]['pending']['public_key_sha256']
                         for uid, c in recovered['credentials'].items()), 'rekey_outage_recovery_used_different_key')
        self.validate_round(before, recovered, 'ca_recovery_publishes_exact_persisted_pending_keys_and_removes_old_files')
        # Stop one reload target to interrupt publication after switching paths.
        before = recovered
        prometheus = r.container('prometheus')
        command(['docker', 'stop', '--time', '2', prometheus])
        try:
            self.start_round()
            self.wait(lambda: r.controller_status()['phase'] == 'activated', 'rekey_activated_phase_not_reached', timeout=180)
            self.configure(paused=True)
            blocked = self.audit()
            self.require(all(self.files_exist(self.retired_paths(before))), 'rekey_deleted_old_keys_before_reload_ack')
            self.add('missing_reload_target_blocks_retirement_and_keeps_old_keys')
            command(['docker', 'kill', controller])
            command(['docker', 'start', controller])
            self.wait(lambda: r.controller_status()['phase'] == 'activated', 'rekey_interrupted_phase_lost')
            again = self.audit()
            self.require({uid: c['pending'] for uid, c in again['credentials'].items()}
                         == {uid: c['pending'] for uid, c in blocked['credentials'].items()}
                         and all(self.files_exist(self.retired_paths(before))), 'rekey_interrupted_state_changed')
            self.add('killed_controller_recovers_same_publication_and_pending_keys')
        finally:
            command(['docker', 'start', prometheus])
        self.pause()
        resumed = self.audit()
        self.require(all(c['public_key_sha256'] == blocked['credentials'][uid]['pending']['public_key_sha256']
                         for uid, c in resumed['credentials'].items()), 'rekey_interrupted_recovery_used_different_key')
        self.validate_round(before, resumed, 'reload_recovery_commits_same_keys_and_only_then_removes_retired_files')
        # A local retirement stays authoritative through further key rotation.
        admitted = 'rekey-before-disable-' + secrets.token_hex(5)
        self.require(self.collector_request(admitted)['status'] == 202, 'rekey_collector_positive_control_failed')
        self.wait(lambda: self.receipt(admitted).get('body', {}).get('state') == 'completed', 'rekey_control_not_processed')
        self.disabled.add(collector)
        self.configure(disabled=[collector])
        policy = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        retired_fp = r.controller_status()['credentials'][collector]['fingerprint']
        self.require(policy['peers'].pop(retired_fp, None) == 'collector', 'rekey_disabled_binding_missing')
        r.write_volume('gateway-tls', {'profile.json': json.dumps(policy)})
        command(['docker', 'restart', controller])
        self.wait(lambda: r.controller_status()['paused'], 'rekey_disabled_restart_not_paused')
        self.start_round()
        final = self.finish_round(resumed)
        self.validate_round(resumed, final, 'remaining_38_keys_rotate_without_changing_disabled_collector')
        current = json.loads(r.execute('gateway', ['python', '-c', "from pathlib import Path;print(Path('/tls/profile.json').read_text())"]))
        denied_id = 'rekey-disabled-' + secrets.token_hex(5)
        self.require(retired_fp not in current['peers'] and self.collector_request(denied_id)['status'] in (0, 403)
                     and self.receipt(denied_id)['status'] == 404, 'rekey_restored_disabled_peer')
        self.add('disabled_collector_and_removed_pin_survive_restart_and_further_rotation')
        # Restore sealed production timing before host preflight. Never re-seal.
        self.configure(key_rotation=original_cfg['key_rotation'], renew_before=original_cfg['renew_before'], paused=True)
        r.down()
        r.up()
        self.require(self.audit() == final and r.controller_status()['paused'], 'rekey_clean_resume_changed_keys')
        self.add('clean_host_resume_preserves_rotated_keys_disabled_identity_and_pause')
        self.require(r.state['rekey_signer_public_sha256'] == signer_before, 'rekey_signer_descriptor_changed')
        r.verify_extra_images()  # Includes crypto verification of the fixed JWK keys.
        self.add('fixed_delegated_jwk_signers_remain_separate_and_unchanged_after_leaf_rekey')
        original_yaml = r.helper(['-c', "from pathlib import Path;print(Path('/managed/prometheus-tls/config.yml').read_text(),end='')"])
        r.compose('stop', '--timeout', '2')
        r.write_volume('prometheus-tls', {'config.yml': original_yaml.replace('scrape_interval: 1s', 'scrape_interval: 9s')})
        try:
            try:
                r.up()
            except RuntimeFailure as error:
                self.require(str(error) == 'rekey_configuration_drift', 'rekey_wrong_configuration_denial')
            else:
                raise RuntimeFailure('rekey_modified_monitoring_configuration_started')
            self.require(all(not row['running'] for row in r.status()['services'].values()), 'rekey_drift_started_services')
            self.add('unapproved_monitoring_config_change_refused_before_any_service_start')
        finally:
            r.write_volume('prometheus-tls', {'config.yml': original_yaml})
        r.up()
        self.access(self.mint('rekey-final-document', user_id=OTHER, device_id=DEVICES[1]), True,
                    'document_enforcement_continues_after_rekey_fault_recovery_and_host_resume')
        self.report['final_keys'] = final
        self.report['completed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/rekey-acceptance')
    args = parser.parse_args()
    checks = RekeyChecks(args.directory)
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
