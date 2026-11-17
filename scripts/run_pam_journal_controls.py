"""Owned local PAM collection controls; no maliciousness or human-login labels."""

import argparse
import base64
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from scripts.f1_lab.collector_freshness import CollectorScope, inspect_capture
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_journal import PamCapture, verify
from scripts.f1_lab.pam_journal_native import unit_invocation
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry
from scripts.f1_lab.systemd_credentials import CredentialSocket
from scripts.run_shared_execution_controls import setup


def run(directory, *, ledger=False, checkpoint=False):
    require(not checkpoint or ledger, 'pam_controls_checkpoint_requires_ledger')
    source = Path(__file__).resolve().parents[1]
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
            and source.parent == Path('/run') and source.name.startswith('zt-pam-journal-v93-'),
            'pam_controls_owned_systemd_source')
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    config = Path('/run')/('zpa93-'+tag[:12])
    config.mkdir(mode=0o755)
    target = 'zpa93t-'+tag[:12]+'.service'
    collector_prefix, verifier_unit, write_unit = 'zpa93c-'+tag[:12], 'zpa93v-'+tag[:12]+'.service', 'zpa93w-'+tag[:12]+'.service'
    state_name = 'secops-pa93-'+tag
    state = Path('/var/lib')/state_name
    ledger_state_name = 'secops-pal95-'+tag
    ledger_state = Path('/var/lib')/ledger_state_name
    admission_unit = 'zpa95a-'+tag[:12]+'.service'
    checkpoint_unit = 'zpa98p-'+tag[:12]+'.service'
    registry_path, env_path, keyless_copy = config/'service-registry.json', config/'public.conf', config/'keyless.json'
    created, checks, launches = [], [], []
    provider = None
    report = {'schema': 'pam-journal-native-controls-1', 'completed': False, 'cases': checks,
        'aws_calls': 0, 'paid_api_calls': 0, 'goal_qualified': False, 'organization_identity_tested': False,
        'host_wide_audit_tested': False, 'production_account_acl_installed': False,
        'additional_raw_journal_export_persisted': False, 'original_system_journal_retains_messages': True,
        'fixture_controller_holds_multiple_fixture_keys': True, 'collector_reports': launches}

    def save():
        (output/'run.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')

    def check(name, condition=True):
        require(condition, 'pam_controls_'+name)
        checks.append(name)

    def command(*args):
        return subprocess.run(['/usr/bin/systemctl', *args], env=READ_ENV,
                              capture_output=True, timeout=25, check=False)

    def install(name, text):
        path = Path('/run/systemd/system')/name
        with path.open('x', encoding='utf8') as stream:
            stream.write(text)
        created.append(path)

    def messages(unit):
        result = subprocess.run(['/usr/bin/journalctl', '--no-pager', '--unit', unit, '--lines=30', '--output=cat'],
            env=READ_ENV, capture_output=True, timeout=5, check=True)
        require(len(result.stdout) <= 65536, 'pam_controls_log_bound')
        rows = [json.loads(raw) for raw in result.stdout.splitlines() if raw.startswith(b'{')]
        require(rows, 'pam_controls_missing_cli_report')
        return rows[-1]

    def private_bytes(key):
        return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def security(row, uid):
        value = row['worker_security']
        return value['effective_uid'] == uid and value['effective_capabilities'] == value['bounding_capabilities'] == 0 and value['no_new_privileges']

    def public_env(pin, key_id='auth-1'):
        env_path.write_text('REGISTRY_SHA256='+pin+'\nAUTH_KEY_ID='+key_id+'\n', encoding='utf8')
        env_path.chmod(0o644)

    def collect(instance, expected=True):
        unit = collector_prefix+'@'+instance+'.service'
        result = command('start', unit)
        launch = {'instance': instance, 'exit_code': result.returncode}
        status = command('show', '--property=Result,ExecMainCode,ExecMainStatus,ActiveState,SubState', '--', unit)
        fields = {}
        if status.returncode == 0 and len(status.stdout) <= 4096:
            for line in status.stdout.decode().splitlines():
                name, separator, value = line.partition('=')
                if (separator and name in {'Result', 'ExecMainCode', 'ExecMainStatus', 'ActiveState', 'SubState'}
                        and re.fullmatch('[a-zA-Z0-9_-]{1,64}', value)):
                    fields[name] = value
        launch['manager_status'] = fields
        launches.append(launch)
        save()  # Preserve startup status even when Python could not emit a receipt.
        row = messages(unit)
        launch['report'] = row
        save()
        require(row['completed'] is expected and (result.returncode == 0) is expected, 'pam_controls_collect_result')
        if expected:
            require(security(row, 65534) and row['dumpable'] is False
                    and row['key_input_kind'] == 'systemd_memory_credential', 'pam_controls_worker_security')
            path = state/instance/'capture.json'
            raw = path.read_bytes()
            require(hashlib.sha256(raw).hexdigest() == row['capture_sha256'], 'pam_controls_capture_pin')
            require(path.stat().st_uid == 65534 and path.stat().st_mode & 0o777 == 0o600
                    and path.parent.stat().st_mode & 0o777 == 0o700, 'pam_controls_private_capture')
            return PamCapture.model_validate(json.loads(raw)), raw
        require(not (state/instance).exists(), 'pam_controls_failed_capture_published')
        return None

    def keyless(raw, boot, invocation, *, pin=None, registry_pin=None, key_id='auth-1', expected=True, copy=True):
        if copy:
            keyless_copy.write_bytes(raw)
            keyless_copy.chmod(0o444)
        pin = hashlib.sha256(raw).hexdigest() if pin is None else pin
        registry_pin = original_pin if registry_pin is None else registry_pin
        path = Path('/run/systemd/system')/verifier_unit
        text = base('daemon')+f'ExecStart=/usr/bin/python3 -m scripts.verify_pam_journal {common} --key-id {key_id} --registry-sha256 {registry_pin} --capture {keyless_copy} --capture-sha256 {pin} --boot-id {boot} --invocation-id {invocation}\n'
        if path not in created:
            install(verifier_unit, text)
        else:
            path.write_text(text, encoding='utf8')
        require(command('daemon-reload').returncode == 0, 'pam_controls_verify_reload')
        command('reset-failed', verifier_unit)
        result = command('start', verifier_unit)
        row = messages(verifier_unit)
        require(row['completed'] is expected and (result.returncode == 0) is expected, 'pam_controls_keyless_result')
        if expected:
            require(security(row, 1) and row['records'] == 2 and not row['human_authenticated']
                    and not row['authorization_asserted'], 'pam_controls_keyless_security')
        return row

    def admit(raw, boot, invocation, *, initialize=False, registry_pin=None, key_id='auth-1', pin=None, expected=True):
        keyless_copy.write_bytes(raw)
        keyless_copy.chmod(0o444)
        pin = hashlib.sha256(raw).hexdigest() if pin is None else pin
        registry_pin = original_pin if registry_pin is None else registry_pin
        path = Path('/run/systemd/system')/admission_unit
        text = base('daemon')+f'StateDirectory={ledger_state_name}\nStateDirectoryMode=0700\nUMask=0077\n'
        text += f'ExecStart=/usr/bin/python3 -m scripts.admit_pam_journal {common} --key-id {key_id} --registry-sha256 {registry_pin} --capture {keyless_copy} --capture-sha256 {pin} --boot-id {boot} --invocation-id {invocation} --ledger-directory {ledger_state}/observations'
        text += ' --initialize\n' if initialize else '\n'
        if path not in created:
            install(admission_unit, text)
        else:
            path.write_text(text, encoding='utf8')
        require(command('daemon-reload').returncode == 0, 'pam_controls_admission_reload')
        command('reset-failed', admission_unit)
        result = command('start', admission_unit)
        row = messages(admission_unit)
        require(row['completed'] is expected and (result.returncode == 0) is expected,
                'pam_controls_admission_result')
        if expected:
            require(security(row, 1) and not row['human_authenticated']
                and not row['authorization_asserted'] and not row['automatic_enforcement_allowed'],
                'pam_controls_admission_security')
        return row

    def checkpoint_run(pin=None, *, expected=True):
        path = Path('/run/systemd/system')/checkpoint_unit
        text = base('daemon')+f'StateDirectory={ledger_state_name}\nStateDirectoryMode=0700\nUMask=0077\n'
        text += f'ExecStart=/usr/bin/python3 -m scripts.checkpoint_pam_observations --tenant local-lab --server shared-lab --unit {target} --source local-auth-journal --key-id auth-1 --ledger-directory {ledger_state}/observations'
        text += '\n' if pin is None else f' --expected-sha256 {pin}\n'
        if path not in created:
            install(checkpoint_unit, text)
        else:
            path.write_text(text, encoding='utf8')
        require(command('daemon-reload').returncode == 0, 'pam_controls_checkpoint_reload')
        command('reset-failed', checkpoint_unit)
        result = command('start', checkpoint_unit)
        value = messages(checkpoint_unit)
        require(value['completed'] is expected and (result.returncode == 0) is expected,
                'pam_controls_checkpoint_result')
        if expected:
            require(security(value, 1) and not value['current_freshness_verified']
                and not value['human_authenticated'] and not value['automatic_enforcement_allowed'],
                'pam_controls_checkpoint_security')
        return value

    py_path = os.environ.get('PYTHONPATH', '')
    require(bool(re.fullmatch(r'[A-Za-z0-9_/:.-]{1,2048}', py_path)), 'pam_controls_dependency_path')

    def base(user):
        require(user in {'nobody', 'daemon'}, 'pam_controls_fixture_account')
        account = pwd.getpwnam(user)
        return ('[Unit]\nDescription=Owned PAM controls\n[Service]\nType=oneshot\n'
            +f'User={account.pw_uid}\nGroup={account.pw_gid}\nWorkingDirectory={source}\n'
            +f'Environment=PYTHONPATH={py_path}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
            +'NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateNetwork=yes\n'
            +'RestrictAddressFamilies=AF_UNIX\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\n'
            +'ProtectHome=yes\nRestrictSUIDSGID=yes\nMemoryMax=256M\nTasksMax=16\nTimeoutStartSec=20\n')

    try:
        keys, registry, _ = setup(config/'fixture-trust')
        auth_key = Ed25519PrivateKey.generate()
        public = base64.urlsafe_b64encode(auth_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
        original_auth = registry.authorities[0].model_copy(update={'kind': 'authentication', 'mode': 'systemd',
            'source_id': 'local-auth-journal', 'key_id': 'auth-1', 'units': [target], 'public_key': public})
        registry = registry.model_copy(update={'authorities': [*registry.authorities, original_auth]})
        original_registry = canonical(registry.model_dump(mode='json'))+b'\n'
        registry_path.write_bytes(original_registry)
        registry_path.chmod(0o644)
        original_pin = hashlib.sha256(original_registry).hexdigest()
        public_env(original_pin)
        scope = CollectorScope(tenant_id='local-lab', server_id='shared-lab', unit=target,
            source_id='local-auth-journal', key_id='auth-1')
        common = f'--tenant {scope.tenant_id} --server {scope.server_id} --unit {target} --source {scope.source_id} --registry {registry_path}'
        selected_key = {'value': auth_key}
        provider_parent = config/'provider'
        provider_parent.mkdir(mode=0o700)
        provider = CredentialSocket(provider_parent/'auth.sock', lambda: private_bytes(selected_key['value']),
                                    allowed_uid=0, maximum_connections=32)
        provider.__enter__()
        target_text = ('[Unit]\nDescription=Owned PAM source fixture\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            +'NoNewPrivileges=yes\nPrivateNetwork=yes\n'
            +'ExecStartPre=/usr/bin/logger -t sudo "pam_unix(sudo:session): session opened for user root by (uid=0)"\n'
            +'ExecStart=/usr/bin/sudo -n -u nobody -- /usr/bin/sleep 0.5\nTimeoutStartSec=10\n')
        install(target, target_text)
        collector_text = base('nobody')+'SupplementaryGroups=systemd-journal\n'+f'EnvironmentFile={env_path}\n'+f'LoadCredential=auth-journal-key:{provider.path}\n'+f'StateDirectory={state_name}\nStateDirectoryMode=0700\nUMask=0077\n'+f'ExecStart=/usr/bin/python3 -m scripts.collect_pam_journal {common} --key-id ${{AUTH_KEY_ID}} --registry-sha256 ${{REGISTRY_SHA256}} --systemd-credential --lookback-seconds 60 --output {state}/%i\n'
        install(collector_prefix+'@.service', collector_text)
        require(command('daemon-reload').returncode == 0 and command('start', target).returncode == 0, 'pam_controls_start')
        boot, invocation = unit_invocation(target)
        first, first_raw = collect('one')
        require(len(first.records) == 2 and first.rejections.untrusted_pam >= 1, 'pam_controls_origin_counts')
        require({r.event for r in first.records} == {'opened', 'closed'}
                and len({r.reported_process_id for r in first.records}) == 1,
                'pam_controls_original_pid_records')
        verify(first, scope, PinnedServiceRegistry(registry_path, original_pin), boot=boot, invocation=invocation)
        check('actual_nonroot_cap0_nnp_memory_credential_collector_reads_real_sudo_open_close')
        check('fake_sudo_syslog_tag_is_rejected_using_actual_journal_process_origin')
        report['kernel_audit_identity_fields_available'] = any(
            r.audit_login_uid is not None or r.audit_session_id is not None for r in first.records)
        check('optional_audit_ids_do_not_become_person_or_process_lifetime_authorization',
              not first.human_authenticated and not first.process_lifetime_identity_verified)
        check('authentication_capture_is_not_an_existing_service_execution_proof',
              inspect_capture(first.model_dump(mode='json'), scope, PinnedServiceRegistry(registry_path, original_pin)).state == 'unavailable')
        first_keyless = keyless(first_raw, boot, invocation)
        report['keyless_worker_security'] = first_keyless['worker_security']
        check('separate_pid1_keyless_daemon_verifies_owned_readonly_copy_without_key_input')
        if ledger:
            admitted = admit(first_raw, boot, invocation, initialize=True)
            check('actual_separate_cap0_nnp_daemon_admits_two_real_pam_events_without_signing_key',
                  admitted['new_events'] == 2 and admitted['unique_events_retained'] == 2)
            repeated = admit(first_raw, boot, invocation)
            check('separate_admission_process_restart_deduplicates_same_original_capture',
                  repeated['new_events'] == 0 and repeated['duplicate_capture']
                  and repeated['original_window_end_us'] == admitted['original_window_end_us'])
            admit(first_raw, boot, invocation, initialize=True, expected=False)
            check('existing_durable_pam_ledger_cannot_be_reinitialized')
            admit(first_raw+b' ', boot, invocation, pin=hashlib.sha256(first_raw).hexdigest(), expected=False)
            unchanged = admit(first_raw, boot, invocation)
            check('damaged_owned_capture_fails_external_pin_without_erasing_or_recounting_ledger',
                  unchanged['new_events'] == 0 and unchanged['unique_events_retained'] == 2)
            if checkpoint:
                original_checkpoint = checkpoint_run()
                original_database = (ledger_state/'observations/observations.sqlite3').read_bytes()
                checked_checkpoint = checkpoint_run(original_checkpoint['checkpoint_sha256'])
                check('separate_keyless_cap0_daemon_checks_two_original_events_against_external_pin',
                      checked_checkpoint['external_pin_matched'] and checked_checkpoint['unique_events'] == 2)
        probe = ("import os,json;blocked=False\ntry:\n fd=os.open("+repr(str(keyless_copy))+",os.O_WRONLY);os.close(fd)\nexcept OSError as error:blocked=error.errno in (13,30)\nprint(json.dumps({'write_denied':blocked}))")
        escaped = probe.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        install(write_unit, base('daemon')+f'ExecStart=/usr/bin/python3 -c "{escaped}"\n')
        require(command('daemon-reload').returncode == 0 and command('start', write_unit).returncode == 0,
                'pam_controls_write_probe')
        check('keyless_daemon_actual_copy_write_open_is_denied', messages(write_unit)['write_denied'])
        keyless_copy.write_bytes(first_raw+b' ')
        keyless(first_raw, boot, invocation, expected=False, copy=False)
        check('actual_copy_damage_fails_external_hash_without_auto_repin')
        require(command('restart', target).returncode == 0, 'pam_controls_target_restart')
        boot2, invocation2 = unit_invocation(target)
        require(boot2 == boot and invocation2 != invocation, 'pam_controls_new_invocation')
        second, second_raw = collect('two')
        check('actual_owned_target_restart_keeps_old_invocation_events_out_of_new_capture',
              second.invocation_id == invocation2 and len(second.records) == 2
              and second.rejections.untrusted_pam >= 4
              and not {r.cursor_sha256 for r in first.records} & {r.cursor_sha256 for r in second.records})
        if ledger:
            second_admission = admit(second_raw, boot2, invocation2)
            check('new_owned_invocation_retains_prior_two_and_adds_only_two_new_cursor_events',
                  second_admission['new_events'] == 2 and second_admission['unique_events_retained'] == 4)
            if checkpoint:
                checkpoint_run(original_checkpoint['checkpoint_sha256'], expected=False)
                check('new_invocation_changes_checkpoint_without_recounting_old_events')
        keyless(first_raw, boot2, invocation2, expected=False)
        check('old_capture_cannot_be_rebound_to_current_target_invocation')
        selected_key['value'] = keys['runtime']
        collect('wrong-role', expected=False)
        selected_key['value'] = auth_key
        check('registered_runtime_private_key_cannot_issue_authentication_capture')
        revoked = registry.model_copy(update={'version': 2, 'authorities': [
            a.model_copy(update={'enabled': False}) if a.kind == 'authentication' else a for a in registry.authorities]})
        changed = canonical(revoked.model_dump(mode='json'))+b'\n'
        registry_path.write_bytes(changed)
        public_env(hashlib.sha256(changed).hexdigest())
        collect('revoked', expected=False)
        check('explicit_admin_revocation_blocks_collection_without_key_role_fallback')
        replacement_key = Ed25519PrivateKey.generate()
        replacement = original_auth.model_copy(update={'key_id': 'auth-2', 'issued_at': datetime.now(UTC),
            'public_key': base64.urlsafe_b64encode(replacement_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')})
        renewed = revoked.model_copy(update={'version': 3, 'authorities': [*revoked.authorities, replacement]})
        renewed_raw = canonical(renewed.model_dump(mode='json'))+b'\n'
        registry_path.write_bytes(renewed_raw)
        renewed_pin = hashlib.sha256(renewed_raw).hexdigest()
        selected_key['value'] = replacement_key
        public_env(renewed_pin, 'auth-2')
        third, third_raw = collect('three')
        verify(third, scope.model_copy(update={'key_id': 'auth-2'}), PinnedServiceRegistry(registry_path, renewed_pin),
               boot=boot2, invocation=invocation2)
        keyless(third_raw, boot2, invocation2, registry_pin=renewed_pin, key_id='auth-2')
        check('explicit_admin_replacement_key_preserves_revocation_and_original_event_times',
              [(r.cursor_sha256, r.recorded_at_us) for r in second.records]
              == [(r.cursor_sha256, r.recorded_at_us) for r in third.records]
              and not third.human_authenticated and not third.authorization_asserted
              and renewed.version == 3 and not next(a for a in renewed.authorities if a.key_id == 'auth-1').enabled)
        if ledger:
            rotated = admit(third_raw, boot2, invocation2, registry_pin=renewed_pin, key_id='auth-2')
            check('explicit_new_auth_key_preserves_same_cursor_dedup_and_all_four_original_events',
                  rotated['new_events'] == 0 and rotated['overlapping_events'] == 2
                  and rotated['unique_events_retained'] == 4)
            report['durable_pam_ledger_tested'] = True
            report['ledger_worker_security'] = rotated['worker_security']
            report['unique_original_pam_events_retained'] = 4
            if checkpoint:
                latest_checkpoint = checkpoint_run()
                latest_database = (ledger_state/'observations/observations.sqlite3').read_bytes()
                check('historical_checkpoint_after_signer_rotation_does_not_reactivate_old_auth_key',
                      latest_checkpoint['unique_events'] == 4
                      and not next(a for a in renewed.authorities if a.key_id == 'auth-1').enabled)
                # Owned fixture only; never install a restored database into a
                # production writer. Preserve both original byte images in RAM.
                (ledger_state/'observations/observations.sqlite3').write_bytes(original_database)
                checkpoint_run(latest_checkpoint['checkpoint_sha256'], expected=False)
                check('actual_whole_owned_database_rollback_fails_separately_retained_latest_pin')
                (ledger_state/'observations/observations.sqlite3').write_bytes(latest_database)
                restored = checkpoint_run(latest_checkpoint['checkpoint_sha256'])
                check('exact_owned_fixture_reinstatement_matches_pin_and_keeps_four_original_events',
                      restored['external_pin_matched'] and restored['unique_events'] == 4)
                report['external_pam_checkpoint_tested'] = True
                report['checkpoint_worker_security'] = restored['worker_security']
        report.update(completed=True, verified_records_each=2,
            original_event_times=[r.recorded_at_us for r in second.records],
            collector_user=65534, keyless_user=1, target_fixture_restarts=1,
            human_authenticated=False, authorization_asserted=False, private_key_written_to_capture=False,
            encrypted_archive_integration_tested=False, new_independent_detection_evaluation=False,
            finished_at=datetime.now(UTC).isoformat())
    finally:
        for path in reversed(created):
            if path.name.endswith('@.service'):
                for instance in ('one', 'two', 'three', 'wrong-role', 'revoked'):
                    unit = collector_prefix+'@'+instance+'.service'
                    command('stop', unit)
                    command('reset-failed', unit)
            else:
                command('stop', path.name)
                command('reset-failed', path.name)
            require(path.parent == Path('/run/systemd/system'), 'pam_controls_cleanup_unit_parent')
            path.unlink(missing_ok=True)
        reloaded = command('daemon-reload').returncode == 0
        if provider is not None:
            provider.close()
        require(config.parent == Path('/run') and config.name == 'zpa93-'+tag[:12], 'pam_controls_cleanup_config')
        shutil.rmtree(config)
        require(state.parent == Path('/var/lib') and state.name == 'secops-pa93-'+tag, 'pam_controls_cleanup_state')
        if state.exists():
            shutil.rmtree(state)
        require(ledger_state.parent == Path('/var/lib') and ledger_state.name == 'secops-pal95-'+tag,
                'pam_controls_cleanup_ledger')
        if ledger_state.exists():
            shutil.rmtree(ledger_state)
        report['owned_units_removed'] = reloaded and all(not path.exists() for path in created)
        report['owned_provider_stopped'] = provider is None or not provider.thread.is_alive()
        report['owned_state_removed'] = not state.exists() and not config.exists()
        report['owned_ledger_state_removed'] = not ledger_state.exists()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--ledger', action='store_true')
    parser.add_argument('--checkpoint', action='store_true')
    args = parser.parse_args()
    result = run(args.directory, ledger=args.ledger, checkpoint=args.checkpoint)
    print(json.dumps({'completed': result['completed'], 'cases': len(result['cases']),
                      'aws_calls': 0, 'paid_api_calls': 0}))


if __name__ == '__main__':
    main()
