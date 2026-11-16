"""Owned native systemd/PAM/caller ingress checks. No threat-performance labels."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.live_execution_context import (
    ExecutionPolicy,
    ExecutionRule,
    PinnedExecutionPolicy,
    collect_pam_context,
    collect_service,
    refine_pam,
)
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.pam_journal import build, micros
from scripts.f1_lab.pam_journal_native import journal_rows
from scripts.f1_lab.shared_execution_collector import (
    READ_ENV,
    collect_current_systemd,
    executable_hash,
)
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    PolicyObservation,
    refine_service,
)
from scripts.run_shared_execution_controls import sign_policy
from scripts.run_systemd_caller_controls import setup_broker, token_for


def run(directory):
    require(os.name == 'posix' and os.geteuid() == 0
            and Path('/proc/1/comm').read_text().strip() == 'systemd', 'live_controls_native_systemd')
    output = Path(directory)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    unit = 'zt-live-evidence-'+tag+'.service'
    unit_path = Path('/run/systemd/system')/unit
    report = {'schema': 'live-evidence-native-controls-1', 'completed': False, 'cases': [],
        'aws_calls': 0, 'paid_api_calls': 0, 'goal_qualified': False, 'organization_identity_tested': False,
        'source_kind': 'actual_systemd_sudo_journal_proc_with_local_oidc_fixture',
        'raw_messages_or_identity_tokens_exported': False}

    def command(*args):
        return subprocess.run(['/usr/bin/systemctl', *args], env=READ_ENV,
                              capture_output=True, timeout=10, check=False)

    def check(name, condition):
        require(condition, 'live_control_'+name)
        report['cases'].append(name)

    def write_policy(rules, version):
        now = datetime.now(UTC)
        value = ExecutionPolicy(version=version, issued_at=now, expires_at=now+timedelta(hours=1), rules=rules)
        path = output/'execution-policy.json'
        path.write_bytes(canonical(value.model_dump(mode='json')))
        return PinnedExecutionPolicy(path, hashlib.sha256(path.read_bytes()).hexdigest())

    try:
        keys, registry, identity_key, broker = setup_broker(output/'trust', unit)
        argv = ['/usr/bin/sudo', '-n', '-u', 'nobody', '--', '/usr/bin/sleep', '60']
        rule = ExecutionRule(tenant_id='local-lab', server_id='shared-lab', unit=unit,
            executable_sha256=executable_hash(Path(argv[0])),
            command_sha256=hashlib.sha256(b''.join(v.encode()+b'\0' for v in argv)).hexdigest(),
            real_uid=0, effective_uid=0)
        policy = write_policy([rule], 1)
        auth_key = Ed25519PrivateKey.generate()
        public = base64.urlsafe_b64encode(auth_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
        auth = registry.authorities[0].model_copy(update={'kind': 'authentication',
            'source_id': 'local-auth-journal', 'key_id': 'auth-1', 'public_key': public})
        registry = registry.model_copy(update={'policy_sha256': policy.sha256,
                                              'authorities': [*registry.authorities, auth]})
        registry_path = output/'trust/registry.json'

        def install_registry(value):
            registry_path.write_bytes(canonical(value.model_dump(mode='json')))
            broker.joiner.registry = PinnedServiceRegistry(registry_path, hashlib.sha256(registry_path.read_bytes()).hexdigest())

        install_registry(registry)
        scope = CollectorScope(tenant_id='local-lab', server_id='shared-lab', unit=unit,
                               source_id='local-auth-journal', key_id='auth-1')
        # Delay on the same PID before sudo exec so the conservative monotonic
        # bound can prove the PAM record occurred after its proc start tick.
        # systemd single quoting: use JSON strings inside the Python expression.
        fixture = 'import os,time;time.sleep(0.2);os.execv("/usr/bin/sudo",'+json.dumps(argv)+')'
        unit_path.write_text('[Unit]\nDescription=Owned local evidence ingress fixture\n[Service]\n'
            +"Type=exec\nExecStart=/usr/bin/python3 -c '"+fixture+"'\n"
            +'NoNewPrivileges=yes\nPrivateNetwork=yes\nTimeoutStopSec=5\n', encoding='utf8')
        require(command('daemon-reload').returncode == 0, 'live_fixture_reload')
        request = broker.issue(tenant_id=rule.tenant_id, server_id=rule.server_id, unit=unit,
            executable_sha256=rule.executable_sha256, command_sha256=rule.command_sha256)

        def authorize(_):
            now = datetime.now(UTC)
            require(rule in policy.current(now).rules, 'live_prior_allowlist')
            return PolicyObservation(decision='allow', policy_sha256=policy.sha256, policy_version=1,
                executable_sha256=rule.executable_sha256, command_sha256=rule.command_sha256), now

        def launch(_):
            require(command('start', unit).returncode == 0, 'live_fixture_start')

        def collect(_):
            deadline = time.monotonic()+5
            while True:
                event, runtime = collect_current_systemd(unit, keys['runtime'], tenant_id=rule.tenant_id,
                    server_id=rule.server_id, source_id='local-proc', key_id='proc-1')
                if runtime.observation.command_sha256 == rule.command_sha256:
                    return event, runtime
                require(time.monotonic() < deadline, 'live_fixture_exec_timeout')
                time.sleep(.05)

        receipt, event, proofs = broker.dispatch(request.request_id, token_for(request, identity_key),
            authorize=authorize, launch=launch, collect=collect,
            policy_proof=lambda e, p, t: sign_policy(e, p, keys['authorization'], observed_at=t, issued_at=datetime.now(UTC)))
        check('actual_proc_bound_to_request_nonce_and_local_oidc_caller', receipt.event_sha256 == event.sha256)
        deadline = time.monotonic()+5
        while True:
            now = datetime.now(UTC)
            raws = list(journal_rows(unit, micros(now)-10000000, micros(now)))
            capture = build(raws, scope, broker.joiner.registry, auth_key, boot=event.boot_id,
                invocation=event.invocation_id, window_start_us=micros(now)-10000000,
                window_end_us=micros(now), now=now)
            opened = [r for r in capture.records if r.event == 'opened']
            if opened:
                break
            require(time.monotonic() < deadline, 'live_fixture_pam_timeout')
            time.sleep(.1)
        check('actual_sudo_pam_open_record_has_exact_main_pid', len(opened) == 1 and opened[0].reported_process_id == event.process_id)
        args = {'cursor_sha256': opened[0].cursor_sha256, 'caller_registry': broker.registry,
                    'request': request, 'receipt': receipt}
        context = collect_pam_context(capture, scope, broker.joiner, event, proofs, **args)
        check('actual_pam_proc_start_boot_invocation_and_caller_join', context.state == 'consistent'
              and context.caller_state == 'local_oidc' and context.caller_ref_sha256 == receipt.caller_ref_sha256)
        before = OperationDecision(.1, .1, False, True, 'baseline_review')
        check('allowlisted_context_does_not_remove_review_or_grant_access', refine_pam(before, context) == before
              and not context.automatic_enforcement_allowed and not context.organization_identity_verified)
        wrong = receipt.model_copy(update={'service_evidence_sha256': 'f'*64})
        check('altered_caller_receipt_cannot_join', collect_pam_context(capture, scope, broker.joiner,
            event, proofs, **{**args, 'receipt': wrong}).state == 'unavailable')
        check('missing_record_cannot_join_by_adjacent_pid', collect_pam_context(capture, scope, broker.joiner,
            event, proofs, cursor_sha256='f'*64).state == 'unavailable')

        def ingress(selected):
            return collect_service(broker.joiner, selected, keys['runtime'], keys['authorization'],
                tenant_id=rule.tenant_id, server_id=rule.server_id, unit=unit, runtime_source_id='local-proc',
                runtime_key_id='proc-1', policy_source_id='local-policy', policy_key_id='policy-1')

        _, _, allowed = ingress(policy)
        check('live_command_and_uid_evaluate_actual_pinned_allowlist', allowed.state == 'consistent')
        denied_policy = write_policy([], 2)
        registry = registry.model_copy(update={'policy_sha256': denied_policy.sha256, 'minimum_policy_version': 2})
        install_registry(registry)
        denied_event, denied_proofs, denied = ingress(denied_policy)
        check('explicit_pinned_policy_replacement_detects_running_denied_command', denied.state == 'adverse')
        denied_capture = build(raws, scope, broker.joiner.registry, auth_key, boot=event.boot_id,
            invocation=event.invocation_id, window_start_us=capture.window_start_us,
            window_end_us=capture.window_end_us)
        denied_context = collect_pam_context(denied_capture, scope, broker.joiner, denied_event, denied_proofs,
                                           cursor_sha256=opened[0].cursor_sha256)
        check('exact_pam_execution_denial_adds_review_alert', denied_context.state == 'adverse'
              and refine_pam(before, denied_context).alert and refine_pam(before, denied_context).review)
        check('shared_execution_denial_adds_alert_without_execution', refine_service(before, denied).alert
              and not refine_service(before, denied).automatic_enforcement_allowed)
        install_registry(registry.model_copy(update={'authorities': [a.model_copy(update={'enabled': False})
            if a.kind == 'authentication' else a for a in registry.authorities]}))
        check('current_authentication_authority_revocation_rejects_old_capture', collect_pam_context(
            denied_capture, scope, broker.joiner, denied_event, denied_proofs,
            cursor_sha256=opened[0].cursor_sha256).state == 'unavailable')
        report['completed'] = True
    except Exception as error:
        report['failure_type'] = type(error).__name__
        report['failure_code'] = str(error) if isinstance(error, ValueError) else 'live_native_unavailable'
        raise
    finally:
        stop = command('stop', unit)
        command('reset-failed', unit)
        unit_path.unlink(missing_ok=True)
        reload_result = command('daemon-reload')
        state = command('show', '--property=ActiveState', '--value', unit)
        report['owned_units_removed'] = (not unit_path.exists() and reload_result.returncode == 0
            and state.stdout.strip() in {b'inactive', b'failed', b''})
        report['owned_processes_stopped'] = stop.returncode in {0, 5} and report['owned_units_removed']
        (output/'run.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    report = run(args.directory)
    print(json.dumps({k: report[k] for k in ('completed', 'cases', 'owned_units_removed', 'owned_processes_stopped')}))
    return 0 if report['completed'] and report['owned_units_removed'] and report['owned_processes_stopped'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
