"""Bounded, read-only transport verification with non-secret failure receipts.

Container auto-removal is preserved. An exit of 137 is not an OOM finding:
the daemon state is no longer available and is deliberately reported unknown.
Mutating custodians never use this path and are never retried or removed here.
"""

import json
import subprocess
import uuid

from scripts.continuous_mtls_runtime import RuntimeFailure

CHILD_REASONS = frozenset({
    'database_transport_ceremony_failed', 'transport_journal_shape',
    'transport_journal_sequence', 'transport_journal_pending', 'transport_plan_scope',
    'transport_plan_signature', 'transport_plan_key_or_root', 'transport_published_file_changed',
    'database_transport_regular_file_required', 'database_transport_private_file_required',
    'database_transport_file_size', 'database_transport_single_certificate_required',
    'database_transport_certificate_invalid', 'database_transport_scope',
    'database_transport_root_changed', 'database_transport_identity_or_key_invalid',
    'transport_filesystem_failure', 'transport_invalid_input', 'transport_crypto_failure',
})
FAILURES = frozenset({'child_failed', 'invalid_receipt', 'timeout', 'launch_failed'})


def child_reason(error):
    """Do not reflect exception text, filenames, library messages or key data."""
    value = str(error)
    if value in CHILD_REASONS:
        return value
    if isinstance(error, OSError):
        return 'transport_filesystem_failure'
    if isinstance(error, (ValueError, TypeError, KeyError, AttributeError, OverflowError)):
        return 'transport_invalid_input'
    return 'transport_crypto_failure'


class VerificationFailure(RuntimeFailure):
    def __init__(self, reason, *, exit_code=None, child=None, cleanup=None):
        super().__init__('database_transport_verification_failed')
        self.diagnostic = {
            'schema': 'transport-verification-failure-1', 'operation': 'verify',
            'reason': reason if type(reason) is str and reason in FAILURES else 'invalid_receipt',
            'cli_exit_code': exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
            'child_reason': child if type(child) is str and child in CHILD_REASONS else None,
            'owned_helper_cleanup_confirmed': cleanup if type(cleanup) is bool else None,
            'oom_killed': None, 'container_state_available': False,
        }


def decode(raw):
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > 32768:
        raise ValueError('receipt')

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate')
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    if not isinstance(value, dict):
        raise TypeError('receipt')
    return value


def timeout_cleanup(name, token, image):
    """Only the single read-only helper created for this invocation may be killed."""
    try:
        inspected = subprocess.run(['docker', 'inspect', name], capture_output=True,
                                   text=True, encoding='utf-8', timeout=10, check=False)
        if inspected.returncode:
            # A failed daemon query does not establish absence.
            return False
        values = json.loads(inspected.stdout)
        if not isinstance(values, list) or len(values) != 1:
            return False
        value = values[0]
        config, host = value['Config'], value['HostConfig']
        if (value['Name'] != '/' + name or value['Image'] != image
                or config.get('Labels', {}).get('secops.transport.verify') != token
                or config.get('User') != '10001:10001'
                or host.get('NetworkMode') != 'none' or host.get('ReadonlyRootfs') is not True
                or host.get('CapDrop') != ['ALL']
                or any(mount.get('RW') is not False for mount in value.get('Mounts', []))):
            return False
        removed = subprocess.run(['docker', 'rm', '--force', value['Id']],
                                 capture_output=True, timeout=10, check=False)
        return removed.returncode == 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.TimeoutExpired):
        return False


def verify(argv, *, payload, epoch, pending, partial, image):
    token = uuid.uuid4().hex
    name = 'secops-transport-verify-' + token
    args = [*argv[:2], '--name', name, '--label', 'secops.transport.verify=' + token, *argv[2:]]
    try:
        result = subprocess.run(args, input=payload, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=20, check=False)
    except subprocess.TimeoutExpired:
        raise VerificationFailure('timeout', cleanup=timeout_cleanup(name, token, image)) from None
    except OSError:
        raise VerificationFailure('launch_failed') from None
    try:
        receipt = decode(result.stdout)
    except (ValueError, TypeError, UnicodeError):
        raise VerificationFailure('invalid_receipt', exit_code=result.returncode) from None
    if result.returncode:
        raise VerificationFailure('child_failed', exit_code=result.returncode,
                                  child=receipt.get('reason')) from None
    if (set(receipt) != {'verified', 'epoch', 'pending', 'transport'}
            or receipt['verified'] is not True or type(receipt['epoch']) is not int
            or receipt['epoch'] != epoch or type(receipt['pending']) is not bool
            or receipt['pending'] != pending
            or (partial and receipt['transport'] is not None)
            or (not partial and (not isinstance(receipt['transport'], dict)
                or receipt['transport'].get('schema') != 'database-transport-preflight-1'
                or receipt['transport'].get('verified') is not True))):
        raise VerificationFailure('invalid_receipt', exit_code=result.returncode) from None
    return receipt
