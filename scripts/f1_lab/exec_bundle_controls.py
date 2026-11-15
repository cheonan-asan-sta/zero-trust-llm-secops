"""Actual six-exec fixture: lose typed sources, restore only isolated review."""

import json
import secrets
import shutil

from cryptography.exceptions import InvalidTag

from scripts.f1_lab.exec_bundle_backup import ExecutionRecoveryBundle
from scripts.f1_lab.native_jsonl import require


def run(lab, launcher, private, root, journal, scope, output, check, *, bundle_observability=False):
    from scripts.f1_lab.capture_backup import sha

    for path in (lab.operations.path, lab.broker.path):
        path.chmod(0o600)
        path.parent.chmod(0o700)
    packages, pins, reviews = [private/name for name in ('bundle-packages', 'bundle-pins', 'bundle-reviews')]
    for path in (packages, pins, reviews):
        path.mkdir(mode=0o700)
    manager = ExecutionRecoveryBundle(scope, journal.service_pin, journal.caller_pin)
    app_raw, broker_raw = lab.operations.path.read_bytes(), lab.broker.path.read_bytes()
    latest = (root/'latest.json').read_bytes()
    originals = {p.relative_to(journal.directory).as_posix(): p.read_bytes()
                 for p in journal.directory.glob('*/*.json')}
    key = secrets.token_bytes(32)
    saved = manager.backup(journal, lab.broker, lab.operations, [launcher.directory],
                           packages/'snapshot', pins/'checkpoint.json', key, 'owned-recovery-1')
    require(saved['intents'] == 5 and saved['sealed'] == 4 and saved['indeterminate'] == 1
            and saved['worker_artifacts'] == 1, 'exec_bundle_native_snapshot_counts')
    require(lab.operations.path.read_bytes() == app_raw and lab.broker.path.read_bytes() == broker_raw
            and (root/'latest.json').read_bytes() == latest, 'exec_bundle_native_snapshot_readonly')
    check('consistent_intent_broker_app_snapshot_preserves_actual_four_seals_and_one_unknown')
    check('snapshot_changes_no_app_grant_broker_record_latest_or_execution')
    package = packages/'snapshot'
    require({p.name for p in package.iterdir()} == {'manifest.json', 'payload.aesgcm'},
            'exec_bundle_native_no_secret_files')
    check('aes256gcm_bundle_contains_typed_payload_only_without_private_key_token_or_argv_files')
    for path in (lab.operations.path, lab.broker.path):
        path.unlink()
    shutil.rmtree(journal.directory)
    shutil.rmtree(launcher.directory)
    restored = manager.restore(package, reviews/'isolated', pins/'checkpoint.json',
                                saved['checkpoint_sha256'], key, 'owned-recovery-1')
    review = reviews/'isolated'
    require((review/'app.sqlite3').read_bytes() == app_raw
            and (review/'broker.sqlite3').read_bytes() == broker_raw,
            'exec_bundle_native_original_database_bytes')
    require({p.relative_to(review/'intents').as_posix(): p.read_bytes()
             for p in (review/'intents').glob('*/*.json')} == originals,
            'exec_bundle_native_original_intent_bytes')
    check('after_actual_selected_source_loss_isolated_restore_matches_databases_and_all_intent_seal_bytes')
    verified = manager.verify_review(review, restored['receipt_sha256'], pins/'checkpoint.json',
                                     saved['checkpoint_sha256'])
    require(verified['indeterminate'] == 1 and verified['sealed'] == 4
            and not verified['authorization_asserted'] and not verified['automatic_activation_allowed'],
            'exec_bundle_native_unknown_stays_unknown')
    require(not lab.operations.path.exists() and not lab.broker.path.exists()
            and not journal.directory.exists() and not launcher.directory.exists()
            and (root/'latest.json').read_bytes() == latest,
            'exec_bundle_native_no_live_replacement')
    check('restore_never_follows_original_worker_path_or_recreates_live_app_broker_or_intent_stores')
    check('restored_consumed_or_unknown_execution_is_not_refunded_reissued_or_promoted')
    observer = None
    if bundle_observability:
        from scripts.f1_lab.exec_bundle_observability_controls import BundleObserver

        observer = BundleObserver(lab,private,package,review,pins/'checkpoint.json',
            saved['checkpoint_sha256'],restored['receipt_sha256'],scope,output,check)
        observer.frame('verified')
    try:
        manager.restore(package, reviews/'wrong-key', pins/'checkpoint.json',
                        saved['checkpoint_sha256'], secrets.token_bytes(32), 'owned-recovery-1')
    except InvalidTag:
        require(not (reviews/'wrong-key').exists(), 'exec_bundle_native_bad_key_no_output')
    else:
        raise AssertionError('wrong recovery key accepted')
    check('wrong_recovery_key_is_rejected_before_any_review_destination_exists')
    payload = package/'payload.aesgcm'
    original = payload.read_bytes()
    try:
        payload.write_bytes(bytes([original[0] ^ 1])+original[1:])
        if observer is not None:
            observer.frame('unavailable',damaged=True)
        try:
            manager.restore(package, reviews/'damaged', pins/'checkpoint.json',
                            saved['checkpoint_sha256'], key, 'owned-recovery-1')
        except ValueError:
            require(not (reviews/'damaged').exists(), 'exec_bundle_native_corruption_no_output')
        else:
            raise AssertionError('damaged pinned ciphertext accepted')
    finally:
        payload.write_bytes(original)
    check('actual_ciphertext_damage_fails_external_pin_without_stale_success_or_activation')
    require(manager.verify_review(review, restored['receipt_sha256'], pins/'checkpoint.json',
                                   saved['checkpoint_sha256'])['completed'], 'exec_bundle_native_recheck')
    check('keyless_review_recheck_retains_original_state_after_encrypted_package_damage_and_repair')
    if observer is not None:
        observer.frame('repaired')
        observer.finish()
    (output/'bundle-controls.json').write_text(json.dumps({
        'completed': True, 'actual_total_execs': 6, 'additional_backup_execs': 0,
        'intent_backed_execs': 5, 'first_manual_exec_outside_intent_bundle': 1,
        'sealed_originals': 4, 'indeterminate': 1, 'worker_artifacts_present': 1,
        'worker_path_reused_for_older_intents': True, 'selected_sources_actually_removed': True,
        'databases_and_all_intent_seals_byte_exact': True, 'checkpoint_sha256': saved['checkpoint_sha256'],
        'payload_sha256': sha(original), 'encrypted_bytes': len(original),
        'review_verified_without_recovery_key': True, 'automatic_activation_allowed': False,
        'original_worker_paths_followed': False, 'grant_refunded': False,
        'organization_sso_tested': False, 'physical_offsite_recovery_tested': False,
        'aws_calls': 0, 'paid_api_calls': 0,
    }, indent=2)+'\n', encoding='utf8')
