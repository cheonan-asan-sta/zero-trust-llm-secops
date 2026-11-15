"""Actual broker process loss after systemd exec; reconciliation never launches."""

import hashlib
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.exec_history_launcher import HistoryUnitLauncher
from scripts.f1_lab.exec_intent import ExecIntentJournal
from scripts.f1_lab.native_jsonl import require


def run(lab, launcher, private, root, outbox, output, check, *, recovery_observability=False,
        scope=None, coherent_backup=False):
    journal = ExecIntentJournal(private/'intents',lab.broker.joiner.registry,lab.broker.registry)
    # This reconciliation facade exposes neither a signing key nor issuance,
    # launch, grant consumption or dispatch methods.
    broker_view = SimpleNamespace(registry=lab.broker.registry,
                                  joiner=SimpleNamespace(registry=lab.broker.joiner.registry),
                                  connect=lab.broker.connect)
    app_view = SimpleNamespace(policy_digest=lab.operations.policy_digest,
                              _transaction=lab.operations._transaction)
    observer = None
    if recovery_observability:
        from scripts.f1_lab.exec_recovery_controls import RecoveryObserver

        observer = RecoveryObserver(lab,root,private/'intents',outbox,scope,output,check)

    def execute_then_exit(phase, exit_code):
        for name in ('request.json','capture.json'):
            (launcher.directory/name).unlink()
        current = HistoryUnitLauncher(lab.target,launcher.argv,launcher.directory,
                                      source_id='local-proc',key_id='proc-1')
        gate = lab.gate(lab.new_request(),lab.new_access())
        child = os.fork()
        if child == 0:
            try:
                def disappear(*args, **kwargs):
                    os._exit(exit_code)

                method = 'seal_completed' if phase == 'pre_seal' else 'fresh_file'
                with patch.object(retention,method,side_effect=disappear):
                    retention.dispatch_and_retain(gate,current,lab.permission,root,outbox,
                                                 intent_root=private/'intents')
            finally:
                error = sys.exception()
                if error is not None:
                    (private/'owned-child-failure.txt').write_text(type(error).__name__,encoding='ascii')
                os._exit(90)
        waited, status = os.waitpid(child,0)
        require(waited == child and os.WIFEXITED(status) and os.WEXITSTATUS(status) == exit_code,
                'exec_intent_actual_child_exit')
        return gate.request.request_id

    latest_before = (root/'latest.json').read_bytes()
    unsealed = execute_then_exit('pre_seal',71)
    check('actual_broker_process_disappears_after_exec_before_seal')
    before_app = hashlib.sha256(lab.operations.path.read_bytes()).hexdigest()
    before_broker = hashlib.sha256(lab.broker.path.read_bytes()).hexdigest()
    unknown = journal.reconcile(unsealed,broker_view,app_view,root,outbox,resume=True)
    require(unknown['state'] == 'indeterminate' and unknown['worker_artifact_present']
            and unknown['app_grant_consumed'] and unknown['broker_state'] == 'bound'
            and not unknown['publication_resumed'] and not unknown['sealed_original_available'],
            'exec_intent_preseal_stays_unknown')
    check('app_consumption_broker_bound_and_worker_presence_do_not_invent_missing_full_seal')
    require((root/'latest.json').read_bytes() == latest_before
            and not (outbox/(unsealed+'.json')).exists(), 'exec_intent_no_invented_capture')
    check('preseal_process_loss_never_reexecutes_or_changes_published_latest')
    require(hashlib.sha256(lab.operations.path.read_bytes()).hexdigest() == before_app
            and hashlib.sha256(lab.broker.path.read_bytes()).hexdigest() == before_broker,
            'exec_intent_readonly_before_resume')
    check('unsealed_reconciliation_does_not_change_app_or_broker_ledgers')
    if observer is not None:
        observer.frame('indeterminate',expected={'intents':4,'sealed':3,'indeterminate':1,
                                               'unpublished':1,'published':2})
        check('recovery_inventory_observes_actual_preseal_loss_and_old_cold_publication_loss')

    sealed = execute_then_exit('pre_outbox',72)
    raw = (private/'intents'/sealed/'capture.json').read_bytes()
    require(not (outbox/(sealed+'.json')).exists(), 'exec_intent_outbox_not_written_before_exit')
    check('actual_second_broker_process_disappears_after_durable_seal_before_outbox')
    if observer is not None:
        observer.frame('pending',expected={'intents':5,'sealed':4,'indeterminate':1,
                                          'unpublished':2,'published':2})
        check('recovery_inventory_finds_completed_original_even_before_outbox_file_exists')
    before_app = hashlib.sha256(lab.operations.path.read_bytes()).hexdigest()
    before_broker = hashlib.sha256(lab.broker.path.read_bytes()).hexdigest()
    restarted = ExecIntentJournal(private/'intents',lab.broker.joiner.registry,lab.broker.registry)
    for _ in range(2):
        recovered = restarted.reconcile(sealed,broker_view,app_view,root,outbox,resume=True)
        require(recovered['state'] == 'sealed_original_verified' and recovered['publication_resumed'],
                'exec_intent_verified_resume')
    require((outbox/(sealed+'.json')).read_bytes() == raw and (root/'latest.json').read_bytes() == raw,
            'exec_intent_same_bytes_after_process_loss')
    check('new_reconciler_without_signer_launch_or_grant_api_resumes_same_original_bytes')
    require(hashlib.sha256(lab.operations.path.read_bytes()).hexdigest() == before_app
            and hashlib.sha256(lab.broker.path.read_bytes()).hexdigest() == before_broker,
            'exec_intent_no_reauthorization')
    check('repeated_sealed_reconciliation_never_consumes_refunds_or_reissues_authorization')
    require(not (outbox/(unsealed+'.json')).exists()
            and not (private/'intents'/unsealed/'capture.json').exists(), 'exec_intent_unknown_not_upgraded')
    check('later_success_does_not_promote_an_older_indeterminate_execution')
    if observer is not None:
        observer.frame('partial',expected={'intents':5,'sealed':4,'indeterminate':1,
                                          'unpublished':1,'published':3})
        observer.finish(unsealed,sealed,restarted,broker_view,app_view)
        if coherent_backup:
            from scripts.f1_lab.exec_bundle_controls import run as run_bundle

            run_bundle(lab,launcher,private,root,restarted,scope,output,check)
    (output/'intent-controls.json').write_text(json.dumps({
        'completed':True,'actual_additional_execs':2,'actual_broker_process_losses':2,
        'total_execs_including_outbox_base_four':6,
        'preseal_loss_state':'indeterminate','preseal_command_reexecuted':False,
        'sealed_original_recovered_byte_exact':True,'authorization_reissued':False,
        'grant_refunded':False,'reconciler_has_signing_key':False,
        'reconciliation_app_broker_bytes_unchanged':True,
        'aws_calls':0,'paid_api_calls':0,
        'local_oidc_fixture':True,'real_organization_identity':False,
    },indent=2)+'\n',encoding='utf8')
