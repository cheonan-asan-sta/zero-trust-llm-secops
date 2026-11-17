"""Observe actual native faults; explicit controller repairs original bytes only."""

import hashlib
import json
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature

from scripts.f1_lab.exec_recovery_inventory import inspect_recovery, intent_runs
from scripts.f1_lab.exec_recovery_status import publish, report
from scripts.f1_lab.native_jsonl import require


class RecoveryObserver:
    def __init__(self, lab, root, intents, outbox, scope, output, check):
        self.lab, self.root, self.intents, self.scope = lab, root, intents, scope
        self.output, self.check = output, check
        self.outbox = outbox
        # Publish on native private tmpfs. A Windows-mounted result directory
        # may report writable permissions and is not a trusted publisher root.
        self.directory = intents.parent / 'recovery-public'
        self.directory.mkdir(mode=0o755)
        self.frames = {}

    def inventory(self):
        return inspect_recovery(self.intents, self.root, self.scope,
                                self.lab.broker.joiner.registry, self.lab.broker.registry)

    def frame(self, name, *, expected=None, unavailable=False):
        values = None if unavailable else self.inventory()
        if expected is not None:
            require(all(values[k] == v for k, v in expected.items()), 'recovery_native_' + name)
        value = report(self.scope, values, now=datetime.now(UTC))
        publish(self.directory / ('recovery-' + name + '.json'), value)
        self.frames[name] = value
        return value

    def finish(self, unsealed, newest, journal, broker_view, app_view):
        # The base retention test removed its live cold DB after taking an
        # isolated backup. That original publication is genuinely missing.
        before = self.inventory()
        require(before['unpublished'] == 1, 'recovery_native_old_cold_loss_visible')
        self.check('recovery_inventory_retains_old_cold_loss_after_new_publication_succeeds')
        app_before = self.lab.operations.path.read_bytes()
        broker_before = self.lab.broker.path.read_bytes()
        latest = (self.root / 'latest.json').read_bytes()
        candidates = []
        for rid in intent_runs(self.intents):
            if rid in {unsealed, newest}:
                continue
            capture = self.intents / rid / 'capture.json'
            if capture.exists():
                # A singleton inspection uses the same publication check with
                # fully verified bytes; it does not trust outbox presence.
                from scripts.f1_lab.capture_backup import private_file
                from scripts.f1_lab.capture_store import capture_store_lock
                from scripts.f1_lab.collector_freshness import MAX_CAPTURE
                from scripts.f1_lab.exec_outbox import publication_states

                with capture_store_lock(self.root):
                    if not publication_states(self.root, self.scope,
                                              [(rid, private_file(capture, MAX_CAPTURE), None)])[rid]:
                        candidates.append(rid)
        require(len(candidates) == 1, 'recovery_native_exact_old_missing_original')
        result = journal.reconcile(candidates[0], broker_view, app_view, self.root,
                                   self.outbox, resume=True)
        require(result['publication_resumed'] and (self.root / 'latest.json').read_bytes() == latest,
                'recovery_native_old_original_not_latest_rollback')
        require(self.lab.operations.path.read_bytes() == app_before
                and self.lab.broker.path.read_bytes() == broker_before,
                'recovery_native_no_ledger_mutation')
        self.frame('publication-complete', expected={'intents': 5, 'sealed': 4,
                   'indeterminate': 1, 'unpublished': 0, 'published': 4})
        self.check('explicit_original_republication_fixes_old_loss_without_exec_or_grant_mutation')
        target = self.intents / unsealed / 'intent.json'
        original = target.read_bytes()
        damaged = json.loads(original)
        signature = damaged['signature']
        damaged['signature'] = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        try:
            target.write_text(json.dumps(damaged), encoding='utf8')
            try:
                self.inventory()
            except InvalidSignature:
                self.frame('unavailable', unavailable=True)
            else:
                raise AssertionError('damaged original signature accepted')
        finally:
            target.write_bytes(original)
        self.check('actual_intent_signature_damage_publishes_unavailable_without_cached_counts')
        self.frame('repaired', expected={'intents': 5, 'sealed': 4,
                   'indeterminate': 1, 'unpublished': 0, 'published': 4})
        origin = self.frames['indeterminate']['oldest_indeterminate_at']
        require(all(v['oldest_indeterminate_at'] == origin for k, v in self.frames.items()
                    if k != 'unavailable'), 'recovery_native_unknown_original_age')
        require(all(v['state'] == ('unavailable' if k == 'unavailable' else 'pending')
                    for k, v in self.frames.items()), 'recovery_native_never_ready')
        self.check('later_repair_never_refreshes_or_clears_original_indeterminate_execution')
        from scripts.f1_lab.exec_recovery_owner_controls import run

        security = run(self.lab, self.root, self.intents, self.scope, self.check)
        destination = self.output / 'recovery-public'
        destination.mkdir(exist_ok=False)
        for path in self.directory.iterdir():
            (destination / path.name).write_bytes(path.read_bytes())
        (self.output / 'recovery-controls.json').write_text(json.dumps({
            'completed': True, 'frames': {k: hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()
                                       for k, v in self.frames.items()},
            'actual_total_execs': 6, 'additional_monitor_execs': 0,
            'indeterminate_retained': 1, 'publication_missing_after_new_resume': 1,
            'explicit_old_original_republication': True, 'final_unpublished': 0,
            'final_state': 'pending', 'authorization_asserted': False,
            'nonroot_worker_security': security, 'aws_calls': 0, 'paid_api_calls': 0,
        }, indent=2) + '\n', encoding='utf8')
