"""Capture actual typed backup/review integrity transitions before cleanup."""

import json

from scripts.f1_lab import exec_bundle_status as status
from scripts.f1_lab.native_jsonl import require


class BundleObserver:
    def __init__(self, lab, private, package, review, checkpoint, checkpoint_sha256,
                 receipt_sha256, scope, output, check):
        self.lab, self.package, self.review = lab, package, review
        self.checkpoint, self.checkpoint_sha256, self.receipt_sha256 = checkpoint, checkpoint_sha256, receipt_sha256
        self.scope, self.output, self.check = scope, output, check
        self.directory = private/'bundle-public'
        self.directory.mkdir(mode=0o755)
        self.frames = {}

    def inspect(self):
        return status.inspect(self.scope, self.package, self.checkpoint, self.checkpoint_sha256,
            self.review, self.receipt_sha256, self.lab.broker.joiner.registry, self.lab.broker.registry)

    def frame(self, name, *, damaged=False):
        if damaged:
            try:
                self.inspect()
            except ValueError:
                value = status.report(self.scope)
            else:
                raise AssertionError('damaged encrypted package reported verified')
        else:
            value = self.inspect()
            require(value['values']['indeterminate'] == 1 and value['values']['sealed'] == 4
                    and value['values']['intents'] == 5, 'bundle_monitor_original_unknown')
        status.publish(self.directory/('bundle-'+name+'.json'), value)
        self.frames[name] = value

    def finish(self):
        require(set(self.frames) == {'verified', 'unavailable', 'repaired'}
                and self.frames['verified']['values'] == self.frames['repaired']['values']
                and self.frames['unavailable']['values'] == {}, 'bundle_monitor_original_times')
        self.check('keyless_bundle_status_retains_actual_snapshot_restore_times_and_one_unknown_after_repair')
        self.check('actual_ciphertext_damage_publishes_unavailable_without_cached_bundle_counts')
        from scripts.f1_lab.exec_bundle_owner_controls import run

        security = run(self.lab, self.package, self.review, self.checkpoint,
            self.checkpoint_sha256, self.receipt_sha256, self.scope, self.check)
        destination = self.output/'bundle-public'
        destination.mkdir(exist_ok=False)
        for path in self.directory.iterdir():
            (destination/path.name).write_bytes(path.read_bytes())
        (self.output/'bundle-observability-controls.json').write_text(json.dumps({
            'completed': True, 'actual_total_execs': 6, 'additional_protected_execs': 0,
            'actual_ciphertext_damaged_then_restored': True, 'original_dates_preserved': True,
            'indeterminate_retained': 1, 'actual_nonroot_worker': security,
            'keyless_worker_has_recovery_key': False, 'keyless_worker_has_signing_keys': False,
            'copied_evidence_ownership_fixture': True, 'production_acl_migration_complete': False,
            'automatic_activation_allowed': False, 'authorization_asserted': False,
            'aws_calls': 0, 'paid_api_calls': 0,
        }, indent=2)+'\n', encoding='utf8')
