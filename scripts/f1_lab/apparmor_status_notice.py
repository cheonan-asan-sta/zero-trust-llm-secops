"""Current AppArmor notice categories for advisory triage, never approval.

A profile replacement can change policy. A STATUS notice alone supplies no
verified caller or authorization. Its learned category may lower a generic
alert only with supported training counts; review must remain required.
"""

import hashlib
import math
import re

from scripts.f1_lab.apparmor_noop import parsed, positive
from scripts.f1_lab.audit_auth_review import original_audit_record
from scripts.f1_lab.audit_intent_context import HARD, IntentObservation
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_observations import raw_features

PROFILE = 'apparmor-current-status-notice-1'


class AppArmorStatusReview:
    def __init__(self, source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}', source_sha256),
                'apparmor_status_source')
        self.source = source_sha256
        self.ordinal = self.size = 0
        self.time = self.serial = self.identity = None
        self.kinds = set()
        self.disabled = False

    def observe(self, ordinal, line, moment, *, source_sha256):
        require(type(ordinal) is int and 0 < ordinal <= 100000 and type(line) is str
                and len(line.encode()) <= MAX_ROW, 'apparmor_status_row')
        empty = IntentObservation(self.source, ordinal, hashlib.sha256(line.encode()).hexdigest(),
                                  ('unknown',), False)
        if self.disabled:
            return empty
        self.size += len(line.encode())
        if (source_sha256 != self.source or ordinal != self.ordinal + 1
                or self.size > 64 * 1024**2 or type(moment) not in {int, float}
                or not math.isfinite(moment) or moment < 0
                or self.time is not None and moment < self.time):
            self.disabled = True
            return empty
        self.ordinal, self.time = ordinal, moment
        item = parsed(line)
        if item is None:
            return empty
        identity, kind, data = item
        if float(identity[0]) != moment:
            self.disabled = True
            return empty
        if kind in {'SYSTEM_BOOT', 'SYSTEM_SHUTDOWN', 'DAEMON_START'}:
            self.serial, self.identity, self.kinds = None, None, set()
            return empty
        serial = int(identity[1])
        if self.serial is not None and serial < self.serial:
            self.disabled = True
            return empty
        if identity != self.identity:
            self.identity, self.kinds = identity, set()
        self.serial = serial
        if kind in self.kinds:
            # Future duplicates cannot rewrite an already emitted observation.
            return empty
        self.kinds.add(kind)
        if (kind != 'AVC' or data.get('apparmor') != 'STATUS'
                or data.get('operation') != 'profile_replace'
                or data.get('profile') != 'unconfined'
                or data.get('comm') != 'apparmor_parser' or not positive(data.get('pid'))
                or not re.fullmatch(r'/[^\x00-\x20\x7f]{1,255}', data.get('name', ''))
                or re.search(r'[;&|<>`$]', data.get('name', ''))
                or any(k in data for k in ('error', 'denied_mask', 'requested_mask'))
                or data.get('info') not in {None, 'same as current profile, skipping'}
                or any(raw_features(original_audit_record(line))[k] for k in HARD)):
            return empty
        uid = data.get('uid')
        if uid is not None and (not re.fullmatch(r'0|[1-9]\d{0,9}', uid) or int(uid) >= 4294967295):
            return empty
        role = 'uid_missing' if uid is None else 'reported_root' if uid == '0' else 'reported_nonroot'
        mode = 'changed_profile' if data.get('info') is None else 'unchanged_profile'
        feature = ('apparmor_status_notice', kind, 'current_record_only', mode, role, 'caller_unverified')
        return IntentObservation(self.source, ordinal, empty.line_sha256, feature, True)
