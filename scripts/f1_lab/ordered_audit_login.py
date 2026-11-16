"""Source-pinned audit serial ordering for equal-time advisory LOGIN records.

Audit timestamps may have millisecond resolution. An increasing serial in the
same verified physical source can order equal-time events; it is not a new
authenticated person, process lifetime proof, grant or policy approval.
"""

import re
from decimal import Decimal

from scripts.f1_lab.audit_auth_review import AuditReview, field, number, original_audit_record
from scripts.f1_lab.native_jsonl import require

KEY = re.compile(r'^type=(?P<kind>[A-Z_]{1,32}) msg=audit\((?P<stamp>\d{1,12}(?:\.\d{1,9})?):(?P<serial>\d{1,20})\): (?P<body>[^\r\n]{1,8192})$')


class OrderedAuditReview(AuditReview):
    def __init__(self, events, source_sha256):
        super().__init__(events)
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}', source_sha256), 'ordered_audit_source')
        self.source_sha256 = source_sha256
        self.ordered_available = True
        self.last_key = None
        self.process_order = {}
        self.ordered_login_observations = 0

    def observe(self, line, time, *, source_sha256):
        require(source_sha256 == self.source_sha256, 'ordered_audit_source_changed')
        reason = super().observe(line, time)
        match = KEY.fullmatch(original_audit_record(line).rstrip('\r\n'))
        if match is None or time is None or float(match['stamp']) != time:
            self.ordered_available = False
            self.process_order.clear()
            return reason
        stamp, serial = Decimal(match['stamp']), int(match['serial'])
        if not 0 < serial < 2**64 or self.last_key is not None and (
            stamp < self.last_key[0] or serial < self.last_key[1]
            or serial == self.last_key[1] and stamp != self.last_key[0]
        ):
            self.ordered_available = False
        self.last_key = stamp, serial
        if not self.ordered_available:
            self.process_order.clear()
            return reason
        for pid, retained in list(self.process_order.items()):
            if self.processes.get(pid) != retained[0]:
                del self.process_order[pid]
        body, kind = match['body'], match['kind']
        pid = number(body, 'pid')
        process = self.processes.get(pid)
        if reason == 'web_service_su_followed_by_account_transition' and process:
            self.process_order[pid] = process, stamp, serial
        retained = self.process_order.get(pid)
        if (reason is None and kind == 'LOGIN' and retained and process == retained[0]
            and time == process[1] and stamp == retained[1] and serial > retained[2]
            and field(body, 'res') == '1' and number(body, 'auid') is not None
            and number(body, 'ses') is not None):
            self.ordered_login_observations += 1
            return 'web_service_su_followed_by_process_login'
        return reason
