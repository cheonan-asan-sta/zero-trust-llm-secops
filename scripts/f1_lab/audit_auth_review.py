"""Causal, source-scoped account transition observations; offline advisory only."""

import math
import re
import shlex
from bisect import bisect_left
from dataclasses import dataclass

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_refinement import OperationDecision

WINDOW = 5.0
SERVICE_ACCOUNTS = frozenset({"www-data", "apache", "nginx", "httpd"})
ACCOUNT = r"[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?"
SYSLOG = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} [^\s]{1,255} "
    r"su\[(?P<pid>\d{1,10})\]: (?P<body>[^\r\n]{1,1024})$"
)
SUCCESS = re.compile(rf"Successful su for (?P<target>{ACCOUNT}) by (?P<caller>{ACCOUNT})")
PLUS = re.compile(rf"\+ /dev/pts/\d{{1,10}} (?P<caller>{ACCOUNT}):(?P<target>{ACCOUNT})")
AUDIT = re.compile(
    r"^type=(?P<kind>[A-Z_]{1,32}) msg=audit\(\d+(?:\.\d+)?:\d+\): (?P<body>[^\r\n]{1,8192})$"
)


def moment(value):
    require(
        value is None or type(value) in {int, float} and math.isfinite(value), "audit_auth_time"
    )


def su_transition(line):
    require(isinstance(line, str) and len(line.encode("utf8")) <= MAX_ROW, "audit_auth_line")
    match = SYSLOG.fullmatch(line.rstrip("\r\n"))
    if match is None or not 0 < int(match["pid"]) < 4294967295:
        return None
    action = SUCCESS.fullmatch(match["body"]) or PLUS.fullmatch(match["body"])
    if action and action["caller"] in SERVICE_ACCOUNTS and action["target"] != action["caller"]:
        return int(match["pid"]), action["target"]
    return None


@dataclass(frozen=True)
class SuEvent:
    time: float
    pid: int
    account: str


def caller_events(records):
    """One host's explicitly bound auth source; no label parameter is accepted."""
    events = []
    high_water = None
    for time, line in records:
        moment(time)
        if time is None:
            continue
        # A regressed source is unavailable for cross-source causal linkage.
        if high_water is not None and time < high_water:
            return ()
        high_water = time
        transition = su_transition(line)
        if transition:
            require(len(events) < 20000, "audit_auth_seed_bound")
            events.append(SuEvent(time, *transition))
    return tuple(events)


def field(body, name):
    try:
        outer = shlex.split(body)
        if len(outer) > 128:
            return None
        pairs = [token.split("=", 1) for token in outer]
        if any(len(pair) != 2 for pair in pairs):
            return None
        messages = [value for key, value in pairs if key == "msg"]
        if len(messages) > 1:
            return None
        if messages:
            inner = [token.split("=", 1) for token in shlex.split(messages[0])]
            if len(inner) > 128 or any(len(pair) != 2 for pair in inner):
                return None
            pairs = [(key, value) for key, value in pairs if key != "msg"] + inner
        if len({key for key, _ in pairs}) != len(pairs):
            return None
        return dict(pairs).get(name)
    except ValueError:
        return None


def number(body, name):
    value = field(body, name)
    return (
        int(value)
        if value and re.fullmatch(r"\d{1,10}", value) and int(value) < 4294967295
        else None
    )


class AuditReview:
    """Never link by missing auid/session, adjacent PID or service name guesses.

    Cross-source seed requires exact reported su PID/account and strictly past
    time. Subsequent account/process/user-unit observations are descriptive
    associations, not authenticated users or evidence of absent authorization.
    """

    def __init__(self, events=()):
        require(
            isinstance(events, tuple)
            and len(events) <= 20000
            and all(isinstance(e, SuEvent) for e in events),
            "audit_auth_seeds",
        )
        self.events = {}
        for event in events:
            moment(event.time)
            require(
                event.time is not None
                and type(event.pid) is int
                and 0 < event.pid < 4294967295
                and isinstance(event.account, str)
                and re.fullmatch(ACCOUNT, event.account),
                "audit_auth_seed_value",
            )
            self.events.setdefault((event.pid, event.account), []).append(event.time)
        for values in self.events.values():
            values.sort()
        self.risks, self.processes, self.users = {}, {}, {}
        self.high_water = None

    def observe(self, line, time):
        require(isinstance(line, str) and len(line.encode("utf8")) <= MAX_ROW, "audit_auth_line")
        moment(time)
        if time is None or self.high_water is not None and time < self.high_water:
            self.risks, self.processes, self.users = {}, {}, {}
            self.high_water = time
            return None
        self.high_water = time
        for mapping in (self.risks, self.processes, self.users):
            for key in list(mapping):
                if mapping[key][-1] < time - WINDOW:
                    del mapping[key]
        match = AUDIT.fullmatch(line.rstrip("\r\n"))
        if not match:
            return None
        body, kind = match["body"], match["kind"]
        pid, account, executable = number(body, "pid"), field(body, "acct"), field(body, "exe")
        success = field(body, "res") == "success"
        if kind == "USER_AUTH" and success and executable in {"/bin/su", "/usr/bin/su"} and pid:
            seeds = self.events.get((pid, account), [])
            first, last = bisect_left(seeds, time - WINDOW), bisect_left(seeds, time)
            if first < last:
                require(
                    account in self.risks or len(self.risks) < 10000, "audit_auth_account_bound"
                )
                # No repeated message may refresh the original episode's TTL.
                self.risks.setdefault(account, (seeds[first],))
            return None
        if (pid in self.processes and kind in {"USER_ACCT", "CRED_ACQ", "USER_START", "USER_END"}
                and (account != self.processes[pid][0] or kind == "USER_END")):
            del self.processes[pid]
        origin = self.risks.get(account)
        if (
            origin
            and 0 < time - origin[0] <= WINDOW
            and success
            and pid
            and executable in {"/lib/systemd/systemd", "/usr/lib/systemd/systemd"}
            and kind in {"USER_ACCT", "CRED_ACQ", "USER_START"}
        ):
            require(
                pid in self.processes or len(self.processes) < 10000, "audit_auth_process_bound"
            )
            self.processes[pid] = (account, time, origin[0])
            uid, session = number(body, "auid"), number(body, "ses")
            if kind == "USER_START" and uid is not None and uid > 0 and session is not None:
                require(uid in self.users or len(self.users) < 10000, "audit_auth_user_bound")
                self.users[uid] = (time, origin[0])
            return "web_service_su_followed_by_account_transition"
        process = self.processes.get(pid)
        if (
            kind == "LOGIN"
            and process
            and time > process[1]
            and field(body, "res") == "1"
            and number(body, "auid") is not None
            and number(body, "ses") is not None
        ):
            return "web_service_su_followed_by_process_login"
        unit = field(body, "unit") or ""
        user_unit = re.fullmatch(r"user@(\d{1,10})(?:\.service)?", unit)
        if (
            kind == "SERVICE_START"
            and success
            and pid == 1
            and number(body, "uid") == 0
            and user_unit
            and executable in {"/lib/systemd/systemd", "/usr/lib/systemd/systemd"}
        ):
            user = self.users.get(int(user_unit[1]))
            if user and time > user[0]:
                return "web_service_su_followed_by_user_manager"
        return None


def refine(previous, reason):
    require(
        isinstance(previous, OperationDecision) and previous.automatic_enforcement_allowed is False,
        "audit_auth_previous",
    )
    require(
        type(previous.alert) is bool
        and type(previous.review) is bool
        and all(
            type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
            for v in [previous.baseline_score, previous.score]
        ),
        "audit_auth_score",
    )
    require(
        reason
        in {
            None,
            "web_service_account_su",
            "web_service_su_followed_by_account_transition",
            "web_service_su_followed_by_process_login",
            "web_service_su_followed_by_user_manager",
        },
        "audit_auth_reason",
    )
    if previous.alert or reason is None:
        return previous
    return OperationDecision(previous.baseline_score, max(previous.score, 0.95), True, True, reason)
