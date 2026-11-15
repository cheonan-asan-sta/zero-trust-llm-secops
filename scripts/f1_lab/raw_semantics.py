"""Bounded HTTP/auth observations; no raw identifiers, truth or access decisions."""

import hashlib
import math
import re
from collections import Counter, deque
from urllib.parse import unquote, urlsplit

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.raw_observations import REQUEST, bucket, raw_features

PROFILE = 'raw-http-auth-semantics-4'
SEMANTIC_DOMAINS = {
    'http_semantic_available': (False, True), 'http_semantic_parse_error': (False, True),
    'http_encoding_replacement': (False, True), 'http_percent_layers': (0, 1, 2),
    'http_query_parameters': tuple(range(7)), 'http_query_duplicate_keys': (False, True),
    'http_query_size': tuple(range(7)), 'http_path_depth': tuple(range(7)),
    'http_path_extension': ('none', 'script', 'static', 'document', 'archive', 'other'),
    'http_sql_terms': tuple(range(7)), 'http_sql_boolean_comparison': (False, True),
    'http_sql_comment': (False, True), 'http_shell_separator': (False, True),
    'http_template_syntax': (False, True), 'http_query_base64_shape': (False, True),
    'http_user_agent_kind': ('unavailable', 'browser', 'http_client', 'scanner', 'bot', 'other'),
    'auth_service_kind': ('none', 'ssh', 'su', 'sudo', 'cron', 'systemd', 'other'),
    'auth_observed_uid_kind': ('unknown', 'root', 'system_range', 'user_range', 'unset'),
    'auth_target_root_observed': (False, True), 'auth_new_session_notice': (False, True),
    'audit_login_uid_available': (False, True), 'audit_session_available': (False, True),
    'audit_login_uid_assigned': (False, True), 'audit_session_assigned': (False, True),
    'audit_program_kind': ('none', 'su', 'sudo', 'cron', 'systemd', 'other'),
    'audit_extended_type': ('other', 'LOGIN', 'USER_LOGIN', 'USER_LOGOUT', 'USER_ERR'),
    'auth_subject_context_available': (False, True),
    'auth_subject_prior_events': tuple(range(7)),
    'auth_subject_prior_privilege_tool': (False, True),
    'auth_subject_prior_failure': (False, True),
    'auth_subject_prior_sensitive_or_shell': (False, True),
}
HISTORY_NAMES = tuple(name for name in SEMANTIC_DOMAINS if name.startswith('auth_subject_'))
SERVICES = {'sshd': 'ssh', 'su': 'su', 'sudo': 'sudo', 'cron': 'cron',
            'systemd': 'systemd', 'systemd-logind': 'systemd'}
SYSLOG_SERVICE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ '
                            r'(?P<service>[A-Za-z0-9_-]+)(?:\[\d+\])?:\s*(?P<message>.*)$')
ACCOUNT = r'[A-Za-z0-9_.@-]{1,128}'


def history_empty():
    return {name: SEMANTIC_DOMAINS[name][0] for name in HISTORY_NAMES}


def uid_kind(number):
    if number is None or not 0 <= number <= 4294967295:
        return 'unknown'
    if number == 4294967295:
        return 'unset'
    return 'root' if number == 0 else 'system_range' if number < 1000 else 'user_range'


def semantic_observations(line):
    require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'semantic_line_bound')
    result = {name: domain[0] for name, domain in SEMANTIC_DOMAINS.items()}
    request = REQUEST.search(line)
    if request:
        target = request[2]
        try:
            for _ in range(2):
                decoded = unquote(target)
                if decoded == target:
                    break
                result['http_percent_layers'] += 1
                target = decoded
            result['http_encoding_replacement'] = '\ufffd' in target
            parsed = urlsplit(target)
            query, path = parsed.query, parsed.path
            parameters = query.split('&') if query else []
            require(len(parameters) <= 64, 'semantic_query_parameter_bound')
            keys = [parameter.split('=', 1)[0] for parameter in parameters]
            result.update(http_semantic_available=True,
                          http_query_parameters=bucket(len(parameters), (1, 2, 3, 5, 10, 25)),
                          http_query_duplicate_keys=len(set(keys)) < len(keys),
                          http_query_size=bucket(len(query), (16, 32, 64, 128, 256, 1024)),
                          http_path_depth=bucket(len([part for part in path.split('/') if part]), (1, 2, 3, 5, 8, 12)))
            suffix = path.rsplit('/', 1)[-1].rsplit('.', 1)
            if len(suffix) == 2:
                extension = suffix[-1].lower()
                families = {'script': {'php', 'phtml', 'jsp', 'asp', 'aspx', 'cgi'},
                            'static': {'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2'},
                            'document': {'html', 'htm', 'pdf', 'txt', 'xml', 'json'},
                            'archive': {'zip', 'gz', 'tar', '7z', 'rar'}}
                result['http_path_extension'] = next((kind for kind, values in families.items() if extension in values), 'other')
            sql_query = query.replace('+', ' ')
            sql = re.findall(r'\b(?:select|union|from|where|sleep|benchmark|information_schema|xp_cmdshell)\b', sql_query, re.IGNORECASE)
            result['http_sql_terms'] = bucket(len(sql), (1, 2, 3, 5, 10, 20))
            result['http_sql_boolean_comparison'] = bool(re.search(r"\b(?:or|and)\s+[\x27\"]?\d+[\x27\"]?\s*=\s*[\x27\"]?\d+", sql_query, re.IGNORECASE))
            result['http_sql_comment'] = bool(re.search(r'--|/\*|\*/', query))
            result['http_shell_separator'] = bool(re.search(r';|\|\||&&|\$\(|`|/dev/tcp/', query))
            result['http_template_syntax'] = bool(re.search(r'\{\{|\}\}|\$\{|<%|%>', query))
            result['http_query_base64_shape'] = any(re.fullmatch(r'[A-Za-z0-9+/]{40,}={0,2}', value.split('=', 1)[-1]) for value in parameters)
        except ValueError:
            result['http_semantic_parse_error'] = True
        agent = re.search(r'"([^"\n]{0,4096})"\s*$', line[request.end():])
        if agent:
            text = agent[1].lower()
            patterns = [('scanner', r'nmap|sqlmap|nikto|wpscan|gobuster|dirbuster'),
                        ('http_client', r'curl|wget|python|urllib|aiohttp|httpclient'),
                        ('bot', r'bot|spider|crawler'), ('browser', r'mozilla|chrome|firefox|safari|opera|edge')]
            result['http_user_agent_kind'] = next((name for name, pattern in patterns if re.search(pattern, text)), 'other')
    service = SYSLOG_SERVICE.match(line)
    if service:
        result['auth_service_kind'] = SERVICES.get(service['service'].lower(), 'other')
    audit_record = bool(re.match(r'^type=[A-Z_]+\s+', line))
    observed_uid = re.search(r'\bby \(uid=(\d{1,10})\)|(?:^|\s)uid=(\d{1,10})(?:\s|$)', line) if service or audit_record else None
    if observed_uid:
        result['auth_observed_uid_kind'] = uid_kind(int(observed_uid[1] or observed_uid[2]))
    if service or audit_record:
        result['auth_target_root_observed'] = bool(re.search(r'(?:for user |\bUSER=|\bacct=")root(?=[\s";]|$)', line))
    result['auth_new_session_notice'] = bool(service and service['service'] == 'systemd-logind'
                                              and re.search(r'\bNew session \S+ of user ', service['message']))
    for field, target in (('auid', 'audit_login_uid_assigned'), ('ses', 'audit_session_assigned')):
        value = re.search(r'(?:^|\s)'+field+r'=(\d{1,10})(?:\s|$)', line) if audit_record else None
        valid = bool(value and int(value[1]) <= 4294967295)
        result['audit_login_uid_available' if field == 'auid' else 'audit_session_available'] = valid
        result[target] = bool(valid and int(value[1]) != 4294967295)
    program = re.search(r'\bexe="([^"]{1,1024})"', line) if audit_record else None
    if program:
        basename = program[1].rsplit('/', 1)[-1]
        result['audit_program_kind'] = basename if basename in {'su', 'sudo', 'cron', 'systemd'} else 'other'
    event_type = re.match(r'^type=(LOGIN|USER_LOGIN|USER_LOGOUT|USER_ERR)\b', line)
    if event_type:
        result['audit_extended_type'] = event_type[1]
    return result


def subject_reference(line):
    record = SYSLOG_SERVICE.match(line)
    if record is None:
        return None
    message = record['message']
    service = record['service'].lower()
    patterns = []
    if service == 'su':
        patterns.append(r'\bSuccessful su for ('+ACCOUNT+r') by ')
    if service in SERVICES:
        patterns.append(r'\bsession (?:opened|closed) for user ('+ACCOUNT+r')(?:\s|$)')
    if service == 'systemd-logind':
        patterns.append(r'\bNew session \S+ of user ('+ACCOUNT+r'?)\.\s*$')
    if service == 'sshd':
        patterns.append(r'^(?:Accepted|Failed) (?:password|publickey) for (?:invalid user )?('+ACCOUNT+r') from ')
    target = next((match[1] for pattern in patterns if (match := re.search(pattern, message))), None)
    if target is None and service == 'sudo':
        match = re.match(r'('+ACCOUNT+r')\s*:\s*TTY=', message)
        target = match[1] if match else None
    return hashlib.sha256(('local-log-account:'+target).encode()).digest() if target else None


def ordered_auth_context(records):
    """Historical single-source replay; earlier ordinal breaks equal-time ties.

    The exact logged account is a local link key, not proof of a human identity.
    All earlier rows, including possibly hostile ones, remain in history. No
    gold labels are accepted, and no authenticated posture/approval is inferred.
    """
    require(isinstance(records, list) and len(records) <= 100000, 'auth_context_rows')
    ordinals, size = set(), 0
    for ordinal, moment, line in records:
        require(type(ordinal) is int and ordinal > 0 and ordinal not in ordinals, 'auth_context_ordinal')
        require(isinstance(line, str) and len(line.encode('utf-8')) <= MAX_ROW, 'auth_context_line')
        size += len(line.encode('utf-8'))
        require(size <= 64*1024**2, 'auth_context_bytes')
        require(moment is None or type(moment) in {int, float} and math.isfinite(moment), 'auth_context_time')
        ordinals.add(ordinal)
    queue, groups, seen, result = deque(), {}, set(), {}
    for ordinal, moment, line in sorted(records, key=lambda row: (float('inf') if row[1] is None else row[1], row[0])):
        key = subject_reference(line)
        observed = history_empty()
        if moment is None or key is None:
            result[ordinal] = observed
            continue
        while queue and queue[0][0] < moment-60:
            _, old_key, digest, flags = queue.popleft()
            seen.remove((old_key, digest))
            group = groups[old_key]
            group.subtract(flags)
            if not group['rows']:
                del groups[old_key]
        group = groups.get(key, Counter())
        observed.update(auth_subject_context_available=True,
                        auth_subject_prior_events=bucket(group['rows'], (1, 2, 5, 10, 25, 100)),
                        auth_subject_prior_privilege_tool=group['privilege'] > 0,
                        auth_subject_prior_failure=group['failure'] > 0,
                        auth_subject_prior_sensitive_or_shell=group['sensitive'] > 0)
        result[ordinal] = observed
        digest = hashlib.sha256(line.encode('utf-8')).digest()
        if (key, digest) in seen:
            continue
        require(key in groups or len(groups) < 10000, 'auth_context_groups')
        basic, semantic = raw_features(line), semantic_observations(line)
        flags = {'rows': 1, 'privilege': int(semantic['auth_service_kind'] in {'su', 'sudo'} or basic['privilege_tool']),
                 'failure': int(basic['auth_failure']), 'sensitive': int(basic['sensitive_file'] or basic['shell_payload'])}
        groups.setdefault(key, Counter()).update(flags)
        queue.append((moment, key, digest, flags))
        seen.add((key, digest))
    return result
