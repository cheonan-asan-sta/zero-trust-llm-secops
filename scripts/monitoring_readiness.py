"""Fresh rule evaluation barrier for local fault tests, distinct from TSDB history."""

from datetime import UTC, datetime

from scripts.monitoring_diagnostics import ALERTS

FRESH_UP = ('up{job="zt-signals",instance="exporter:9101"} == 1 and '
            '(time() - timestamp(up{job="zt-signals",instance="exporter:9101"}) < 15)')


def inactive_rule(body, name, floor, *, now=None):
    """Return public evidence only after a new healthy inactive evaluation.

    Missing/duplicate rules, old evaluations, pending/firing alerts and errors
    never count as a clear baseline. Historical ALERTS samples are not deleted.
    """
    now = now or datetime.now(UTC)
    if name not in ALERTS or not isinstance(body, dict) or body.get('status') != 'success':
        return None
    data = body.get('data')
    if not isinstance(data, dict) or not isinstance(data.get('groups'), list) or len(data['groups']) > 8:
        return None
    found = []
    for group in data['groups']:
        if not isinstance(group, dict) or not isinstance(group.get('rules'), list) or len(group['rules']) > 32:
            return None
        for rule in group['rules']:
            if isinstance(rule, dict) and rule.get('name') == name:
                if group.get('name') != 'c01-zero-trust-operations':
                    return None
                found.append(rule)
    if len(found) != 1:
        return None
    rule = found[0]
    if (rule.get('state') != 'inactive' or rule.get('health') != 'ok' or rule.get('lastError')
            or rule.get('alerts') != [] or not isinstance(rule.get('lastEvaluation'), str)):
        return None
    try:
        stamp = datetime.fromisoformat(rule['lastEvaluation'])
        if stamp.utcoffset() is None or not floor <= stamp <= now or (now - stamp).total_seconds() > 15:
            return None
    except (ValueError, TypeError, OverflowError):
        return None
    return {'alertname': name, 'state': 'inactive', 'health': 'ok', 'last_evaluation': stamp.isoformat()}
