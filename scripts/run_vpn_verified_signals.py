"""Local VPN evidence controls and unchanged historical-data comparison."""

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.audit_vpn_precision import raw_records
from scripts.f1_lab.line_truth import annotations
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import load_operation_refinement
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.vpn_risk_retention import RiskRetention, retained_contexts
from scripts.f1_lab.vpn_signal_controls import NOW, VPNControls, arguments, signature
from scripts.f1_lab.vpn_verified_signals import VerifiedVPNRisk
from scripts.fit_native_raw import receipt
from scripts.run_operation_refinement import ROOT, fingerprint, pinned


def compare_history(plan, prior, model):
    result = {}
    candidate = VerifiedVPNRisk(model, None)  # No fabricated device/permission sidecars.
    for scenario in plan['scenarios']:
        name = scenario['name']
        preparation = receipt(ROOT/scenario['directory'], scenario['preparation_sha256'])
        directory = ROOT/scenario['pairs_directory']
        manifest = pinned(directory/'audit.json', preparation['source_manifest_sha256'])
        require(manifest['completed'] and manifest['timestamp_basis'] ==
                'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check', 'vpn_history_contract')
        indices = [i for i, p in enumerate(manifest['pairs']) if p['provenance']['raw_member'].endswith('/openvpn.log')]
        require(len(indices) == 1, 'vpn_history_one_source')
        i = indices[0]
        pair = manifest['pairs'][i]
        p = pair['provenance']
        records, errors = raw_records(directory, i, pair, preparation['pairs'][i])
        contexts = retained_contexts(records, p['raw_sha256'], model.vpn_model)
        by_n = {c.base.ordinal: c for c in contexts.values()}
        scored, hashes = [], [hashlib.sha256(), hashlib.sha256()]
        for ordinal, _, line in records:
            context = by_n[ordinal]
            features = {**core_features(line), **semantic_observations(line)}
            before = model.decide(features, context.base.case_id, context)
            after = candidate.decide(features, context.base.case_id, context)
            require(before == after and not after.automatic_enforcement_allowed, 'vpn_missing_evidence_drift')
            for sha, value in zip(hashes, (before, after), strict=True):
                sha.update(canonical({'case_id': context.base.case_id, **value.__dict__})+b'\n')
            scored.append((ordinal, before.alert, after.alert))
        gold, _ = annotations(directory/f'pair-{i}-labels.source', p['label_sha256'])
        require(all(1 <= n <= len(records) for n in gold), 'vpn_history_labels')
        before_count, after_count = counts(), counts()
        for ordinal, a, b in scored:
            record(before_count, ordinal in gold, a)
            record(after_count, ordinal in gold, b)
        expected = next(x['metrics']['alert'] for x in prior['scenarios'][name]['per_pair'] if x['raw_member'] == p['raw_member'])
        require(metrics(before_count) == metrics(after_count) == expected, 'vpn_history_baseline_drift')
        result[name] = {'population': len(records), 'before': metrics(before_count), 'after': metrics(after_count),
            'before_sha256': hashes[0].hexdigest(), 'after_sha256': hashes[1].hexdigest(), 'time_errors': errors,
            'raw_sha256': p['raw_sha256'], 'label_sha256': p['label_sha256'], 'evidence_coverage': 0,
            'note': 'Historical logs have no authenticated device/authorization evidence; no enrichment invented.'}
    return result


def compare_controls(directory, model):
    controls = VPNControls(directory, model)
    candidate = VerifiedVPNRisk(model, controls.bridge)
    kinds = [('healthy-authorized', False, {})]*20
    kinds += [(kind, True, args) for kind, args in [
        ('compromised-device', {'device': 'compromised'}), ('at-risk-device', {'device': 'at_risk'}),
        ('unknown-device', {'device': 'unknown'}), ('unmanaged-device', {'managed': False}),
        ('inactive-user', {'active': False}), ('failed-mfa', {'mfa': 'failed'}),
        ('unknown-mfa', {'mfa': 'unknown'}), ('failed-auth', {'authentication': 'failure'}),
        ('unknown-auth', {'authentication': 'unknown'}), ('unapproved-role', {'role': 'viewer'}),
        ('anomalous-location', {'event_changes': {'network': {'location_anomaly': True}}}),
        ('unapproved-new-device', {'event_changes': {'behavior': {'new_device': True}}}),
        ('missing-permission', {'approval': False}), ('missing-evidence', {}),
        ('forged-gateway', {}), ('forged-posture', {}), ('forged-permission', {}),
        ('cross-request-proof', {}), ('stale-posture', {}), ('future-posture', {}),
        ('raw-auth-failure', {'raw_message': 'AUTH_FAILED'}),
        ('raw-tls-failure', {'raw_message': 'TLS Error: handshake failed'}),
        ('raw-path-traversal', {'raw_message': '../secret'}),
        ('raw-command', {'raw_message': 'request ?cmd=id'}),
        ('raw-scanner', {'raw_message': 'sqlmap'}),
        ('raw-sensitive-file', {'raw_message': '/etc/shadow'}),
        ('raw-privilege-tool', {'raw_message': 'sudo -l'}),
        ('raw-service-stop', {'raw_message': 'service stopped'}),
        ('raw-access-denied', {'raw_message': 'client denied by server configuration'}),
    ]]
    before_counts, after_counts, rows = counts(), counts(), []
    lost_tp = introduced_fp = 0
    for index, (kind, malicious, options) in enumerate(kinds, 1):
        now = NOW+timedelta(seconds=index)
        row = controls.build(now=now, index=index, session='vpn-control-'+str(index), **options)
        before = model.decide(row['features'], row['case_id'], row['context'])
        evidence = row['evidence']
        if kind == 'missing-evidence':
            row['evidence'] = None
        elif kind == 'forged-gateway':
            row['evidence'] = evidence.model_copy(update={'binding': evidence.binding.model_copy(update={'signature': 'A'*86})})
        elif kind == 'forged-posture':
            row['evidence'] = controls.resign_binding(evidence.model_copy(update={
                'posture': evidence.posture.model_copy(update={'signature': 'A'*86})}))
        elif kind == 'forged-permission':
            row['evidence'] = controls.resign_binding(evidence.model_copy(update={
                'approval': evidence.approval.model_copy(update={'signature': 'A'*88})}))
        elif kind == 'cross-request-proof':
            row['evidence'] = evidence.model_copy(update={'binding': evidence.binding.model_copy(
                update={'request_sha256': 'e'*64})})
        elif kind in {'stale-posture', 'future-posture'}:
            from app.services.trusted_signals import canonical_observation
            observed = now+timedelta(seconds=1) if kind == 'future-posture' else now-timedelta(seconds=31)
            posture = evidence.posture.model_copy(update={'observed_at': observed,
                'issued_at': observed if kind == 'future-posture' else now})
            posture = posture.model_copy(update={'signature': signature(controls.keys['device'], canonical_observation(posture))})
            row['evidence'] = controls.resign_binding(evidence.model_copy(update={'posture': posture}))
        after = candidate.decide(**arguments(row))
        require(not after.automatic_enforcement_allowed, 'vpn_controls_never_enforce')
        record(before_counts, malicious, before.alert)
        record(after_counts, malicious, after.alert)
        lost_tp += int(malicious and before.alert and not after.alert)
        introduced_fp += int(not malicious and not before.alert and after.alert)
        rows.append({'control_id': index, 'family': kind, 'malicious': malicious, 'raw_line_sha256':
            hashlib.sha256(row['raw_line'].encode()).hexdigest(), 'before': before.__dict__, 'after': after.__dict__})
    require(lost_tp == introduced_fp == 0 and after_counts['fn'] == 0
            and after_counts['fp'] < before_counts['fp'], 'vpn_controls_quality_gate')
    return {'scope': 'authored prospective functional controls; not independent performance evaluation',
        'before': metrics(before_counts), 'after': metrics(after_counts), 'lost_baseline_tp': lost_tp,
        'introduced_fp': introduced_fp, 'controls': rows, 'private_keys_persisted': False,
        'public_configuration': [fingerprint(directory/(name+'.json')) for name in ('sources', 'approvals', 'policies', 'enrollments')]}


def run(plan_path, plan_sha, prior_path, prior_sha, output):
    plan_path, prior_path, output = Path(plan_path), Path(prior_path), Path(output)
    plan, prior = pinned(plan_path, plan_sha), pinned(prior_path, prior_sha)
    require(plan['schema'] == 'f1-error-vpn-experiment-1' and plan['scope'] == 'observed development/calibration only'
            and prior['completed'] and prior['plan']['sha256'] == plan_sha, 'vpn_verified_plan')
    require(not output.exists() and not output.is_symlink(), 'fresh_verified_vpn_output')
    for name, value in prior['sources'].items():
        require(fingerprint(ROOT/name) == value, 'vpn_baseline_source_changed')
    output.mkdir(parents=True, mode=0o700)
    paths = ('scripts/f1_lab/vpn_verified_signals.py', 'scripts/f1_lab/vpn_signal_controls.py', 'scripts/f1_lab/vpn_enrollment.py',
             'scripts/run_vpn_verified_signals.py', 'app/services/trusted_signals.py', 'scripts/f1_lab/source_registry.py',
             'scripts/f1_lab/registry.py', 'scripts/f1_lab/approvals.py', 'scripts/f1_lab/resource_policy.py')
    report = {'schema': 'extra-vpn-verified-signals-1', 'completed': False, 'started_at': datetime.now(UTC).isoformat(),
        'sources': {name: fingerprint(ROOT/name) for name in paths}, 'plan': fingerprint(plan_path),
        'prior': fingerprint(prior_path), 'production_adopted': False, 'goal_qualified': False,
        'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0, 'models_refitted': False, 'labels_changed': False}
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    started = time.perf_counter()
    save()
    try:
        old = pinned(ROOT/prior['stateless_run']['path'], prior['stateless_run']['sha256'])
        specs = plan['models']
        base = load_operation_refinement(ROOT/old['policy']['path'], old['policy']['sha256'],
            ROOT/specs['web']['path'], specs['web']['sha256'], ROOT/specs['heads']['path'], specs['heads']['sha256'],
            ROOT/specs['vpn']['path'], specs['vpn']['sha256'])
        model = RiskRetention(base)
        before_models = [fingerprint(ROOT/s['path']) for s in specs.values()]
        report['history'] = compare_history(plan, prior, model)
        save()
        report['controls'] = compare_controls(output/'public-controls', model)
        require(before_models == [fingerprint(ROOT/s['path']) for s in specs.values()], 'vpn_models_changed')
        require(all(fingerprint(ROOT/name) == value for name, value in report['sources'].items()), 'vpn_sources_changed')
        report['completed'] = True
    except (ValueError, TypeError, OSError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        report['elapsed_seconds'] = round(time.perf_counter()-started, 3)
        report['ended_at'] = datetime.now(UTC).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--prior', required=True, type=Path)
    parser.add_argument('--expected-prior-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = run(args.plan, args.expected_plan_sha256, args.prior, args.expected_prior_sha256, args.output)
    print(json.dumps({'completed': report['completed'], 'controls': report.get('controls', {}).get('after')}))


if __name__ == '__main__':
    main()
