"""Real three-stage control replay; label access occurs only after sealing."""

import base64
import zipfile

import pytest

from scripts import audit_transfer_overlap as overlap
from scripts import prepare_transfer_source as intake
from scripts import run_rotated_transfer as driver
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_heads import NativeHeads
from scripts.f1_lab.operation_context import bound_contexts, canonical, core_features
from scripts.f1_lab.operation_refinement import POLICY as OPERATION_POLICY
from scripts.f1_lab.raw_semantics import PROFILE, semantic_observations
from scripts.f1_lab.rotation_transfer import POLICY, select_pairs
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.f1_lab.web_refinement import WebRefinement, fit_http_tree
from scripts.prepare_native_stream import StreamLimits, prepare


def request(path, second):
    return (f'192.0.2.1 - - [07/Feb/2022:10:00:{second:02d} +0000] '
            f'"GET {path} HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n')


def controls(root):
    normal_line = request('/asset.js', 0)
    normal = {**core_features(normal_line), **semantic_observations(normal_line)}
    attack = {**normal, 'sql_injection': True}
    other_line = '[Mon Feb 07 10:00:03.000000 2022] [authz_core:error] [pid 1] [client 192.0.2.1:12345] AH01630: client denied by server configuration: /srv/.htaccess\n'
    other = {**core_features(other_line), **semantic_observations(other_line)}
    vpn_observation = '2022-02-07 10:00:04 192.0.2.1:12345 TLS Error: TLS handshake failed\n'
    vpn_core = {**core_features(vpn_observation), **semantic_observations(vpn_observation)}
    heads = NativeHeads(profile=PROFILE, tree_variant='ordered_binary')
    for _ in range(10):
        heads.observe_training(normal, False)
        heads.observe_training(attack, True)
        heads.observe_training({**other, 'http_forbidden': False}, False)
        heads.observe_training(other, True)
        heads.observe_training({**vpn_core, 'tls_failure': False}, False)
        heads.observe_training(vpn_core, True)
    heads.fit()
    tree, _ = fit_http_tree([(normal, False)]*10+[(attack, True)]*10)
    heads_path = root/'heads.json'
    heads_path.write_bytes(canonical(heads.export())+b'\n')
    web_path = root/'web.json'
    web_path.write_bytes(canonical(WebRefinement(heads, sha(heads_path), tree, 'c'*64).export())+b'\n')
    vpn_line = '2022-02-07 10:00:00 192.0.2.1:12345 TLS: Initial packet\n'
    vpn_f = next(iter(bound_contexts([(1, 10, vpn_line)], 'vpn', 'a'*64).values())).vpn_features
    vpn = NativeBinaryTree(profile=VPN_PROFILE)
    for _ in range(10):
        vpn.observe_training(vpn_f, True)
        vpn.observe_training({**vpn_f, 'vpn_peer_seen_before': True}, False)
    vpn.fit()
    vpn_path = root/'vpn.json'
    vpn_path.write_bytes(canonical(vpn.export())+b'\n')
    specs = {name: {'path': path.name, 'sha256': sha(path)} for name, path in
             (('heads', heads_path), ('web', web_path), ('vpn', vpn_path))}
    policy_path = root/'policy.json'
    policy_path.write_bytes(canonical({**OPERATION_POLICY, **{key+'_model_sha256': value['sha256']
                                                           for key, value in specs.items()}})+b'\n')
    return specs, {'path': policy_path.name, 'sha256': sha(policy_path)}


def test_real_three_stage_replay_never_opens_labels_until_sealed(tmp_path, monkeypatch):
    specs, operation_policy = controls(tmp_path)
    def command(argv):
        return '/uploads/tool.php?a='+base64.b64encode(canonical(argv)).decode()
    access = request('/asset.js', 0)+request(command(['cat', '/etc/shadow']), 1)+request(command(['tar', '-tf', 'data.tar']), 2)
    error = '[Mon Feb 07 10:00:03.000000 2022] [authz_core:error] [pid 1] [client 192.0.2.1:12345] AH01630: client denied by server configuration: /srv/.htaccess\n'
    vpn = '2022-02-07 10:00:04 192.0.2.1:12345 TLS Error: TLS handshake failed\n'
    source = tmp_path/'synthetic-control.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        for host in ('web', 'vpn'):
            archive.writestr(f'control/gather/{host}/facts.json', canonical({'date_time': {'tz': 'UTC', 'tz_offset': '+0000'}}))
        for host, name, body, positive in (('web', 'apache2/site-access.log.1', access, [2, 3]),
                ('web', 'apache2/site-error.log.1', error, [1]), ('vpn', 'openvpn/openvpn.log', vpn, [1])):
            archive.writestr(f'control/gather/{host}/logs/{name}', body)
            archive.writestr(f'control/labels/{host}/logs/{name}', b''.join(canonical({'line': n, 'labels': ['test_control']})+b'\n'
                                                                                   for n in positive))
    value = {'archive_sha256': sha(source), 'simulation_start': POLICY['simulation_start'],
        'simulation_end': POLICY['simulation_end'], 'metadata_source': 'synthetic unit-test controls',
        'maximum_total_rows': 100, 'source_id': 'synthetic_controls_only',
        'models': specs, 'operation_policy': operation_policy}
    # Freeze-contract drift has separate tests; this one exercises real raw,
    # model, context, stage, seal and score paths with synthetic controls only.
    monkeypatch.setattr(driver, 'check_freeze', lambda *_: value)
    state = {'may_open_labels': False, 'label_members_read': 0}
    original_copy = intake.copy_member
    def copied(archive, archive_hash, member, destination, **kwargs):
        if '/labels/' in member:
            assert state['may_open_labels'], 'label body reached predictor'
            state['label_members_read'] += 1
        return original_copy(archive, archive_hash, member, destination, **kwargs)
    monkeypatch.setattr(intake, 'copy_member', copied)
    raw, prepared, output = tmp_path/'raw', tmp_path/'prepared', tmp_path/'predictions'
    anchor = 'a'*64
    intake.prepare(tmp_path, source, tmp_path/'freeze.json', anchor, raw,
                   freeze_checker=lambda *_: value, pair_selector=select_pairs)
    prepare(raw, sha(raw/'audit.json'), prepared, include_truth=False,
            limits=StreamLimits(database_bytes=1024**2, output_bytes=1024**2,
                                min_free_bytes=16*1024**2, active_http_events=100))
    packet = driver.prediction_packet(tmp_path, tmp_path/'freeze.json', anchor, raw, prepared, output)
    assert packet['population'] == 5 and packet['inference_errors'] == 0
    assert state['label_members_read'] == 0 and not (prepared/'truth.jsonl').exists()
    assert packet['stages']['v51']['population'] == 5 and packet['stages']['v52']['population'] == 5
    audited = overlap.audit(tmp_path, tmp_path/'freeze.json', anchor, output/'prediction-manifest.json',
        packet['manifest_sha256'], prepared, [prepared], tmp_path/'overlap', freeze_checker=lambda *_: value)
    assert audited['heldout_rows'] == audited['rows_matching_development_feature_vector'] == 5
    assert audited['rows_removed_from_evaluation'] == 0 and audited['exact_raw_source_overlap']
    assert state['label_members_read'] == 0 and not (tmp_path/'overlap/overlap.sqlite3').exists()
    with pytest.raises(ValueError, match='overlap_prediction_seal'):
        overlap.audit(tmp_path, tmp_path/'freeze.json', anchor, output/'prediction-manifest.json',
            'b'*64, prepared, [prepared], tmp_path/'bad-overlap', freeze_checker=lambda *_: value)
    state['may_open_labels'] = True
    result = driver.score_packet(tmp_path, source, tmp_path/'freeze.json', anchor, raw, output,
                                 packet['manifest_sha256'], tmp_path/'score')
    assert state['label_members_read'] == 3
    assert result['completed'] and result['population'] == 5 and not result['goal_qualified']
    assert result['source_id'] == 'synthetic_controls_only'
    assert result['stages']['v51']['changes']['new_tp'] == 1
