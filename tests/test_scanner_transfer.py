import base64
import copy
import zipfile

import pytest

from scripts import prepare_transfer_source as intake
from scripts import run_rotated_transfer as driver
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_transfer import POLICY as WILSON_POLICY
from scripts.f1_lab.rotation_transfer import check_freeze as wilson_check
from scripts.f1_lab.rotation_transfer import select_pairs
from scripts.f1_lab.scanner_transfer import POLICY, check_freeze, freeze
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_native_stream import StreamLimits, prepare
from tests.test_f1_rotated_transfer import freezer_fixture
from tests.test_rotated_transfer_chain import controls, request


def wardbeck_fixture(tmp_path):
    root, archive, acquisition = freezer_fixture(tmp_path)
    for asset, policy in [('asset_id', 'asset_id'), ('filename', 'filename'), ('publisher_md5', 'publisher_md5')]:
        acquisition['asset'][asset] = POLICY[policy]
    (root/'infra/f1-lab/native-data-protocol.json').write_bytes(canonical({
        'schema_version': 'f1-native-data-protocol-1', 'source_records': {'raw_logs': POLICY['metadata_source']},
        'scenario_split_proposal': {'development': ['russellmitchell'], 'calibration': ['wardbeck'], 'reserved_final': ['wilson']},
        'original_six_domain_goal_replaced': False, 'full_six_domain_goal_eligible': False}))
    return root, archive, acquisition


def test_original_calibration_role_and_fixed_candidate_are_pinned(tmp_path):
    root, archive, acquisition = wardbeck_fixture(tmp_path)
    path = tmp_path/'freeze.json'
    anchor = freeze(root, acquisition, archive, path)
    value = check_freeze(root, path, anchor)
    assert value['policy']['original_planned_role'] == 'calibration'
    assert not value['policy']['redesignated_as_final_holdout'] and not value['policy']['goal_qualified']
    assert value['policy']['candidate_chain'][-1] == 'v62-scanner-read-review'
    with pytest.raises(ValueError, match='policy_changed'):
        wilson_check(root, path, anchor)


@pytest.mark.parametrize('field,value', [('original_planned_role', 'final'), ('redesignated_as_final_holdout', True),
    ('alert_threshold', .5), ('candidate_chain', WILSON_POLICY['candidate_chain']), ('source_id', 'ait-wilson')])
def test_rehashed_role_threshold_or_candidate_change_is_rejected(tmp_path, field, value):
    root, archive, acquisition = wardbeck_fixture(tmp_path)
    path = tmp_path/'freeze.json'
    freeze(root, acquisition, archive, path)
    changed = decode(path.read_bytes())
    changed['policy'][field] = value
    path.write_bytes(canonical(changed))
    with pytest.raises(ValueError, match='policy_changed'):
        check_freeze(root, path, sha(path))


def test_wrong_publisher_or_exposed_source_cannot_be_frozen(tmp_path):
    root, archive, acquisition = wardbeck_fixture(tmp_path)
    original = copy.deepcopy(acquisition)
    acquisition['asset']['filename'] = WILSON_POLICY['filename']
    with pytest.raises(ValueError, match='publisher_contract'):
        freeze(root, acquisition, archive, tmp_path/'wrong.json')
    (archive.parent/'evaluation-access.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='unsealed_source'):
        freeze(root, original, archive, tmp_path/'exposed.json')


@pytest.mark.parametrize('role', ['development', 'reserved_final', 'duplicate', 'missing'])
def test_original_data_plan_cannot_be_reassigned_before_freezing(tmp_path, role):
    root, archive, acquisition = wardbeck_fixture(tmp_path)
    path = root/'infra/f1-lab/native-data-protocol.json'
    plan = decode(path.read_bytes())
    roles = plan['scenario_split_proposal']
    if role == 'duplicate':
        roles['calibration'].append('wardbeck')
    else:
        roles['calibration'].remove('wardbeck')
        if role != 'missing':
            roles[role].append('wardbeck')
    path.write_bytes(canonical(plan))
    with pytest.raises(ValueError, match='original_role_changed'):
        freeze(root, acquisition, archive, tmp_path/'freeze.json')
    assert not (tmp_path/'freeze.json').exists()


@pytest.mark.parametrize('stage,policy', [(False, POLICY), (True, WILSON_POLICY), ('yes', POLICY)])
def test_wrong_stage_contract_is_rejected_before_reading_raw_inputs(tmp_path, stage, policy):
    with pytest.raises(ValueError):
        driver.prediction_packet(tmp_path, tmp_path/'freeze', 'a'*64, tmp_path/'raw', tmp_path/'prepared',
                                 tmp_path/'out', freeze_checker=lambda *_: {'policy': policy}, scanner_stage=stage)
    assert not (tmp_path/'out').exists()


def test_real_four_stage_replay_preserves_role_and_labels_stay_outside_prediction(tmp_path, monkeypatch):
    specs, operation_policy = controls(tmp_path)
    def command(argv):
        return '/uploads/tool.php?a='+base64.b64encode(canonical(argv)).decode()
    access = (request('/asset.js', 0)+request(command(['cat', '/etc/shadow']), 1)
              +request(command(['tar', '-tf', 'data.tar']), 2)
              +request('/', 3).replace('Mozilla/5.0', 'Nmap Scripting Engine')).replace('07/Feb/2022', '23/Jan/2022')
    error = '[Sun Jan 23 10:00:04.000000 2022] [authz_core:error] [pid 1] [client 192.0.2.1:12345] AH01630: client denied by server configuration: /srv/.htaccess\n'
    vpn = '2022-01-23 10:00:05 192.0.2.1:12345 TLS Error: TLS handshake failed\n'
    source = tmp_path/'controls.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        for host in ('web', 'vpn'):
            archive.writestr(f'control/gather/{host}/facts.json', canonical({'date_time': {'tz': 'UTC', 'tz_offset': '+0000'}}))
        for host, name, body, positives in [('web', 'apache2/site-access.log.1', access, [2, 3, 4]),
                ('web', 'apache2/site-error.log.1', error, [1]), ('vpn', 'openvpn/openvpn.log', vpn, [1])]:
            archive.writestr(f'control/gather/{host}/logs/{name}', body)
            archive.writestr(f'control/labels/{host}/logs/{name}', b''.join(canonical({'line': n, 'labels': ['control']})+b'\n'
                                                                                       for n in positives))
    value = {'policy': POLICY, 'archive_sha256': sha(source), 'simulation_start': POLICY['simulation_start'],
        'simulation_end': POLICY['simulation_end'], 'metadata_source': 'synthetic controls only',
        'maximum_total_rows': 100, 'source_id': 'synthetic_controls_only', 'models': specs, 'operation_policy': operation_policy}
    checker = lambda *_: value
    state = {'labels_allowed': False, 'labels_read': 0}
    original_copy = intake.copy_member
    def copied(archive, archive_hash, member, destination, **kwargs):
        if '/labels/' in member:
            assert state['labels_allowed']
            state['labels_read'] += 1
        return original_copy(archive, archive_hash, member, destination, **kwargs)
    monkeypatch.setattr(intake, 'copy_member', copied)
    raw, prepared, output = tmp_path/'raw', tmp_path/'prepared', tmp_path/'predictions'
    anchor = 'a'*64
    intake.prepare(tmp_path, source, tmp_path/'freeze.json', anchor, raw, freeze_checker=checker, pair_selector=select_pairs)
    prepare(raw, sha(raw/'audit.json'), prepared, include_truth=False,
            limits=StreamLimits(database_bytes=1024**2, output_bytes=1024**2,
                                min_free_bytes=16*1024**2, active_http_events=100))
    packet = driver.prediction_packet(tmp_path, tmp_path/'freeze.json', anchor, raw, prepared, output,
                                     freeze_checker=checker, scanner_stage=True)
    assert packet['population'] == 6 and packet['inference_errors'] == 0 and state['labels_read'] == 0
    assert set(packet['stages']) == {'v49', 'v51', 'v52', 'v62'}
    assert packet['original_planned_role'] == 'calibration' and not packet['redesignated_as_final_holdout']
    manifest_path = output/'prediction-manifest.json'
    original_manifest = manifest_path.read_bytes()
    changed = decode(original_manifest)
    changed['original_planned_role'] = 'final'
    manifest_path.write_bytes(canonical(changed))
    with pytest.raises(ValueError, match='prediction_role'):
        driver.score_packet(tmp_path, source, tmp_path/'freeze.json', anchor, raw, output,
                            sha(manifest_path), tmp_path/'wrong', freeze_checker=checker, scanner_stage=True)
    assert state['labels_read'] == 0
    manifest_path.write_bytes(original_manifest)
    state['labels_allowed'] = True
    result = driver.score_packet(tmp_path, source, tmp_path/'freeze.json', anchor, raw, output,
        packet['manifest_sha256'], tmp_path/'score', freeze_checker=checker, scanner_stage=True)
    assert result['completed'] and result['population'] == 6 and not result['goal_qualified']
    assert result['changes'] == {'new_tp': 1, 'introduced_fp': 0, 'lost_tp': 0, 'removed_fp': 0}
    assert result['stages']['v51']['changes']['new_tp'] == 1
    assert state['labels_read'] == 3 and result['original_planned_role'] == 'calibration'
