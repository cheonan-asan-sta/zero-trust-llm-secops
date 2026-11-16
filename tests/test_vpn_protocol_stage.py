import hashlib
import json
import tarfile

import pytest

from scripts.f1_lab.transfer_evaluation import sha
from scripts.stage_vpn_protocol_replay import stage


def fixture(tmp_path):
    raw=tmp_path/'raw';raw.mkdir()
    source=raw/'pair-0-raw.source'
    source.write_bytes(b'2025-01-01 00:00:00 192.0.2.1:10000 VERIFY KU OK\n')
    digest=sha(source);member='gather/vpn/logs/openvpn.log'
    dump=lambda path,value:path.write_text(json.dumps(value),encoding='utf8')
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'malicious':99,'normal':999,'pairs':[{'malicious':99,'provenance':{'raw_member':member,
            'raw_sha256':digest,'simulation_start':1735689600,'simulation_end':1735776000,
            'label_member':'excluded-label-path'}}]}
    dump(raw/'audit.json',manifest)
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),
        'malicious':99,'normal':999,'files':{'truth.jsonl':{'sha256':'f'*64}},
        'pairs':[{'raw_member':member,'raw_sha256':digest,'rows':1,'malicious':99,'normal':999}]}
    prepared=tmp_path/'preparation.json';dump(prepared,prep)
    baseline=tmp_path/'baseline.jsonl'
    baseline.write_text(json.dumps({'case_id':hashlib.sha256((digest+':1').encode()).hexdigest(),
        'source_index':0,'before':True,'after':True,'before_score':.99,'after_score':.99,
        'reason':'vpn_history_risk_review','error':None})+'\n',encoding='utf8')
    (raw/'truth.jsonl').write_text('must not be staged',encoding='utf8')
    catalog={'schema':'vpn-protocol-replay-catalog-1','scope':'observed_development','goal_qualified':False,
        'scenarios':[{'name':'arbitrary','preparation':str(prepared),'preparation_sha256':sha(prepared),
            'raw':str(raw),'baseline':str(baseline),'baseline_sha256':sha(baseline),'population':1}]}
    path=tmp_path/'catalog.json';dump(path,catalog)
    return path,catalog,baseline,dump


def test_staging_strips_label_aggregates_adjacent_truth_and_noncode_artifacts(tmp_path):
    path,_,_,_=fixture(tmp_path);out=tmp_path/'package'
    report=stage(path,sha(path),out)
    assert report['completed'] and report['validation_labels_or_aggregates_staged'] is False
    prep=json.loads((out/'inputs/arbitrary-preparation.json').read_bytes())
    assert set(prep)=={'completed','inputs_contain_truth','source_manifest_sha256','pairs'}
    assert set(prep['pairs'][0])=={'raw_member','raw_sha256','rows'}
    raw=json.loads((out/'inputs/raw/arbitrary/audit.json').read_bytes())
    assert set(raw)=={'completed','timestamp_basis','pairs'}
    assert set(raw['pairs'][0])=={'provenance'}
    assert set(raw['pairs'][0]['provenance'])=={'raw_member','raw_sha256','simulation_start','simulation_end'}
    assert not list((out/'inputs').rglob('*truth*')) and not list((out/'inputs').rglob('*.md'))
    with tarfile.open(out/'inputs/code.tar') as archive:
        assert all(m.name.endswith('.py') and m.name.startswith(('app/','scripts/')) for m in archive)
    assert report['frozen_training_parameters_staged'] is True


def test_audit_profile_stages_only_audit_auth_raw_and_its_frozen_head(tmp_path):
    path,catalog,baseline,dump=fixture(tmp_path);spec=catalog['scenarios'][0]
    raw=tmp_path/'raw';audit=raw/'pair-1-raw.source';audit.write_bytes(b'audit-observation\n')
    member='gather/share/logs/audit/audit.log';digest=sha(audit)
    manifest=json.loads((raw/'audit.json').read_bytes())
    manifest['pairs'].append({'provenance':{'raw_member':member,'raw_sha256':digest,
        'simulation_start':1735689600,'simulation_end':1735776000,'label_member':'excluded'}})
    dump(raw/'audit.json',manifest)
    prep=json.loads((tmp_path/'preparation.json').read_bytes())
    prep['source_manifest_sha256']=sha(raw/'audit.json')
    prep['pairs'].append({'raw_member':member,'raw_sha256':digest,'rows':1})
    dump(tmp_path/'preparation.json',prep)
    row=json.loads(baseline.read_bytes());row.update(case_id=hashlib.sha256((digest+':1').encode()).hexdigest(),source_index=1)
    with baseline.open('a',encoding='utf8') as stream:stream.write(json.dumps(row)+'\n')
    spec.update(preparation_sha256=sha(tmp_path/'preparation.json'),baseline_sha256=sha(baseline),population=2)
    dump(path,catalog)
    out=tmp_path/'audit-package';report=stage(path,sha(path),out,profile='apparmor-causal')
    assert report['completed'] and report['profile']=='apparmor-causal' and report['legacy_models_sha256'] is None
    assert (out/'inputs/raw/arbitrary/pair-1-raw.source').read_bytes()==audit.read_bytes()
    assert not (out/'inputs/raw/arbitrary/pair-0-raw.source').exists()
    assert {p.name for p in (out/'inputs/models').iterdir()}=={'head.json'}


@pytest.mark.parametrize('fault',['extra_truth_field','name_escape','pin','population'])
def test_staging_rejects_label_in_prediction_unsafe_names_bad_pins_and_changed_population(tmp_path,fault):
    path,catalog,baseline,dump=fixture(tmp_path)
    if fault=='extra_truth_field':
        value=json.loads(baseline.read_bytes());value['malicious']=False
        baseline.write_text(json.dumps(value)+'\n',encoding='utf8')
        catalog['scenarios'][0]['baseline_sha256']=sha(baseline)
    if fault=='name_escape':catalog['scenarios'][0]['name']='../escape'
    if fault=='population':catalog['scenarios'][0]['population']=2
    dump(path,catalog)
    with pytest.raises(ValueError):stage(path,'f'*64 if fault=='pin' else sha(path),tmp_path/'rejected')
    assert not (tmp_path/'escape').exists()
