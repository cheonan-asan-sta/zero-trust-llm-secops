import json

import pytest

from scripts.f1_lab.transfer_evaluation import sha
from scripts.stage_journal_service_replay import stage
from tests.test_vpn_protocol_stage import fixture


def catalog(tmp_path):
    path,value,_,dump=fixture(tmp_path)
    raw=tmp_path/'raw';manifest=json.loads((raw/'audit.json').read_bytes())
    member='gather/internal_share/logs/audit/audit.log'
    manifest['pairs'][0]['provenance']['raw_member']=member;dump(raw/'audit.json',manifest)
    prep=json.loads((tmp_path/'preparation.json').read_bytes());prep['pairs'][0]['raw_member']=member
    prep['source_manifest_sha256']=sha(raw/'audit.json');dump(tmp_path/'preparation.json',prep)
    value['scenarios'][0]['preparation_sha256']=sha(tmp_path/'preparation.json')
    journal=tmp_path/'decoded.jsonl'
    journal.write_text(json.dumps({'MESSAGE':'original journal message','_BOOT_ID':'1'*32,
        'malicious':True,'expected_alert':True,'attack_labels':['excluded']})+'\n',encoding='utf8')
    binary=tmp_path/'original.journal';binary.write_bytes(b'opaque nonexecuted binary provenance fixture')
    value['journal_support']=[{'scenario':'arbitrary','source_index':0,'raw_source_sha256':prep['pairs'][0]['raw_sha256'],
        'member':'gather/internal_share/logs/journal/'+'1'*32+'/system.journal',
        'path':str(journal),'sha256':sha(journal),'binary_path':str(binary),'binary_sha256':sha(binary),
        'archive_sha256':'a'*64,'hostname':'internal-share'}]
    dump(path,value);return path,value,dump


@pytest.mark.parametrize('recovery',[False,True])
def test_journal_stage_projects_only_required_fields_and_retains_original_provenance(tmp_path,recovery):
    path,value,dump=catalog(tmp_path)
    if recovery:value['journal_support'][0]['member']=value['journal_support'][0]['member'].replace('system.journal','system@recovered.journal~')
    dump(path,value);out=tmp_path/'package';report=stage(path,sha(path),out)
    assert report['completed'] and report['profile']=='journal-service' and report['model_sha256'] is None
    projected=json.loads((out/'inputs/journal/member-0.jsonl').read_bytes())
    assert set(projected)=={'MESSAGE','_BOOT_ID'}
    assert projected['MESSAGE']=='original journal message'
    members=json.loads((out/'inputs/journal-catalog.json').read_bytes())['members']
    assert members[0]['original_decoded_sha256']==value['journal_support'][0]['sha256']
    assert members[0]['sha256']==sha(out/'inputs/journal/member-0.jsonl') and members[0]['physical_rows']==1
    assert not list((out/'inputs/models').iterdir())
    assert not list((out/'inputs').rglob('*truth*'))


@pytest.mark.parametrize('fault',['host','source','scenario','member','pin','duplicate'])
def test_invalid_support_is_rejected_and_partial_package_is_not_marked_complete(tmp_path,fault):
    path,value,dump=catalog(tmp_path);spec=value['journal_support'][0]
    if fault=='host':spec['hostname']='other-host'
    if fault=='source':spec['raw_source_sha256']='f'*64
    if fault=='scenario':spec['scenario']='unknown'
    if fault=='member':spec['member']=spec['member'].replace('internal_share','webserver')
    if fault=='pin':spec['sha256']='f'*64
    if fault=='duplicate':value['journal_support'].append(spec.copy())
    dump(path,value);out=tmp_path/'rejected'
    with pytest.raises(ValueError):stage(path,sha(path),out)
    assert json.loads((out/'stage.json').read_bytes())['completed'] is False
