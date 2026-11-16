import hashlib
import json
import zipfile

import pytest

from scripts.prepare_intent_training_source import prepare


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def packet(tmp_path,*,zone='UTC',outside=False,unpaired=False):
    archive=tmp_path/'example_no-pcaps.zip'
    sources={'gather/share/logs/audit/audit.log':'first\nsecond\n',
        'gather/web/logs/audit/audit.log':'third\nfourth\n','gather/web/logs/auth.log':'fifth\n'}
    with zipfile.ZipFile(archive,'w') as package:
        for member,text in sources.items():
            package.writestr(member,text)
            mirror=member.replace('gather/','labels/',1)
            package.writestr(mirror,json.dumps({'line':99 if outside else 1,'labels':['attack']})+'\n'
                if member.endswith('audit.log') else '')
        for host in ('share','web'):
            package.writestr('gather/'+host+'/facts.json',json.dumps({'ansible_facts':{
                'date_time':{'tz':zone,'tz_offset':'+0000'}}}))
        if unpaired:package.writestr('gather/unlabeled/logs/audit/audit.log','unknown\n')
    acquisition={'completed':True,'publisher_md5_verified':True,'local_sha256':sha(archive),
        'asset':{'record_id':19483937,'record_version':'v2_1','filename':archive.name,
            'license_id':'cc-by-nc-sa-4.0','bytes':archive.stat().st_size}}
    receipt=tmp_path/'acquisition.json';receipt.write_text(json.dumps(acquisition),encoding='utf8')
    plan={'schema':'audit-intent-training-intake-1','name':'example','role':'training','goal_qualified':False,
        'metadata_source':'https://zenodo.org/records/19483937','simulation_start':0,'simulation_end':1000,
        'acquisition':str(receipt),'acquisition_sha256':sha(receipt),'archive':str(archive)}
    path=tmp_path/'plan.json';path.write_text(json.dumps(plan),encoding='utf8')
    return path,plan


def test_training_intake_keeps_all_exact_paired_rows_and_never_labels_unpaired_normal(tmp_path):
    path,_=packet(tmp_path,unpaired=True)
    result=prepare(path,sha(path),tmp_path/'prepared')
    assert result['completed'] and result['population']==5
    assert result['unpaired_assumed_benign'] is False and len(result['excluded_unpaired'])==1
    rows=[json.loads(r) for r in (tmp_path/'prepared/truth.jsonl').read_text().splitlines()]
    assert len(rows)==5 and sum(r['malicious'] for r in rows)==2
    prep=json.loads((tmp_path/'prepared/preparation.json').read_bytes())
    assert set(prep)=={'completed','inputs_contain_truth','pairs','source_manifest_sha256'}
    assert all(set(p)=={'raw_member','raw_sha256','rows'} for p in prep['pairs'])
    assert not list((tmp_path/'prepared/raw').glob('*labels*'))
    assert all(r['zip_crc_verified_at_eof'] for r in result['copied'].values())
    assert (tmp_path/'prepared/training-access.jsonl').is_file()


@pytest.mark.parametrize('mode',['role','zone','label_bounds','archive_drift'])
def test_training_intake_rejects_wrong_roles_clock_labels_and_archive_drift(tmp_path,mode):
    path,plan=packet(tmp_path,zone='unknown' if mode=='zone' else 'UTC',outside=mode=='label_bounds')
    if mode=='role':
        plan['role']='evaluation';path.write_text(json.dumps(plan),encoding='utf8')
    if mode=='archive_drift':
        with (tmp_path/'example_no-pcaps.zip').open('ab') as stream:stream.write(b'tampered')
    with pytest.raises(ValueError):prepare(path,sha(path),tmp_path/'rejected')


def test_training_intake_requires_external_plan_pin_and_fresh_destination(tmp_path):
    path,_=packet(tmp_path)
    with pytest.raises(ValueError,match='intent_intake_plan_pin'):
        prepare(path,'a'*64,tmp_path/'out')
    prepare(path,sha(path),tmp_path/'out')
    with pytest.raises(FileExistsError):prepare(path,sha(path),tmp_path/'out')
