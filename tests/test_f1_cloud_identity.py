import hashlib
import json

import pytest

from scripts.audit_cloud_identity import audit, summarize


def principal(identifier='p', *, account='a', key=None):
    identity={'type':'AssumedRole','accountId':account,'principalId':identifier}
    if key is not None:
        identity['accessKeyId']=key
    return {'userIdentity':identity,'sharedEventID':'shared'}


def service(*, shared='different', key=None):
    identity={'type':'AWSService','invokedBy':'s3.amazonaws.com'}
    if key is not None:
        identity['accessKeyId']=key
    return {'userIdentity':identity,'sharedEventID':shared,'should_sample':True}


def test_service_name_ip_and_account_alone_never_make_a_caller_join():
    a=principal()
    a['userIdentity']['invokedBy']='s3.amazonaws.com'
    a['sourceIPAddress']='same-ip'
    b=service()
    b['userIdentity']['accountId']='a'
    b['sourceIPAddress']='same-ip'
    result=summarize([a,b])
    assert result['service_exact_join_candidates']=={'no_candidate':1}
    assert not result['candidate_join_verified'] and not result['inference_features_changed']


def test_exact_join_candidate_stays_unverified_and_ids_are_not_exported():
    result=summarize([principal(identifier='secret-principal',key='secret-access-key'),service(key='secret-access-key')])
    assert result['service_exact_join_candidates']=={'one_candidate':1}
    assert 'secret-' not in str(result) and result['raw_identifiers_displayed_or_exported']==0
    assert not result['candidate_join_verified']


def test_shared_event_conflicts_retain_ambiguity_and_account_scope():
    result=summarize([principal('same',account='one'),principal('same',account='two'),service(shared='shared')])
    assert result['service_exact_join_candidates']=={'multiple_candidates':1}


def test_missing_or_nonboolean_gold_not_used_to_invent_identity():
    a=service()
    del a['should_sample']
    b={**service(),'should_sample':'false'}
    result=summarize([a,b])
    assert result['service_label_counts']=={'unknown':2}
    assert result['service_exact_join_candidates']=={'no_candidate':2}


def source(tmp_path):
    source=tmp_path/'source';source.mkdir()
    assets=[]
    for index,records in enumerate([[principal()],[service()]]):
        path=source/f'asset-{index}.json.source'
        path.write_text(json.dumps({'Records':records}))
        assets.append({'asset':{'path':f'TrainOn/file{index}.zip'},'member':{
            'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}})
    path=source/'acquisition.json'
    path.write_text(json.dumps({'completed':True,'test_archive_downloaded':False,'assets':assets}))
    return source,hashlib.sha256(path.read_bytes()).hexdigest()


def test_pinned_workflow_does_not_fit_or_touch_test_data(tmp_path):
    directory,anchor=source(tmp_path)
    result=audit(directory,anchor,tmp_path/'out')
    assert result['completed'] and result['rows']==2 and result['test_records_read']==0
    assert not result['classifier_fitted'] and not result['goal_qualified']


@pytest.mark.parametrize('fault',['hash','test_asset'])
def test_invalid_training_contract_never_publishes_success(tmp_path,fault):
    directory,anchor=source(tmp_path)
    if fault=='hash':
        path=directory/'asset-0.json.source';path.write_bytes(path.read_bytes()+b' ')
    else:
        path=directory/'acquisition.json';receipt=json.loads(path.read_bytes())
        receipt['assets'][1]['asset']['path']='TestOn/file.zip'
        path.write_text(json.dumps(receipt));anchor=hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        audit(directory,anchor,tmp_path/'out')
    assert not (tmp_path/'out/audit.json').exists()
