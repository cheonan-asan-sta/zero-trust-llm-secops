import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest

from scripts.f1_lab.audit_intent_context import AuditIntentReview
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_native_audit_training import COMMAND, POLICY, prepare


def fixture(tmp_path):
    source=b'type=DAEMON_ROTATE msg=audit(1700000000.100:1): op=rotate res=success\n'
    source+=b'type=USER_START msg=audit(1700000000.101:2): pid=5 uid=0 auid=1000 ses=1 res=success\n'
    (tmp_path/'audit-native.source').write_bytes(source)
    status={'boot_id':'a'*32,'timezone':'UTC','policy_sha256':hashlib.sha256(POLICY).hexdigest(),
        'audit':{'lost':'0','enabled':'1'}}
    sessions=[{'number':n,'ssh_exit':0,'operation':{'uid':1000,'loginuid':'1000','sessionid':str(n),
        'tty':'/dev/pts/0','command':COMMAND,'exit_code':0}} for n in range(1,9)]
    report={'completed':True,'owned_container_removed':True,'network_disconnected_before_collection':True,
        'host_configuration_changed':False,'goal_qualified':False,'new_independent_evaluation':False,
        'aws_calls':0,'paid_api_calls':0,'guest':{'completed':True,'role':'controlled_normal_training',
            'owned_qemu_exited':True,'outer_networks_after_disconnect':{},'outer_interfaces':['lo'],
            'guest_collection_begin':{'status':status},'capture':{'status':status,'complete_file_snapshot':True,
                'bytes':len(source),'sha256':hashlib.sha256(source).hexdigest()},'sessions':sessions}}
    path=tmp_path/'execution.json'
    def dump():path.write_text(json.dumps(report),encoding='utf8')
    dump();return path,report,source,dump


def test_native_intake_preserves_exact_bytes_all_physical_rows_and_training_role(tmp_path):
    path,_report,source,_dump=fixture(tmp_path);out=tmp_path/'prepared'
    result=prepare(path,sha(path),out)
    assert result['completed'] and result['role']=='controlled_normal_training' and result['population']==2
    assert result['native_bytes_modified'] is False and result['goal_qualified'] is False
    assert (out/'raw/pair-0-raw.source').read_bytes()==source
    labels=[json.loads(r) for r in (out/'truth.jsonl').read_text().splitlines()]
    assert len(labels)==2 and all(r['malicious'] is False for r in labels)
    assert labels[1]['case_id']==hashlib.sha256((result['source_sha256']+':2').encode()).hexdigest()
    assert result['new_independent_evaluation'] is False and result['original_evaluation_population_changed'] is False


def test_enriched_group_separator_is_not_counted_as_an_extra_physical_line(tmp_path):
    path,report,source,dump=fixture(tmp_path)
    source=source.replace(b'\n',b'\x1dUID="display-only"\n')
    (tmp_path/'audit-native.source').write_bytes(source)
    report['guest']['capture'].update(bytes=len(source),sha256=hashlib.sha256(source).hexdigest());dump()
    result=prepare(path,sha(path),tmp_path/'prepared')
    assert result['population']==2 and result['source_sha256']==hashlib.sha256(source).hexdigest()
    assert (tmp_path/'prepared/raw/pair-0-raw.source').read_bytes()==source


def test_checked_in_real_capture_preserves_native_bytes_and_eight_actual_pam_flows():
    folder=Path(__file__).resolve().parents[1]/'infra/f1-lab/native-audit/captured-v113'
    provenance=json.loads((folder/'provenance.json').read_bytes());source=folder/'audit-native.source'
    assert sha(source)==provenance['source_sha256']
    reader=AuditIntentReview(provenance['source_sha256']);counts=Counter();rows=0
    with source.open('rb') as stream:
        for rows,body in enumerate(stream,1):
            line=body.decode('utf8');stamp=float(re.search(r'msg=audit\(([0-9.]+):',line)[1])
            result=reader.observe(rows,line,stamp,source_sha256=provenance['source_sha256'])
            assert result.line_sha256==hashlib.sha256(body).hexdigest()
            if result.eligible:counts[result.key[1]]+=1
    assert rows==provenance['physical_rows']==169
    assert counts==dict.fromkeys(['USER_LOGIN','USER_CMD','CRED_REFR','USER_START','USER_END','CRED_DISP'],8)
    assert provenance['role']=='controlled_normal_training' and provenance['new_independent_evaluation'] is False


@pytest.mark.parametrize('fault',['container','qemu','network','interface','host','independent','lost','timezone',
    'policy','command','failed','unset','duplicate_session','root_uid','session_count'])
def test_missing_isolation_scope_successful_operation_or_integrity_proof_rejects_intake(tmp_path,fault):
    path,report,_source,dump=fixture(tmp_path);guest=report['guest']
    if fault=='container':report['owned_container_removed']=False
    if fault=='qemu':guest['owned_qemu_exited']=False
    if fault=='network':guest['outer_networks_after_disconnect']={'bridge':{}}
    if fault=='interface':guest['outer_interfaces']=['lo','eth0']
    if fault=='host':report['host_configuration_changed']=True
    if fault=='independent':report['new_independent_evaluation']=True
    if fault=='lost':guest['capture']['status']['audit']['lost']='1'
    if fault=='timezone':guest['capture']['status']['timezone']='unknown'
    if fault=='policy':guest['capture']['status']['policy_sha256']='f'*64
    if fault=='command':guest['sessions'][0]['operation']['command']=['sudo','arbitrary']
    if fault=='failed':guest['sessions'][0]['ssh_exit']=1
    if fault=='unset':guest['sessions'][0]['operation']['loginuid']='4294967295'
    if fault=='duplicate_session':guest['sessions'][1]['operation']['sessionid']='1'
    if fault=='root_uid':guest['sessions'][0]['operation']['uid']=0
    if fault=='session_count':guest['sessions'].pop()
    dump()
    with pytest.raises(ValueError):prepare(path,sha(path),tmp_path/'rejected')


@pytest.mark.parametrize('fault',['execution_pin','source_pin','partial_line','missing_timestamp'])
def test_changed_or_incomplete_native_input_is_never_rewritten_to_pass(tmp_path,fault):
    path,report,source,dump=fixture(tmp_path)
    if fault=='source_pin':(tmp_path/'audit-native.source').write_bytes(source+b'extra\n')
    if fault in {'partial_line','missing_timestamp'}:
        source=source[:-1] if fault=='partial_line' else b'not an audit event\n'
        (tmp_path/'audit-native.source').write_bytes(source)
        report['guest']['capture'].update(bytes=len(source),sha256=hashlib.sha256(source).hexdigest());dump()
    with pytest.raises(ValueError):prepare(path,'f'*64 if fault=='execution_pin' else sha(path),tmp_path/'rejected')
