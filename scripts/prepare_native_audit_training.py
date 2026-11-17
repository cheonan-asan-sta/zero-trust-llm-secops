"""Preserve a verified owned-guest capture as controlled normal training only.

Labels come from a predeclared, isolated, authorized operation protocol; this
is neither publisher ground truth nor independent production validation.
Native source bytes are copied unchanged and every physical row is retained.
"""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha

COMMAND=['/usr/bin/sudo','-n','/usr/bin/tail','/var/log/syslog']
POLICY=b'zt-normal ALL=(root) NOPASSWD: /usr/bin/tail /var/log/syslog\n'


def prepare(execution_path,pin,output):
    execution_path=Path(execution_path)
    require(sha(execution_path)==pin,'native_training_execution_pin')
    execution=decode(execution_path.read_bytes());guest=execution.get('guest',{})
    require(execution.get('completed') is True and execution.get('owned_container_removed') is True
        and execution.get('network_disconnected_before_collection') is True
        and execution.get('host_configuration_changed') is False and execution.get('goal_qualified') is False
        and execution.get('new_independent_evaluation') is False and execution.get('aws_calls')==0
        and execution.get('paid_api_calls')==0 and guest.get('completed') is True
        and guest.get('role')=='controlled_normal_training' and guest.get('owned_qemu_exited') is True
        and guest.get('outer_networks_after_disconnect')=={} and guest.get('outer_interfaces')==['lo'],
        'native_training_controlled_scope')
    policy_sha=hashlib.sha256(POLICY).hexdigest()
    capture=guest['capture'];before=guest['guest_collection_begin']['status'];after=capture['status']
    require(before['boot_id']==after['boot_id'] and before['timezone']==after['timezone']=='UTC'
        and before['policy_sha256']==after['policy_sha256']==policy_sha
        and before['audit']['lost']==after['audit']['lost']=='0'
        and before['audit']['enabled'] in {'1','2'} and after['audit']['enabled'] in {'1','2'}
        and capture['complete_file_snapshot'] is True,'native_training_capture_contract')
    sessions=guest['sessions'];require(type(sessions) is list and len(sessions)==8,'native_training_sessions')
    ids=set()
    for n,spec in enumerate(sessions,1):
        operation=spec.get('operation',{})
        require(spec.get('number')==n and spec.get('ssh_exit')==0 and operation.get('exit_code')==0
            and operation.get('command')==COMMAND and type(operation.get('uid')) is int and operation['uid']>0,
            'native_training_operation')
        uid,session=operation.get('loginuid'),operation.get('sessionid')
        require(type(uid) is str and uid==str(operation['uid']) and type(session) is str
            and re.fullmatch(r'0|[1-9]\d{0,9}',session) and int(session)<4294967295
            and session not in ids and re.fullmatch(r'/dev/pts/\d{1,10}',operation.get('tty','')),
            'native_training_login_fields')
        ids.add(session)
    source=execution_path.parent/'audit-native.source'
    require(source.stat().st_size==capture['bytes'] and sha(source,16*1024**2)==capture['sha256'],
        'native_training_source_pin')
    rows=[];times=[]
    with source.open('rb') as stream:
        for ordinal,body in enumerate(stream,1):
            require(ordinal<=100000 and len(body)<=MAX_ROW and body.endswith(b'\n'),'native_training_raw_bound')
            match=re.search(rb'\bmsg=audit\((\d{1,12}(?:\.\d{1,9})?):\d{1,20}\):',body)
            require(match is not None,'native_training_native_timestamp')
            times.append(float(match[1]));rows.append(body)
    require(rows and min(times)>=0 and max(times)<4102444800,'native_training_time_bounds')
    out=Path(output);out.mkdir(parents=True,exist_ok=False);raw=out/'raw';raw.mkdir()
    shutil.copyfile(source,raw/'pair-0-raw.source')
    require(sha(raw/'pair-0-raw.source')==capture['sha256'],'native_training_copy_pin')
    member='gather/owned-native-guest/logs/audit/audit.log'
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'source_kind':'controlled_native_kernel_audit','normal_label_basis':'predeclared isolated authorized operations',
        'pairs':[{'provenance':{'raw_member':member,'raw_sha256':capture['sha256'],
            'native_source_path':'/var/log/audit/audit.log','simulation_start':int(min(times))-1,
            'simulation_end':int(max(times))+1,'execution_sha256':pin,'native_boot_id':after['boot_id']}}]}
    (raw/'audit.json').write_bytes(canonical(manifest)+b'\n')
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),
        'source_kind':'controlled_native_kernel_audit','pairs':[{'raw_member':member,'raw_sha256':capture['sha256'],'rows':len(rows)}]}
    (out/'preparation.json').write_bytes(canonical(prep)+b'\n')
    with (out/'truth.jsonl').open('xb') as target:
        for ordinal in range(1,len(rows)+1):
            target.write(canonical({'case_id':hashlib.sha256((capture['sha256']+':'+str(ordinal)).encode()).hexdigest(),
                'malicious':False,'attack_labels':[]})+b'\n')
    require(sha(execution_path)==pin and sha(source)==capture['sha256'],'native_training_source_drift')
    report={'completed':True,'role':'controlled_normal_training','source_kind':'real_kernel_audit_from_owned_guest',
        'normal_label_basis':'predeclared isolated authorized operations; not an independently adjudicated real incident',
        'execution_sha256':pin,'source_sha256':capture['sha256'],'population':len(rows),'successful_sessions':8,
        'native_bytes_modified':False,'unpaired_public_logs_assumed_benign':False,
        'preparation_sha256':sha(out/'preparation.json'),'truth_sha256':sha(out/'truth.jsonl'),
        'new_independent_evaluation':False,'original_evaluation_population_changed':False,
        'goal_qualified':False,'aws_calls':0,'paid_api_calls':0}
    (out/'run.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('execution','sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args();r=prepare(a.execution,a.sha256,a.output)
    print(json.dumps({k:r[k] for k in ('completed','role','population','goal_qualified')}));return 0


if __name__=='__main__':raise SystemExit(main())
