import hashlib
import json
import string

import pytest

from scripts.f1_lab.journal_service_review import (
    JournalServiceReview,
    encoded_dns_error,
    journal_time,
    micros,
)
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_journal_service_review import predict

MACHINE='1'*32
BOOT='2'*32
INVOCATION='3'*32
LABEL='+/'+(string.ascii_letters+string.digits)[:59]
QUERY='.'.join([LABEL]*4+['example','org'])
MESSAGE=f"dig: '{QUERY}' is not a legal name (ran out of space)"


def audit(kind,stamp,serial,body):
    return f'type={kind} msg=audit({stamp}:{serial}): {body}\n'


def packet(tmp_path,*,mutate=None,stamp='1001.000'):
    command='pid=1 uid=0 auid=4294967295 ses=4294967295 msg=\'unit=demo comm="systemd" exe="/lib/systemd/systemd" res=success\''
    lines=[audit('USER_END','1000.000',1,'pid=2 uid=0'),audit('SERVICE_START',stamp,2,command),
        audit('SERVICE_STOP',stamp,3,command)]
    source=tmp_path/'audit.source';source.write_bytes(''.join(lines).encode());pin=sha(source)
    base={'_MACHINE_ID':MACHINE,'_BOOT_ID':BOOT,'_HOSTNAME':'internal-share'}
    rows=[
        {**base,'__REALTIME_TIMESTAMP':'1000001000','_SOURCE_REALTIME_TIMESTAMP':'1000000000',
            '_TRANSPORT':'audit','_AUDIT_ID':'1','MESSAGE':'USER_END pid=2 uid=0'},
        {**base,'__REALTIME_TIMESTAMP':'1000100000','_TRANSPORT':'journal','_PID':'1','_UID':'0',
            'UNIT':'demo.service','JOB_TYPE':'start','INVOCATION_ID':INVOCATION},
        {**base,'__REALTIME_TIMESTAMP':'1000999000','_TRANSPORT':'stdout','_PID':'55','_UID':'0',
            '_SYSTEMD_UNIT':'demo.service','_SYSTEMD_INVOCATION_ID':INVOCATION,
            '_EXE':'/bin/bash','_CMDLINE':'/bin/bash /usr/bin/task','MESSAGE':MESSAGE},
    ]
    if mutate:mutate(rows)
    path=tmp_path/'journal.jsonl';path.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
    member={'path':str(path),'sha256':sha(path),'machine_id':MACHINE,'hostname':'internal-share'}
    reader=JournalServiceReview(pin,lines,[member])
    return reader,pin,lines,member


def run(reader,pin,lines):
    return [reader.observe(n,line,source_sha256=pin) for n,line in enumerate(lines,1)]


def test_prior_process_evidence_links_by_unit_boot_and_invocation_without_filling_human_identity(tmp_path):
    reader,pin,lines,_=packet(tmp_path);actual=run(reader,pin,lines)
    assert actual[0] is None and all(actual[n] for n in [1,2])
    assert actual[1]['evidence_age_microseconds']==1000
    assert actual[1]['reported_process_pid']=='55' and actual[1]['human_caller_verified'] is False
    assert 'auid=4294967295' in lines[1]


@pytest.mark.parametrize('stamp,expected',[('1005.999',True),('1005.999001',False)])
def test_five_second_boundary_uses_integer_microseconds(tmp_path,stamp,expected):
    r,pin,lines,_=packet(tmp_path,stamp=stamp)
    assert bool(run(r,pin,lines)[1]) is expected


@pytest.mark.parametrize('fault',[
    'future_receipt','future_source','missing_receipt','missing_anchor','wrong_anchor_body','wrong_machine',
    'wrong_hostname','wrong_unit','wrong_boot','wrong_invocation','wrong_transport','not_root',
    'manager_pid','different_exe','shell_metachar','non_shell_command','no_payload',
])
def test_missing_mismatched_or_future_evidence_cannot_raise_review(tmp_path,fault):
    def mutate(rows):
        row=rows[2]
        if fault=='future_receipt':row['__REALTIME_TIMESTAMP']='1001000001'
        if fault=='future_source':row['_SOURCE_REALTIME_TIMESTAMP']='1001000001'
        if fault=='missing_receipt':row.pop('__REALTIME_TIMESTAMP')
        if fault=='missing_anchor':rows[0]['_TRANSPORT']='stdout'
        if fault=='wrong_anchor_body':rows[0]['MESSAGE']='USER_END pid=3 uid=0'
        if fault=='wrong_machine':row['_MACHINE_ID']='f'*32
        if fault=='wrong_hostname':row['_HOSTNAME']='other-host'
        if fault=='wrong_unit':row['_SYSTEMD_UNIT']='other.service'
        if fault=='wrong_boot':row['_BOOT_ID']='f'*32
        if fault=='wrong_invocation':row['_SYSTEMD_INVOCATION_ID']='f'*32
        if fault=='wrong_transport':row['_TRANSPORT']='syslog'
        if fault=='not_root':row['_UID']='1000'
        if fault=='manager_pid':row['_PID']='1'
        if fault=='different_exe':row['_EXE']='/usr/bin/dig'
        if fault=='shell_metachar':row['_CMDLINE']='/bin/bash /usr/bin/task;other'
        if fault=='non_shell_command':row['_CMDLINE']='/bin/bash -c payload'
        if fault=='no_payload':row['MESSAGE']="dig: 'example.org' is not a legal name (ran out of space)"
    r,pin,lines,_=packet(tmp_path,mutate=mutate)
    assert run(r,pin,lines)==[None,None,None]


def test_later_unit_invocation_invalidates_earlier_process_evidence(tmp_path):
    def mutate(rows):rows.append({**rows[1],'__REALTIME_TIMESTAMP':'1000999500','INVOCATION_ID':'e'*32})
    r,pin,lines,_=packet(tmp_path,mutate=mutate)
    assert run(r,pin,lines)==[None,None,None]


def test_source_order_mismatch_disables_further_evidence(tmp_path):
    r,pin,lines,_=packet(tmp_path)
    assert r.observe(1,lines[0],source_sha256='f'*64) is None
    assert r.observe(2,lines[1],source_sha256=pin) is None and r.disabled


def test_reset_requires_new_preceding_native_audit_anchor(tmp_path):
    _,_,lines,member=packet(tmp_path)
    lines=[audit('SYSTEM_BOOT','1000.000',1,'op=boot'),*lines[1:]]
    pin=hashlib.sha256(''.join(lines).encode()).hexdigest()
    r=JournalServiceReview(pin,lines,[member])
    assert run(r,pin,lines)==[None,None,None]


def test_changed_raw_line_cannot_reuse_original_source_pin(tmp_path):
    r,pin,lines,_=packet(tmp_path)
    assert r.observe(1,lines[0],source_sha256=pin) is None
    assert r.observe(2,lines[1].replace('unit=demo','unit=other'),source_sha256=pin) is None
    assert r.disabled and r.observe(3,lines[2],source_sha256=pin) is None


def test_sidecar_tamper_is_rejected_before_or_after_observation(tmp_path):
    r,pin,lines,m=packet(tmp_path)
    path=tmp_path/'journal.jsonl';path.write_text('changed',encoding='utf8')
    with pytest.raises(ValueError,match='journal_sidecar_pin'):JournalServiceReview(pin,lines,[m])
    with pytest.raises(ValueError,match='journal_sidecar_drift'):r.verify()


def test_oversize_name_is_not_enough_without_entropy_or_nonhostname_payload():
    assert encoded_dns_error(MESSAGE)
    assert not encoded_dns_error(MESSAGE.replace(LABEL,'a'*61))
    assert not encoded_dns_error(MESSAGE.replace('+','X').replace('/','Y'))
    assert not encoded_dns_error(MESSAGE.replace('ran out of space','other problem'))


def test_dns_wire_limit_counts_label_lengths_and_root_and_handles_trailing_dot():
    q='.'.join([LABEL]*3+['a'*62])
    assert len(q)==248 and not encoded_dns_error(f"dig: '{q}' is not a legal name (ran out of space)")
    assert encoded_dns_error(MESSAGE.replace(QUERY,QUERY+'.'))


@pytest.mark.parametrize('value',[None,True,'nan','1.1234567','4102444800','-1'])
def test_invalid_audit_microsecond_time_is_unavailable(value):
    assert micros(value) is None


def test_earlier_origin_cannot_hide_later_receipt():
    assert journal_time({'_SOURCE_REALTIME_TIMESTAMP':'1000000000','__REALTIME_TIMESTAMP':'1001000001'})==1001000001


def test_replay_preserves_existing_alert_reason_errors_and_complete_population(tmp_path):
    _,pin,lines,m=packet(tmp_path)
    raw=tmp_path/'raw';raw.mkdir();(raw/'pair-0-raw.source').write_bytes(''.join(lines).encode())
    prep={'pairs':[{'raw_sha256':pin,'raw_member':'gather/internal_share/logs/audit/audit.log','rows':3}]}
    prior=[{'case_id':hashlib.sha256((pin+':'+str(n)).encode()).hexdigest(),'source_index':0,
        'before':False,'after':False,'before_score':.1,'after_score':.1,'reason':'unchanged',
        'error':'prior-error' if n==3 else None} for n in range(1,4)]
    baseline=tmp_path/'baseline.jsonl';baseline.write_text(''.join(json.dumps(r)+'\n' for r in prior),encoding='utf8')
    member={**m,'source_index':0,'raw_source_sha256':pin}
    out=tmp_path/'pred.jsonl';report=predict(prep,raw,baseline,sha(baseline),out,[member])
    rows=[json.loads(b) for b in out.read_bytes().splitlines()]
    assert report['population']==3 and report['inference_errors']==1 and report['changed_alerts']==1
    assert rows[1]['after'] is True and rows[2]['error']=='prior-error' and rows[2]['after'] is None
    prior[1].update(after=True,after_score=.98,reason='verified_current_denial')
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in prior),encoding='utf8')
    out=tmp_path/'preserve.jsonl';predict(prep,raw,baseline,sha(baseline),out,[member])
    rows=[json.loads(b) for b in out.read_bytes().splitlines()]
    assert rows[1]['after_score']==.98 and rows[1]['reason']=='verified_current_denial'
