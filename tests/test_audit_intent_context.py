import hashlib
import json
from dataclasses import replace

import pytest

from scripts.f1_lab.audit_intent_context import AuditIntentReview, command_intent
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.run_audit_intent_review import predict
from scripts.train_audit_intent import fit

SHA='a'*64


def row(kind,body, *, when=100.,serial=1):
    return f'type={kind} msg=audit({when}:{serial}): {body}\n'


def sequence(*,uid=1001,session=10,account='unrelated-user',pid=42,address='192.0.2.1'):
    unknown=f'pid={pid} uid=0 auid=4294967295 ses=4294967295'
    assigned=f'pid={pid} uid=0 auid={uid} ses={session}'
    msg=f'acct="{account}" exe="/usr/sbin/sshd" addr={address} terminal=ssh res=success'
    return [row('USER_ACCT',unknown+f" msg='op=PAM:accounting {msg}'",serial=1),
        row('CRED_ACQ',unknown+f" msg='op=PAM:setcred {msg}'",serial=2),
        row('LOGIN',assigned+' res=1',serial=3),
        row('USER_START',assigned+f" msg='op=PAM:session_open {msg}'",serial=4),
        row('USER_LOGIN',assigned+f" msg='op=login id={uid} exe=\"/usr/sbin/sshd\" addr={address} terminal=/dev/pts/0 res=success'",serial=5)]


def feed(review,lines, *, start=1,when=100.):
    return [review.observe(i,line,when,source_sha256=SHA) for i,line in enumerate(lines,start)]


def test_uid_process_role_does_not_replace_nonroot_target_and_ids_are_not_learned():
    a=feed(AuditIntentReview(SHA),sequence())[-1]
    b=feed(AuditIntentReview(SHA),sequence(uid=2002,account='different-user',pid=99,address='203.0.113.2'))[-1]
    assert a.eligible and a.key==b.key
    assert a.key==('sshd_nonroot_target_flow','USER_LOGIN','sshd','root','nonroot','success')


@pytest.mark.parametrize('omit',[0,1,2,3])
def test_missing_login_lifecycle_never_becomes_supported_intent(omit):
    lines=sequence();lines.pop(omit)
    assert not feed(AuditIntentReview(SHA),lines)[-1].eligible


@pytest.mark.parametrize('mutation',['root','different_pid','different_session','different_account','id_mismatch','failed'])
def test_inconsistent_flow_cannot_lower_alarm(mutation):
    lines=sequence()
    if mutation=='root':lines=sequence(uid=0,account='root')
    if mutation=='different_pid':lines[-1]=lines[-1].replace('pid=42','pid=43')
    if mutation=='different_session':lines[-1]=lines[-1].replace('ses=10','ses=11')
    if mutation=='different_account':lines[-2]=lines[-2].replace('unrelated-user','somebody-else')
    if mutation=='id_mismatch':lines[-1]=lines[-1].replace('id=1001 exe','id=9999 exe')
    if mutation=='failed':lines[-1]=lines[-1].replace('res=success','res=failed')
    assert not feed(AuditIntentReview(SHA),lines)[-1].eligible


def test_known_failed_auth_same_remote_address_is_retained_across_pids():
    r=AuditIntentReview(SHA)
    failed=row('USER_AUTH',"pid=900 uid=0 auid=4294967295 ses=4294967295 msg='exe=\"/usr/sbin/sshd\" addr=192.0.2.1 res=failed'")
    feed(r,[failed])
    assert not feed(r,sequence(),start=2)[-1].eligible


@pytest.mark.parametrize('secret',['/etc/gshadow','/etc/security/opasswd'])
def test_credential_store_read_observation_blocks_later_same_loginuid(secret):
    r=AuditIntentReview(SHA)
    command=('cat '+secret).encode().hex()
    prior=row('USER_CMD',f"pid=80 uid=1001 auid=1001 ses=9 msg='cmd={command} terminal=pts/9 res=success'")
    feed(r,[prior])
    assert not feed(r,sequence(),start=2)[-1].eligible


def test_closed_ssh_process_cannot_reopen_with_stale_lifecycle_stages():
    r=AuditIntentReview(SHA);feed(r,sequence())
    closed=row('USER_END','pid=42 uid=0 auid=1001 ses=10 msg=\'acct="unrelated-user" exe="/usr/sbin/sshd" res=success\'')
    feed(r,[closed],start=6)
    assert not feed(r,[sequence()[-1]],start=7)[-1].eligible


def test_missing_time_clears_partial_login_lifecycle():
    r=AuditIntentReview(SHA);feed(r,sequence()[:4])
    r.observe(5,'unavailable record\n',None,source_sha256=SHA)
    assert not feed(r,[sequence()[-1]],start=6)[-1].eligible


def test_source_switch_regression_and_reboot_do_not_reuse_context():
    r=AuditIntentReview(SHA);feed(r,sequence()[:4])
    assert not r.observe(5,sequence()[-1],100.,source_sha256='b'*64).eligible
    r=AuditIntentReview(SHA);feed(r,sequence()[:4])
    feed(r,[row('SYSTEM_BOOT','pid=1')],start=5)
    assert not feed(r,[sequence()[-1]],start=6)[-1].eligible


@pytest.mark.parametrize('command',['tail /var/log/auth.log','tail /etc/shadow','tail /var/log/syslog; id',
    'tail /var/log/syslog > /tmp/out','tail -f /var/log/syslog','tail /var/log/../etc/shadow'])
def test_unsupported_or_sensitive_command_never_becomes_log_inspection(command):
    assert command_intent(command.encode().hex())[0]=='unknown'


def diagnostic_command():
    return row('USER_CMD','pid=51 uid=1001 auid=1001 ses=10 msg=\'cwd="/home/arbitrary" '
        f'cmd={b"tail /var/log/syslog".hex()} terminal=pts/0 res=success\'',when=101.,serial=7)


def test_command_intent_is_bound_to_reported_session_and_closed_on_logout():
    r=AuditIntentReview(SHA);feed(r,sequence())
    assert feed(r,[diagnostic_command()],start=6,when=101.)[0].eligible
    end=row('USER_END','pid=42 uid=0 auid=1001 ses=10 msg=\'acct="unrelated-user" exe="/usr/sbin/sshd" res=success\'',when=102.)
    feed(r,[end],start=7,when=102.)
    assert not feed(r,[diagnostic_command().replace('101.0:','102.0:')],start=8,when=102.)[0].eligible


def test_support_threshold_and_any_training_attack_veto_are_preserved(tmp_path):
    raw=sequence()[-1];obs=feed(AuditIntentReview(SHA),sequence())[-1]
    before=OperationDecision(.99,.99,True,True,'unchanged')
    for n,attack,lower in [(4,False,False),(5,False,True),(100,True,False)]:
        model=IntentHead()
        for _ in range(n):model.add(obs,False)
        if attack:model.add(obs,True)
        path=tmp_path/f'{n}-{attack}.json';pin=model.save(path)
        frozen=IntentHead.load(path,pin)
        result=frozen.refine(before,obs,source_sha256=SHA,ordinal=5,raw=raw)
        assert result.alert is (not lower) and result.review
        assert not result.automatic_enforcement_allowed


def test_explicit_risk_reasons_and_observation_fingerprints_are_not_overridden(tmp_path):
    raw=sequence()[-1];obs=feed(AuditIntentReview(SHA),sequence())[-1];m=IntentHead()
    for _ in range(5):m.add(obs,False)
    pin=m.save(tmp_path/'m.json');m=IntentHead.load(tmp_path/'m.json',pin)
    before=OperationDecision(.99,.99,True,True,'verified_current_execution_or_caller_denial')
    assert m.refine(before,obs,source_sha256=SHA,ordinal=5,raw=raw) is before
    with pytest.raises(ValueError):m.refine(before,replace(obs,line_sha256='f'*64),source_sha256=SHA,ordinal=5,raw=raw)
    assert hashlib.sha256(raw.encode()).hexdigest()==obs.line_sha256


def packet(tmp_path):
    raw=tmp_path/'raw';raw.mkdir()
    lines=[line for i in range(5) for line in sequence(pid=42+i,session=10+i)]
    body=''.join(lines).encode();pin=hashlib.sha256(body).hexdigest()
    (raw/'pair-0-raw.source').write_bytes(body)
    member='gather/web/logs/audit/audit.log'
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs':[{'provenance':{'raw_member':member,'raw_sha256':pin,
            'simulation_start':0,'simulation_end':1000}}]}
    dump=lambda path,value:path.write_text(json.dumps(value),encoding='utf8')
    digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    dump(raw/'audit.json',manifest)
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':digest(raw/'audit.json'),
        'pairs':[{'raw_member':member,'raw_sha256':pin,'rows':len(lines)}]}
    dump(tmp_path/'preparation.json',prep)
    rows=[{'case_id':hashlib.sha256((pin+':'+str(i)).encode()).hexdigest(),'malicious':False}
        for i in range(1,len(lines)+1)]
    (tmp_path/'truth.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
    plan={'schema':'audit-intent-training-plan-1','scope':'previously_observed_development',
        'goal_qualified':False,'minimum_support':5,'sources':[{'name':'arbitrary-development-source',
            'role':'training','raw':str(raw),'preparation':str(tmp_path/'preparation.json'),
            'preparation_sha256':digest(tmp_path/'preparation.json'),
            'truth':str(tmp_path/'truth.jsonl'),'truth_sha256':digest(tmp_path/'truth.jsonl')} ]}
    dump(tmp_path/'plan.json',plan)
    return prep,raw,plan,rows,digest,dump


def test_explicit_training_then_pinned_replay_preserves_population_errors_and_order(tmp_path):
    prep,raw,plan,rows,sha,dump=packet(tmp_path)
    result=fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'fit')
    assert result['training'][0]['eligible']==5 and result['training'][0]['population']==25
    head=IntentHead.load(tmp_path/'fit/model.json',result['model_sha256'])
    previous=[{'case_id':r['case_id'],'source_index':0,'before':True,'after':True,
        'before_score':.99,'after_score':.99,'reason':'unchanged','error':'previous-error' if i==0 else None}
        for i,r in enumerate(rows)]
    baseline=tmp_path/'baseline.jsonl'
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in previous),encoding='utf8')
    outcome=predict(head,prep,raw,baseline,sha(baseline),tmp_path/'predictions.jsonl')
    predictions=[json.loads(r) for r in (tmp_path/'predictions.jsonl').read_text().splitlines()]
    assert outcome['population']==25 and outcome['inference_errors']==1 and outcome['changed_alerts']==5
    assert [r['case_id'] for r in predictions]==[r['case_id'] for r in rows]
    assert predictions[0]['error']=='previous-error' and predictions[0]['after'] is None
    assert sum(r['after'] is False for r in predictions)==5
    assert outcome['validation_labels_opened'] is False
    # Evaluation labels must never silently become training material.
    plan['sources'][0]['role']='evaluation';dump(tmp_path/'bad-plan.json',plan)
    with pytest.raises(ValueError,match='intent_training_role'):
        fit(tmp_path/'bad-plan.json',sha(tmp_path/'bad-plan.json'),tmp_path/'bad-fit')


def test_training_rejects_misaligned_truth_and_raw_drift(tmp_path):
    _prep,raw,plan,rows,sha,dump=packet(tmp_path)
    truth=tmp_path/'truth.jsonl'
    rows[0]['case_id']='0'*64
    truth.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
    plan['sources'][0]['truth_sha256']=sha(truth);dump(tmp_path/'plan.json',plan)
    with pytest.raises(ValueError,match='intent_training_truth_alignment'):
        fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'bad-fit')
    (raw/'pair-0-raw.source').write_text('tampered',encoding='utf8')
    with pytest.raises(ValueError,match='audit_auth_raw_hash'):
        fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'drift-fit')


def test_uniform_chain_applies_source_bound_auth_risk_before_learned_review(tmp_path):
    _prep,_raw,_plan,_rows,sha,dump=packet(tmp_path)
    result=fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'fit')
    head=IntentHead.load(tmp_path/'fit/model.json',result['model_sha256'])
    raw=tmp_path/'auth-raw';raw.mkdir()
    command='Jan 24 04:38:06 host sudo: arbitrary-user : TTY=pts/8 ; PWD=/tmp/cache ; USER=root ; COMMAND=/bin/cat /etc/shadow\n'
    opened='Jan 24 04:38:06 host sudo: pam_unix(sudo:session): session opened for user root by (uid=0)\n'
    source=raw/'pair-0-raw.source';source.write_bytes((command+opened).encode())
    pin=sha(source);member='gather/web/logs/auth.log'
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs':[{'provenance':{'raw_member':member,'raw_sha256':pin,
            'simulation_start':1642982400,'simulation_end':1643068800}}]}
    dump(raw/'audit.json',manifest)
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),
        'pairs':[{'raw_member':member,'raw_sha256':pin,'rows':2}]}
    baseline=tmp_path/'auth-baseline.jsonl'
    baseline.write_text(''.join(json.dumps({'case_id':hashlib.sha256((pin+':'+str(i)).encode()).hexdigest(),
        'source_index':0,'before':False,'after':False,'before_score':.1,'after_score':.1,
        'reason':'unchanged','error':None})+'\n' for i in (1,2)),encoding='utf8')
    for option,expected in [(False,False),(True,True)]:
        path=tmp_path/f'auth-{option}.jsonl'
        result=predict(head,prep,raw,baseline,sha(baseline),path,with_risk_observations=option)
        rows=[json.loads(r) for r in path.read_text().splitlines()]
        assert result['population']==2 and rows[0]['after'] is False
        assert rows[1]['after'] is expected
        if option:assert 'cooccurs' in rows[1]['reason']
