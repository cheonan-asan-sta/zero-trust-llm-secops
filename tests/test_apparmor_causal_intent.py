from dataclasses import replace

import pytest

from scripts.f1_lab.apparmor_causal_intent import AppArmorCausalReview
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.operation_refinement import OperationDecision
from tests.test_apparmor_noop import event

SOURCE='a'*64
START=1700000000.123


def changed(**kwargs):
    return [s.replace('info="same as current profile, skipping" ','') for s in event(**kwargs)]


def consume(reader,rows,*,start=1):
    import re
    return [reader.observe(n,line,float(re.search(r'audit\(([0-9.]+):',line)[1]),source_sha256=SOURCE)
        for n,line in enumerate(rows,start)]


def test_only_current_or_previous_rows_never_complete_first_status_from_future():
    reader=AppArmorCausalReview(SOURCE)
    first=consume(reader,changed())
    assert [o.eligible for o in first]==[False,False,True]
    # Fixture order is SYSCALL, AVC, PROCTITLE; both precede the arguments.
    assert first[2].key[1]=='PROCTITLE' and first[2].key[4]=='changed_profile'
    later=consume(reader,changed(stamp='1700000000.124',serial='72'),start=4)
    assert [o.eligible for o in later]==[False,True,True]
    assert first[1].eligible is False and later[1].key[2]=='prior_parser_invocation'


def test_real_source_avc_syscall_proctitle_order_has_the_same_causal_boundary():
    rows=changed();rows=[rows[1],rows[0],rows[2]]
    result=consume(AppArmorCausalReview(SOURCE),rows)
    assert [o.eligible for o in result]==[False,False,True]


@pytest.mark.parametrize('pid,delta,eligible',[('812',5,True),('812',5.001,False),('813',.001,False)])
def test_prior_invocation_is_same_pid_and_expires_without_refresh_from_status(pid,delta,eligible):
    reader=AppArmorCausalReview(SOURCE);consume(reader,changed())
    # Feeding a status at t+4 must not renew the prior command's t=0 TTL.
    status=changed(stamp=str(START+4),serial='72')[1]
    assert consume(reader,[status],start=4)[0].eligible
    row=changed(stamp=str(START+delta),serial='73',pid=pid)[1]
    if delta<4:
        reader=AppArmorCausalReview(SOURCE);consume(reader,changed());ordinal=4
    else:ordinal=5
    assert consume(reader,[row],start=ordinal)[0].eligible is eligible


@pytest.mark.parametrize('fault',['source','ordinal','clock','regression','missing','nan'])
def test_source_order_and_clock_fail_closed(fault):
    reader=AppArmorCausalReview(SOURCE);consume(reader,changed())
    row=changed(stamp='1700000000.124',serial='72')[1]
    source=SOURCE;ordinal=4;moment=START+.001
    if fault=='source':source='b'*64
    if fault=='ordinal':ordinal=5
    if fault=='clock':moment+=1
    if fault=='regression':moment=START-1
    if fault=='missing':moment=None
    if fault=='nan':moment=float('nan')
    assert not reader.observe(ordinal,row,moment,source_sha256=source).eligible
    assert reader.disabled and not reader.invocations


@pytest.mark.parametrize('before,after',[
    ('apparmor="STATUS"','apparmor="DENIED"'),('profile_replace','profile_remove'),
    ('profile_replace','profile_load'),('comm="apparmor_parser"','comm="sh"'),
    ('profile="unconfined"','profile="another"'),('name="/usr/bin/example"','error=-1 name="/usr/bin/example"'),
    ('name="/usr/bin/example"','denied_mask=w name="/usr/bin/example"'),
    ('name="/usr/bin/example"','requested_mask=w name="/usr/bin/example"'),
    ('name="/usr/bin/example"','name="relative"'),('pid=812','pid=0'),
])
def test_adverse_or_unmatched_status_revokes_prior_process_observation(before,after):
    reader=AppArmorCausalReview(SOURCE);consume(reader,changed())
    rows=changed(stamp='1700000000.124',serial='72');rows[1]=rows[1].replace(before,after)
    result=consume(reader,rows,start=4)
    assert not any(o.eligible for o in result)


@pytest.mark.parametrize('args',[
    ['/sbin/apparmor_parser','-R','/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser','-r','--Complain','/etc/apparmor.d/example'],
    ['/sbin/apparmor_parser','-r','/tmp/example'],
    ['/sbin/apparmor_parser','-r','/etc/apparmor.d/../example'],
    ['/bin/sh','-c','/etc/apparmor.d/example'],
])
def test_other_commands_do_not_establish_a_parser_invocation(args):
    rows=changed();rows[2]=rows[2].split('proctitle=')[0]+'proctitle='+b'\0'.join(a.encode() for a in args).hex()+'\n'
    reader=AppArmorCausalReview(SOURCE)
    assert not any(o.eligible for o in consume(reader,rows)) and not reader.invocations


@pytest.mark.parametrize('before,after',[
    ('pid=812','pid=813'),('exe="/sbin/apparmor_parser"','exe="/tmp/apparmor_parser"'),
    ('success=yes','success=no'),('syscall=1','syscall=59'),('exit=372','exit=-1'),
])
def test_mismatched_or_failed_syscall_cannot_establish_invocation(before,after):
    rows=changed();rows[0]=rows[0].replace(before,after)
    reader=AppArmorCausalReview(SOURCE)
    assert not any(o.eligible for o in consume(reader,rows))


def test_duplicate_record_and_boot_clear_state_without_rewriting_past_outputs():
    reader=AppArmorCausalReview(SOURCE);past=consume(reader,changed())
    rows=changed(stamp='1700000000.124',serial='72')
    duplicate=[rows[0],rows[0],rows[1],rows[2]]
    assert not any(o.eligible for o in consume(reader,duplicate,start=4))
    assert past[2].eligible and not reader.invocations
    consume(reader,['type=SYSTEM_BOOT msg=audit(1700000000.125:73): op=boot\n'],start=8)
    status=changed(stamp='1700000000.126',serial='74')[1]
    assert not consume(reader,[status],start=9)[0].eligible


def test_profile_names_are_not_learned_and_replacement_is_not_reported_as_noop():
    first=consume(AppArmorCausalReview(SOURCE),changed())[2]
    rows=[r.replace('/usr/bin/example','/opt/another') for r in changed()]
    assert consume(AppArmorCausalReview(SOURCE),rows)[2].key==first.key
    unchanged=consume(AppArmorCausalReview(SOURCE),event())[2]
    assert unchanged.key!=first.key and unchanged.key[4]=='unchanged_profile'


def test_another_executable_or_unbound_command_with_same_pid_revokes_prior_invocation():
    reader=AppArmorCausalReview(SOURCE);consume(reader,changed())
    row=changed(stamp='1700000000.124',serial='72')[0].replace('/sbin/apparmor_parser','/bin/sh')
    consume(reader,[row],start=4)
    later=changed(stamp='1700000000.125',serial='73')[1]
    assert not consume(reader,[later],start=5)[0].eligible


@pytest.mark.parametrize('normal,attack,lower',[(4,0,False),(5,0,True),(100,1,False)])
def test_only_supported_learned_cells_lower_generic_risk_and_never_grant_authority(tmp_path,normal,attack,lower):
    rows=changed();observation=consume(AppArmorCausalReview(SOURCE),rows)[2]
    model=IntentHead()
    for _ in range(normal):model.add(observation,False)
    for _ in range(attack):model.add(observation,True)
    pin=model.save(tmp_path/'head.json');model=IntentHead.load(tmp_path/'head.json',pin)
    previous=OperationDecision(.99,.99,True,True,'unchanged')
    result=model.refine(previous,observation,source_sha256=SOURCE,ordinal=3,raw=rows[2])
    assert result.alert is (not lower) and result.review and not result.automatic_enforcement_allowed
    denied=replace(previous,reason='signed_execution_policy_violation')
    assert model.refine(denied,observation,source_sha256=SOURCE,ordinal=3,raw=rows[2]) is denied
