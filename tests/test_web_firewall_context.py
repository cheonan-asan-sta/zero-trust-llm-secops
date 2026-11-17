import hashlib
import json
import re

import pytest

from scripts.f1_lab.audit_auth_review import refine
from scripts.f1_lab.audit_intent_context import IntentObservation
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.web_firewall_context import REASON, WebFirewallReview
from scripts.run_audit_intent_review import predict
from scripts.run_local_vpn_protocol_batch import run as batch

SOURCE='a'*64


def row(kind,body,*,at=100.,serial=1):
    return f'type={kind} msg=audit({at}:{serial}): {body}\n'


def sequence(*,command='iptables -L',cwd='/var/www/arbitrary/site/uploads/2025/11',pid=42,tty='pts/7',at=100.5):
    session='auid=4294967295 ses=4294967295'
    cmd=f'pid={pid} uid=1003 {session} msg=\'cwd="{cwd}" cmd={command.encode().hex()} terminal={tty} res=success\''
    pam=f'pid={pid} uid=0 {session} msg=\'acct="root" exe="/usr/bin/sudo" terminal=/dev/{tty} res=success\''
    return [row('USER_CMD',cmd),row('CRED_REFR',pam,serial=2),row('USER_START',pam,serial=3),
        row('NETFILTER_CFG','table=arbitrary_table family=2 entries=0',at=at,serial=4),
        row('SYSCALL','arch=c000003e syscall=313 success=yes exit=0 ppid=900 pid=901 uid=0',at=at,serial=4),
        row('PROCTITLE','proctitle='+b'/sbin/modprobe\0-q\0--\0iptable_filter'.hex(),at=at,serial=4)]


def feed(observer,rows,*,start=1):
    return [observer.observe(n,line,float(re.search(r'audit\(([0-9.]+):',line)[1]),source_sha256=SOURCE)
        for n,line in enumerate(rows,start)]


def test_same_source_request_pam_and_later_netfilter_observations_add_review_only():
    observer=WebFirewallReview(SOURCE);reasons=feed(observer,sequence())
    assert reasons==[None,None,None,REASON,REASON,REASON]
    assert 'cooccurs' in REASON
    before=OperationDecision(.1,.1,False,False,'unchanged');after=refine(before,REASON)
    assert after.alert and after.review and not after.automatic_enforcement_allowed
    already=OperationDecision(.99,.99,True,True,'independent-current-denial')
    assert refine(already,REASON) is already


def test_enriched_aliases_do_not_change_raw_request_and_pam_context():
    lines=[r.rstrip('\n')+'\x1dUID="display-only" AUID="unknown"\n' for r in sequence()]
    assert feed(WebFirewallReview(SOURCE),lines)==[None,None,None,REASON,REASON,REASON]


@pytest.mark.parametrize('omit',[0,1,2,3])
def test_missing_request_pam_stage_or_netfilter_record_cannot_seed(omit):
    rows=sequence();rows.pop(omit)
    assert not any(feed(WebFirewallReview(SOURCE),rows))


@pytest.mark.parametrize('cwd,command',[
    ('/home/operator','iptables -L'),('/tmp/cache','iptables -L'),('/var/www/site/public','iptables -L'),
    ('/var/www/site/uploads-backup','iptables -L'),('/var/www/site/uploads/../public','iptables -L'),
    ('/var/www/site//uploads','iptables -L'),('/var/www/site/uploads','iptables -F'),
    ('/var/www/site/uploads','iptables -L; id'),('/var/www/site/uploads','iptables -L | cat'),
    ('/var/www/site/uploads','iptables -L > /tmp/out'),('/var/www/site/uploads','iptables $(id)'),
    ('/var/www/site/uploads','cat /proc/net/ip_tables_names'),('/var/www/site/uploads','iptables -L -L'),
])
def test_plain_admin_other_commands_and_ambiguous_shells_do_not_add_this_signal(cwd,command):
    assert not any(feed(WebFirewallReview(SOURCE),sequence(cwd=cwd,command=command)))


@pytest.mark.parametrize('command',['/sbin/iptables --list -n','ip6tables -L -v','/usr/sbin/nft list ruleset'])
def test_fixed_query_grammar_handles_ipv6_and_nft_without_identifier_exceptions(command):
    assert feed(WebFirewallReview(SOURCE),sequence(command=command,pid=123,tty='pts/12'))[-1]==REASON


@pytest.mark.parametrize('fault',['pid','tty','uid','acct','exe','failed','auid','session'])
def test_conflicting_reported_fields_prevent_binding_request_to_pam(fault):
    rows=sequence()
    old,new={'pid':('pid=42','pid=43'),'tty':('pts/7','pts/8'),'uid':('uid=0','uid=1003'),
        'acct':('acct="root"','acct="other"'),'exe':('/usr/bin/sudo','/usr/sbin/sshd'),
        'failed':('res=success','res=failed'),'auid':('auid=4294967295','auid=1003'),
        'session':('ses=4294967295','ses=10')}[fault]
    rows[2]=rows[2].replace(old,new)
    assert not any(feed(WebFirewallReview(SOURCE),rows))


@pytest.mark.parametrize('at,expected',[(100.,True),(105.,True),(105.001,False)])
def test_original_order_and_five_second_boundary_do_not_renew_from_pam(at,expected):
    assert bool(feed(WebFirewallReview(SOURCE),sequence(at=at))[-1]) is expected


def test_later_request_never_backfills_earlier_netfilter_and_event_consumes_seed_once():
    observer=WebFirewallReview(SOURCE)
    early=row('NETFILTER_CFG','table=filter family=2 entries=0',serial=1)
    assert feed(observer,[early])==[None]
    observer=WebFirewallReview(SOURCE);assert feed(observer,sequence())[-1]==REASON
    later=row('NETFILTER_CFG','table=filter family=2 entries=0',at=101.,serial=5)
    assert feed(observer,[later],start=7)==[None]


def test_boot_clears_context_and_unset_login_fields_remain_unverified():
    observer=WebFirewallReview(SOURCE);feed(observer,sequence()[:3])
    assert observer.confirmed[42][2]==('4294967295','4294967295')
    boot=row('SYSTEM_BOOT','op=boot',at=100.25,serial=4)
    assert feed(observer,[boot],start=4)==[None] and not observer.confirmed
    net=sequence()[3].replace(':4)',':5)')
    assert feed(observer,[net],start=5)==[None]


@pytest.mark.parametrize('kind',['USER_END','CRED_DISP'])
def test_closed_pam_flow_cannot_seed_later_netfilter(kind):
    rows=sequence();closed=rows[2].replace('USER_START',kind).replace(':3)',':4)')
    rows.insert(3,closed)
    assert not any(feed(WebFirewallReview(SOURCE),rows))


@pytest.mark.parametrize('fault',['source','ordinal','clock','missing','regression','serial','nan','malformed'])
def test_bad_source_order_clock_and_malformed_rows_disable_new_context(fault):
    observer=WebFirewallReview(SOURCE);rows=sequence();feed(observer,rows[:3])
    line=rows[3];ordinal=4;moment=100.5;source=SOURCE
    if fault=='source':source='b'*64
    if fault=='ordinal':ordinal=5
    if fault=='clock':moment=101.
    if fault=='missing':moment=None
    if fault=='regression':line=line.replace('100.5','99.0');moment=99.
    if fault=='serial':line=line.replace(':4)',':2)')
    if fault=='nan':moment=float('nan')
    if fault=='malformed':line='not an audit row\n'
    assert observer.observe(ordinal,line,moment,source_sha256=source) is None
    assert observer.disabled and not observer.pending and not observer.confirmed


def test_ambiguous_multiple_confirmed_commands_and_duplicate_event_do_not_propagate():
    observer=WebFirewallReview(SOURCE);first=sequence();feed(observer,first[:3])
    second=sequence(pid=43)[:3];second=[r.replace(':1)',':4)').replace(':2)',':5)').replace(':3)',':6)') for r in second]
    feed(observer,second,start=4)
    assert feed(observer,[first[3].replace(':4)',':7)')],start=7)==[None]
    observer=WebFirewallReview(SOURCE);feed(observer,first[:4])
    assert feed(observer,[first[3]],start=5)==[None]
    assert feed(observer,[first[4]],start=6)==[None]


@pytest.mark.parametrize('value',[None,1,'true'])
def test_runner_network_mode_requires_boolean_before_opening_files(value):
    with pytest.raises(ValueError,match='protocol_network_option'):
        batch('not-opened','not-opened','unused',with_network_audit_context=value)


def test_opt_in_replay_keeps_all_rows_errors_explicit_denials_and_default_behavior(tmp_path):
    raw=tmp_path/'raw';raw.mkdir();body=''.join(sequence()).encode()
    (raw/'pair-0-raw.source').write_bytes(body);pin=sha(raw/'pair-0-raw.source')
    pairs=[{'raw_member':'gather/web/logs/audit/audit.log','raw_sha256':pin,'rows':6},
        {'raw_member':'gather/dns/logs/dnsmasq.log','raw_sha256':'d'*64,'rows':1}]
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs':[{'provenance':{**p,'simulation_start':0,'simulation_end':200}} for p in pairs]}
    (raw/'audit.json').write_text(json.dumps(manifest),encoding='utf8')
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),'pairs':pairs}
    previous=[]
    for index,pair in enumerate(pairs):
        for ordinal in range(1,pair['rows']+1):
            previous.append({'case_id':hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest(),
                'source_index':index,'before':False,'after':False,'before_score':.1,'after_score':.1,
                'reason':'unchanged','error':None if index==0 else 'previous-error'})
    baseline=tmp_path/'baseline.jsonl'
    def dump():baseline.write_text(''.join(json.dumps(r)+'\n' for r in previous),encoding='utf8')
    dump();head=IntentHead();observation=IntentObservation(pin,1,'b'*64,('unused',)*6,True)
    for _ in range(5):head.add(observation,False)
    model=tmp_path/'head.json';model_pin=head.save(model);head=IntentHead.load(model,model_pin)
    for enabled,changes in [(False,0),(True,3)]:
        path=tmp_path/f'pred-{enabled}.jsonl'
        result=predict(head,prep,raw,baseline,sha(baseline),path,with_apparmor_causality=True,
            with_network_audit_context=enabled)
        rows=[json.loads(r) for r in path.read_text().splitlines()]
        assert result['population']==7 and result['inference_errors']==1 and result['changed_alerts']==changes
        assert [r['case_id'] for r in rows]==[r['case_id'] for r in previous]
        assert rows[-1]['after'] is None and rows[-1]['error']=='previous-error'
        if enabled:assert all(r['reason']==REASON for r in rows[3:6])
    previous[3].update(after=True,after_score=.99,reason='signed_execution_policy_violation');dump()
    path=tmp_path/'denied.jsonl'
    result=predict(head,prep,raw,baseline,sha(baseline),path,with_apparmor_causality=True,
        with_network_audit_context=True)
    assert result['changed_alerts']==2
    denied=json.loads(path.read_text().splitlines()[3])
    assert denied['after'] is True and denied['reason']=='signed_execution_policy_violation'
    (raw/'pair-0-raw.source').write_bytes(body+b'extra\n')
    with pytest.raises(ValueError,match='audit_auth_raw_hash'):
        predict(head,prep,raw,baseline,sha(baseline),tmp_path/'invalid.jsonl',with_network_audit_context=True)
