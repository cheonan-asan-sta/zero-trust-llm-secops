from datetime import UTC, datetime

import pytest

from scripts.f1_lab.audit_auth_review import refine
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.sensitive_auth_context import (
    IDENTITY_REASON,
    REASON,
    RECON_REASON,
    SensitiveAuthReview,
)

SHA = 'a'*64
NOW = datetime(2025,1,24,4,38,6,tzinfo=UTC).timestamp()
CMD = 'Jan 24 04:38:06 host sudo:    arbitrary-user : TTY=pts/8 ; PWD=/tmp/cache ; USER=root ; COMMAND=/bin/cat /etc/shadow\n'
OPEN = 'Jan 24 04:38:06 host sudo: pam_unix(sudo:session): session opened for user root by (uid=0)\n'


def observe(observer, ordinal, line, moment=NOW, source=SHA):
    return observer.observe(ordinal,line,moment,source_sha256=source)


def test_missing_pid_remains_unknown_but_observed_credential_cooccurrence_adds_risk():
    o=SensitiveAuthReview(SHA)
    assert observe(o,1,CMD) is None
    reason=observe(o,2,OPEN)
    assert reason==REASON and 'cooccurs' in reason
    before=OperationDecision(.1,.1,False,False,'baseline')
    after=refine(before,reason)
    assert after.alert and after.review and not after.automatic_enforcement_allowed


@pytest.mark.parametrize('command', ['/bin/cat /etc/passwd','/bin/cat /etc/shadow.old',
    '/bin/echo /etc/shadow','/bin/cat /tmp/shadow','/bin/cat /etc/shadow; echo x',
    '/bin/cat /etc/shadow | head','/bin/cat $(echo /etc/shadow)', '/bin/cat /etc/shadow > /tmp/out'])
def test_nonmatching_or_shell_ambiguous_commands_do_not_create_this_signal(command):
    o=SensitiveAuthReview(SHA)
    observe(o,1,CMD.replace('/bin/cat /etc/shadow',command))
    assert observe(o,2,OPEN) is None


@pytest.mark.parametrize('change', ['host','target','closed','service','expired','missing_time','mismatched_time','source','ordinal','pid'])
def test_unbound_or_ambiguous_sequence_cannot_add_risk(change):
    o=SensitiveAuthReview(SHA)
    first=CMD if change!='pid' else CMD.replace('sudo:','sudo[42]:')
    observe(o,1,first)
    line=OPEN
    kwargs={}
    ordinal=2
    if change=='host':line=line.replace(' host ',' other ')
    if change=='target':line=line.replace('user root','user nobody')
    if change=='closed':line=line.replace('opened','closed')
    if change=='service':line=line.replace('sudo:','sshd:')
    if change=='expired':line=line.replace('04:38:06','04:38:08');kwargs['moment']=NOW+2
    if change=='missing_time':kwargs['moment']=None
    if change=='mismatched_time':kwargs['moment']=NOW+1
    if change=='source':kwargs['source']='b'*64
    if change=='ordinal':ordinal=3
    if change=='pid':line=line.replace('sudo:','sudo[43]:')
    assert observe(o,ordinal,line,**kwargs) is None


def test_intervening_record_and_later_command_never_explain_earlier_pam():
    o=SensitiveAuthReview(SHA)
    assert observe(o,1,OPEN) is None
    observe(o,2,CMD)
    observe(o,3,'unrelated record\n')
    assert observe(o,4,OPEN) is None


def test_source_clock_regression_disables_new_context():
    o=SensitiveAuthReview(SHA)
    observe(o,1,CMD)
    observe(o,2,OPEN.replace('04:38:06','04:38:05'),NOW-1)
    observe(o,3,CMD)
    assert observe(o,4,OPEN) is None


def test_second_pam_does_not_reuse_consumed_command_and_prior_alert_is_preserved():
    o=SensitiveAuthReview(SHA)
    observe(o,1,CMD)
    reason=observe(o,2,OPEN)
    assert reason==REASON and observe(o,3,OPEN) is None
    before=OperationDecision(.99,.99,True,True,'independent')
    assert refine(before,reason) is before


def test_recursive_root_recon_from_web_upload_path_is_observed_risk_not_identity():
    o=SensitiveAuthReview(SHA)
    line=CMD.replace('/tmp/cache','/var/www/unrelated/app/uploads/images').replace('/bin/cat /etc/shadow','/bin/ls -laR /root/')
    observe(o,1,line)
    assert observe(o,2,OPEN)==RECON_REASON


@pytest.mark.parametrize('pwd,command', [('/home/admin','/bin/ls -laR /root/'),
    ('/tmp/cache','/bin/ls -laR /root/'),('/var/www/site/public','/bin/ls -laR /root/'),
    ('/var/www/site/uploads','/bin/ls -la /root/'),('/var/www/site/uploads','/bin/ls -laR /tmp/'),
    ('/var/www/site/uploads/../public','/bin/ls -laR /root/'),
    ('/var/www/site/uploads','/bin/ls -laR /root/; echo x')])
def test_recon_requires_both_web_path_shape_and_direct_protected_recursive_request(pwd,command):
    o=SensitiveAuthReview(SHA)
    observe(o,1,CMD.replace('/tmp/cache',pwd).replace('/bin/cat /etc/shadow',command))
    assert observe(o,2,OPEN) is None


@pytest.mark.parametrize('root',['/var/www/site/uploads/2025/01','/srv/www/app/cache',
    '/usr/share/nginx/html/content/tmp'])
@pytest.mark.parametrize('target',['/etc/passwd','/etc/group'])
def test_root_identity_enumeration_from_web_storage_adds_review_only(root,target):
    o=SensitiveAuthReview(SHA)
    command=CMD.replace('/tmp/cache',root).replace('/bin/cat /etc/shadow','/bin/cat '+target)
    observe(o,1,command)
    reason=observe(o,2,OPEN)
    assert reason==IDENTITY_REASON
    result=refine(OperationDecision(.1,.1,False,False,'unchanged'),reason)
    assert result.alert and result.review and not result.automatic_enforcement_allowed


@pytest.mark.parametrize('pwd,command',[('/home/admin','/bin/cat /etc/passwd'),
    ('/tmp/cache','/bin/cat /etc/passwd'),('/var/www/site/public','/bin/cat /etc/passwd'),
    ('/var/www/site/uploads-backup','/bin/cat /etc/passwd'),
    ('/var/www/site/uploads/../public','/bin/cat /etc/passwd'),
    ('/var/www/site/uploads','/bin/cat /etc/passwd.old'),
    ('/var/www/site/uploads','/bin/cat /etc/passwd; id'),
    ('/var/www/site/uploads','/bin/cat /etc/passwd > /tmp/out')])
def test_identity_read_requires_exact_file_direct_command_and_web_storage_shape(pwd,command):
    o=SensitiveAuthReview(SHA)
    observe(o,1,CMD.replace('/tmp/cache',pwd).replace('/bin/cat /etc/shadow',command))
    assert observe(o,2,OPEN) is None
