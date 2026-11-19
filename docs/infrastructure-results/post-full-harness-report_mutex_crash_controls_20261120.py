"""Owned Windows mutex timeout, process death, and blocked-reader boundaries."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

assert os.name=='nt'
source=Path(sys.argv[1]).resolve()
output=Path(sys.argv[2]).resolve()
output.mkdir(exist_ok=False,parents=True)
sys.path.insert(0,str(source))
from scripts.evaluate_m6 import write_report
from scripts.local_process_runtime import direct_python

binary,env=direct_python(dict(os.environ,AWS_EC2_METADATA_DISABLED='true',PYTHONPYCACHEPREFIX=str(output/'bytecode')))
env['PYTHONPATH']=str(source)+os.pathsep+env.get('PYTHONPATH','')
for name in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','AZURE_OPENAI_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_PROFILE'):env.pop(name,None)
path=output/'report.json'
write_report(path,{'old':True})
before=path.read_bytes()
child='''import sys,time
from pathlib import Path
from scripts.evaluate_m6 import _windows_report_mutex
root=Path(sys.argv[1])
with _windows_report_mutex(root/"report.json"):
 (root/"locked").write_text("owned")
 time.sleep(60)
'''
result={'schema':'owned-report-mutex-crash-controls-1','completed':False,'source_commit':sys.argv[3],'source_sha256':hashlib.sha256((source/'scripts/evaluate_m6.py').read_bytes()).hexdigest(),'paid_api_calls':0,'checks':[]}
p=subprocess.Popen([binary,'-c',child,str(output)],cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
result['owned_child_pid']=p.pid
try:
    deadline=time.monotonic()+45
    while not (output/'locked').exists():
        assert p.poll() is None and time.monotonic()<deadline
        time.sleep(.01)
    started=time.monotonic()
    try:write_report(path,{'should_not_publish':True})
    except TimeoutError:pass
    else:raise AssertionError('publication bypassed owned mutex')
    assert path.read_bytes()==before and not list(output.glob('.m6-report-*'))
    result['lock_timeout_seconds']=time.monotonic()-started
    result['checks'].append('bounded_mutex_wait_preserves_old_report_and_cleans_temporary')
    p.kill()
    p.wait(timeout=10)
    write_report(path,{'after_abandonment':True})
    assert json.loads(path.read_bytes())=={'after_abandonment':True}
    result['checks'].append('actual_process_death_releases_abandoned_mutex_for_next_writer')
    before=path.read_bytes()
    with path.open('rb'):
        try:write_report(path,{'must_not_replace_open_reader':True})
        except PermissionError:pass
        else:raise AssertionError('unshared reader was unexpectedly replaced')
        assert path.read_bytes()==before and not list(output.glob('.m6-report-*'))
    result['checks'].append('persistent_unshared_reader_remains_bounded_failure_with_old_report_intact')
    write_report(path,{'after_reader_closed':True})
    assert json.loads(path.read_bytes())=={'after_reader_closed':True}
    result['checks'].append('publication_recovers_after_reader_closes')
    result['completed']=True
finally:
    if p.poll() is None:p.kill()
    data=p.communicate(timeout=10)[0]
    (output/'owned-child.log').write_bytes(data)
    result['owned_child_finished']=p.poll() is not None
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
