"""Four owned processes and a reader contend on synthetic report publication."""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

source=Path(sys.argv[1]).resolve()
output=Path(sys.argv[2]).resolve()
output.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(source))
from scripts.local_process_runtime import direct_python

worker='''import json,sys,time
from pathlib import Path
from scripts.evaluate_m6 import write_report
root=Path(sys.argv[1]); worker=int(sys.argv[2]); go=root/"go"
(root/f"ready-{worker}").write_text("ready")
deadline=time.monotonic()+60
while not go.exists():
 if time.monotonic()>deadline:raise TimeoutError("owned barrier")
 time.sleep(.01)
for sequence in range(64):
 write_report(root/"report.json",{"worker":worker,"sequence":sequence,"data":str(worker)*65536})
'''
env=dict(os.environ,AWS_EC2_METADATA_DISABLED='true',PYTHONPYCACHEPREFIX=str(output/'bytecode'))
for name in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','AZURE_OPENAI_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_PROFILE'):
    env.pop(name,None)
env['PYTHONPATH']=str(source)+os.pathsep+env.get('PYTHONPATH','')
binary,env=direct_python(env)
processes=[]
report={'schema':'owned-atomic-report-stress-1','completed':False,'source_commit':'8d2df526843418e50124b23808c54b9597e79008','source_sha256':hashlib.sha256((source/'scripts/evaluate_m6.py').read_bytes()).hexdigest(),'workers':4,'writes_per_worker':64,'reader_complete_reports':0,'reader_sharing_conflicts':0,'paid_api_calls':0,'detection_metrics_changed':False}

started=time.monotonic()
try:
    for index in range(4):
        processes.append(subprocess.Popen([binary,'-c',worker,str(output),str(index)],cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT))
    (output/'owned-processes.json').write_text(json.dumps({'pids':[p.pid for p in processes],'executable':binary}))
    while not all((output/f'ready-{i}').exists() for i in range(4)):
        if any(p.poll() is not None for p in processes) or time.monotonic()-started>60:
            raise RuntimeError('owned workers did not reach barrier')
        time.sleep(.01)
    (output/'go').write_text('go')
    while True:
        try:
            value=json.loads((output/'report.json').read_bytes())
        except FileNotFoundError:
            pass
        except PermissionError:
            report['reader_sharing_conflicts']+=1
        else:
            assert set(value)=={'worker','sequence','data'} and type(value['worker']) is int and 0<=value['worker']<4
            assert type(value['sequence']) is int and 0<=value['sequence']<64 and value['data']==str(value['worker'])*65536
            report['reader_complete_reports']+=1
        if all(p.poll() is not None for p in processes):break
        if time.monotonic()-started>90:raise TimeoutError('owned publication deadline')
        time.sleep(.001)
    assert all(p.returncode==0 for p in processes)
    assert report['reader_complete_reports']>0
    assert not list(output.glob('.m6-report-*'))
    report['successful_atomic_writes']=256
    report['completed']=True
finally:
    for index,p in enumerate(processes):
        if p.poll() is None:p.kill()
        data=p.communicate(timeout=10)[0]
        (output/f'worker-{index}.log').write_bytes(data)
    report['child_exit_codes']=[p.returncode for p in processes]
    report['elapsed_seconds']=time.monotonic()-started
    report['owned_processes_finished']=all(p.poll() is not None for p in processes)
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
