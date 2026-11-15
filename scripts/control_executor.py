"""Trusted maintenance host, never an online CA/leaf; owns Docker-admin access."""

import json
import os
import sys
import time

from scripts.authority_rotation_coordinator import Coordinator, lease
from scripts.certificate_controller import LifecycleError
from scripts.control_plane_ha import Management
from scripts.executor_store import Store

METHODS={'guard','load_control','save_control','leaf','custodian','witness','backup','restore_check',
    'promote','resume','command','raw','container','_operation','ensure_volumes','persist_profile'}
JOB_SITE='secops.executor-site'
JOB_EPOCH='secops.executor-epoch'
JOB_MODE='secops.executor-mode'


class ExecutorManagement(Management):
    def __init__(self,profile,store=None):
        super().__init__(profile)
        self.executor=store or Store.environment()
        if (self.executor.context['expected']['project'] != self.project
                or self.executor.context['expected']['graph_image'] != self.profile['image']
                or self.directory() != self.executor.root):
            raise LifecycleError('executor_profile_scope')

    def transition_read(self,path):return self.executor.record(path)
    def transition_write(self,path,record):self.executor.save_record(path,record)

    def raw(self,args,payload=None,timeout=60):
        self.executor.guard()
        if args and args[0] in {'run','create'}:
            c=self.executor.context
            operation=args[0]
            args=[operation,'--label',JOB_SITE+'='+c['site'],'--label',JOB_EPOCH+'='+str(c['expected']['epoch']),
                '--label',JOB_MODE+'='+('job' if operation=='run' else 'service'),
                '--label','secops.executor-project='+self.project,*args[1:]]
            if operation=='run':
                from scripts.executor_fence import ENV
                if args.count(self.profile['image'])!=1 or '--entrypoint' not in args:
                    raise LifecycleError('executor_job_image_or_entrypoint_scope')
                image_at=args.index(self.profile['image']);entry=args.index('--entrypoint')
                if entry+2!=image_at:raise LifecycleError('executor_job_entrypoint_layout')
                executable=args[entry+1];command=args[image_at+1:]
                prefix=args[:entry]
                for site in ['a','b']:
                    gen=c['expected']['generations'][site]
                    volume=self.project+f'-executor-{site}-g{gen}-owner'
                    prefix+=['--mount',f'type=volume,src={volume},dst=/executor-fence-{site},readonly']
                fence={'expected':c['expected'],'roles':['/executor-fence-a/owner.json','/executor-fence-b/owner.json']}
                args=[*prefix,'--env',ENV+'='+json.dumps(fence,separators=(',',':')),'--entrypoint','python',
                    self.profile['image'],'-m','scripts.executor_fence','exec',executable,*command]
        return super().raw(args,payload,timeout)

    def persist_profile(self):
        self.control_job({'operation':'write_profile','profile':self.profile})
        self.executor.save_json('profile.json',self.profile)


def main():
    if len(sys.argv)>1 and sys.argv[1]=='daemon':
        while True:time.sleep(1)
    store=Store.environment();store.guard();request=json.load(sys.stdin)
    b=ExecutorManagement(store.load_json('profile.json'),store)
    fault=request.get('fault')
    def cut(point,record=None):
        if fault and point==fault['point'] and (record is None or record['phase']==fault.get('phase',record['phase'])):
            os._exit(73)
    # Fault injection is only enabled by the dedicated local test command.
    if len(sys.argv)>1 and sys.argv[1]=='test-rpc':
        b._transition_hook=lambda point:cut(point)
        store.hook=cut
    elif fault:raise LifecycleError('executor_fault_mode_denied')
    operation=request['operation'];args=request.get('args',[]);kwargs=request.get('kwargs',{})
    if operation=='view':result=b.profile
    elif operation=='service-seal':
        from scripts.executor_cluster import Cluster
        from scripts.service_daemon_recovery import seal_services_local
        with lease(b.directory()):
            result=seal_services_local(Cluster(store.load_json('cluster.json')),*args,**kwargs)
    elif operation=='journal':result=store.record(b.directory()/'management-transition.json')
    elif operation=='tick':
        with lease(b.directory()):
            coordinator=Coordinator(b.profile,b.directory(),backend=b)
            try:coordinator.tick()
            except (OSError,ValueError,TypeError,KeyError):
                coordinator.state['last_error']='authority_transition_failed_no_rollback';coordinator.persist()
                raise
            result={'phase':coordinator.state['phase'],'epoch':coordinator.state['epoch'],'error':coordinator.state['last_error']}
    elif operation in {'promote','resume','backup','restore_check'}:result=getattr(b,operation)(*args,**kwargs)
    elif operation in METHODS:
        with lease(b.directory()):result=getattr(b,operation)(*args,**kwargs)
    else:raise LifecycleError('executor_operation_scope')
    print(json.dumps({'result':result,'profile':b.profile}))


if __name__=='__main__':main()
