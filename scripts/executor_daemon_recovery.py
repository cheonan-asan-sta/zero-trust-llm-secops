"""Explicit recovery on the same trusted Docker data store; never restart Docker."""

import copy
import json
import re

from scripts import executor_transition as op
from scripts.certificate_controller import LifecycleError
from scripts.executor_cluster import Cluster


def prototype(anchor,site):
    return Cluster({**anchor,'active':site,'epoch':1,'hosts':{s:{'generation':1,'worker':None,
        'journal':anchor['project']+f'-executor-{s}-g1-journal','owner':anchor['project']+f'-executor-{s}-g1-owner'} for s in ['a','b']}})


def daemon_id(c):
    value=json.loads(c.raw(['info','--format','{{json .ID}}']))
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9:-]{16,128}',value):
        raise LifecycleError('executor_daemon_identity_invalid')
    return value


def validate_seal(seal):
    try:
        value=copy.deepcopy(seal);checksum=value.pop('sha256')
        if (set(value)!={'schema','anchor','daemon_id'} or value['schema']!='executor-daemon-seal-1'
                or checksum!=op.digest(value) or not re.fullmatch(r'[a-zA-Z0-9:-]{16,128}',value['daemon_id'])):raise ValueError
        prototype(value['anchor'],'a')
    except (ValueError,KeyError,TypeError):raise LifecycleError('executor_daemon_seal_invalid') from None
    return value


def verify_daemon(seal,anchor):
    value=validate_seal(seal);c=prototype(anchor,'a')
    if value['anchor']!=anchor or daemon_id(c)!=value['daemon_id']:raise LifecycleError('executor_daemon_identity_changed')
    for key in ['graph_image','executor_image']:
        image=json.loads(c.raw(['image','inspect',anchor[key]]))[0]
        if image['Id']!=anchor[key]:raise LifecycleError('executor_daemon_image_changed')
    return c


def seal_daemon(c):
    # Establish the public, out-of-daemon anchor while the paired cluster is healthy.
    for site in ['a','b']:
        for kind in ['journal','owner']:c.verify_volume(site,kind)
        if (c.disk(c.d['hosts'][site]['journal'],'read').get('cluster.json')!=c.d
                or c.disk(c.d['hosts'][site]['owner'],'read')!={'owner.json':c.role()}):
            raise LifecycleError('executor_daemon_seal_cluster_mismatch')
        if not c.inspect_worker(site)['State']['Running']:raise LifecycleError('executor_host_not_running')
    c.rpc('view')
    value={'schema':'executor-daemon-seal-1','anchor':c.anchor(),'daemon_id':daemon_id(c)}
    return {**value,'sha256':op.digest(value)}


def incomplete_workers(record):
    for descriptor in [record['original'],record['planned']]:
        c=Cluster(copy.deepcopy(descriptor))
        for site in ['a','b']:
            host=c.d['hosts'][site];name=c.project+f'-executor-{site}-e{c.d["epoch"]}'
            found=op.lookup(c,name)
            if found is None:
                if host['worker'] is not None:c.inspect_worker(site,missing_ok=descriptor is record['original'])
                continue
            if host['worker'] is None:
                if found['Config']['Labels'].get(op.LABEL)!=record['id']:raise LifecycleError('executor_operator_worker_replaced')
                host['worker']={'name':name,'id':found['Id']}
            c.verify_worker(site,found);op.require_stopped(found)


def restore_complete(record):
    c=Cluster(record['planned']);workers=[]
    op.require_absent(c,record['actor'].get('predecessors',[]))
    for site in ['a','b']:
        for kind in ['journal','owner']:c.verify_volume(site,kind)
        files=c.disk(c.d['hosts'][site]['journal'],'read')
        if files.get(op.NAME)!=op.envelope(record) or files.get('cluster.json')!=c.d:
            raise LifecycleError('executor_operator_complete_mismatch')
        if c.disk(c.d['hosts'][site]['owner'],'read')!={'owner.json':c.role()}:
            raise LifecycleError('executor_operator_complete_owner')
        found=c.inspect_worker(site)
        op.require_worker_state(found)
        workers.append(found)
    # No copy, owner write, epoch increment or business operation in this path.
    for found in workers:
        if not found['State']['Running']:c.raw(['start',found['Id']])
    c.rpc('raw',(['info','--format','{{.ID}}'],))
    return op.complete_result(record)


def recover_daemon(seal,anchor,site,journal,owner):
    c=verify_daemon(seal,anchor)
    if site not in {'a','b'} or not re.fullmatch(re.escape(c.project)+f'-executor-{site}-g[0-9]+-journal',journal):
        raise LifecycleError('executor_operator_recovery_scope')
    files=c.disk(journal,'read')
    if op.NAME not in files:raise LifecycleError('executor_actor_recovery_intent_missing')
    record=op.read_record(files[op.NAME]);old=Cluster(record['original'])
    if (old.anchor()!=anchor or record['target']!=site or old.d['hosts'][site]['journal']!=journal
            or old.d['hosts'][site]['owner']!=owner):raise LifecycleError('executor_operator_recovery_anchor')
    found=op.lookup(c,c.project+'-executor-takeover-lock')
    if found is not None:
        op.verify_actor(old,found,op.record_request(record));op.require_stopped(found)
        if found['Id']!=record['actor']['id']:raise LifecycleError('executor_operator_identity_changed')
    else:op.require_absent(c,[record['actor']['id']])
    if record['phase']=='complete':
        value=restore_complete(record)
        if found is not None:c.raw(['rm','--volumes',found['Id']])
        return value
    op.recovery_evidence(old,record,present_actor=found)
    incomplete_workers(record)
    return op.recover_operator(anchor,site,journal,owner)
