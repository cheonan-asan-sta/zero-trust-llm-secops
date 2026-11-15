"""Offline public executor-volume initialization/copy; no secret payloads."""

import json
import sys
from pathlib import Path

from scripts.certificate_controller import LifecycleError, replace_file
from scripts.control_mirror import durable_parent
from scripts.control_transition import read

NAMES={'profile.json','cluster.json','management-transition.json','authority-coordinator.json','owner.json',
    'executor-transition.json','executor-transition-faults.json'}


def load(root):
    result={}
    for p in root.iterdir():
        if p.is_symlink():raise LifecycleError('executor_disk_symlink')
        if p.name.endswith(('.lock','.new')):continue
        if not p.is_file() or p.name not in NAMES or p.stat().st_size>4*1024**2:
            raise LifecycleError('executor_disk_file_scope')
        if p.name=='management-transition.json':read(p)
        if p.name=='executor-transition.json':
            from scripts.executor_transition import read_record
            read_record(json.loads(p.read_bytes()))
        result[p.name]=json.loads(p.read_bytes())
    return result


def copy_resume(root,source_root,expected):
    from scripts.executor_transition import core_files, tree_hashes
    source=core_files(load(source_root));target=core_files(load(root))
    if tree_hashes(source)!=expected:raise LifecycleError('executor_copy_source_changed')
    if any(name not in source or value!=source[name] for name,value in target.items()):
        raise LifecycleError('executor_copy_conflict')
    for name,value in source.items():
        if name not in target:replace_file(root/name,json.dumps(value,sort_keys=True));durable_parent(root/name)
    if core_files(load(root))!=source:raise LifecycleError('executor_copy_mismatch')
    return {'copied':True}


def main():
    request=json.load(sys.stdin);root=Path('/data')
    if request['operation']=='read':result=load(root)
    elif request['operation']=='write':
        for name,value in request['files'].items():
            if name not in NAMES:raise LifecycleError('executor_disk_write_scope')
            replace_file(root/name,json.dumps(value,sort_keys=True));durable_parent(root/name)
        result={'written':True}
    elif request['operation']=='copy_resume':
        result=copy_resume(root,Path('/source'),request['expected'])
    elif request['operation']=='copy':
        source=load(Path('/source'))
        if any(root.iterdir()):raise LifecycleError('executor_disk_target_not_empty')
        for name,value in source.items():
            replace_file(root/name,json.dumps(value,sort_keys=True));durable_parent(root/name)
        if load(root)!=source:raise LifecycleError('executor_disk_copy_mismatch')
        result={'copied':True}
    else:raise LifecycleError('executor_disk_operation')
    print(json.dumps(result))


if __name__=='__main__':main()
