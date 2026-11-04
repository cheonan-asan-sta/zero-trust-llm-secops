"""Peer-first public executor state; takeover requires external confirmed fencing.

Two replicas are NOT a quorum. Only the trusted operator changes owner records
while both old worker containers are removed and their child work is settled.
"""

import json
import os
from pathlib import Path

from scripts.certificate_controller import LifecycleError, replace_file
from scripts.control_mirror import durable_parent
from scripts.control_transition import read, write
from scripts.executor_fence import owner

ENV = 'SECOPS_EXECUTOR_CONTEXT'
FILES = {'profile.json','management-transition.json','cluster.json'}


class Store:
    def __init__(self,context):
        if (set(context) != {'site','expected','root','peer','roles'} or context['site'] not in {'a','b'}
                or len(context['roles']) != 2 or len(set(context['roles'])) != 2):
            raise LifecycleError('executor_context_shape')
        expected=context['expected']
        owner(expected)
        paths=[context['root'],context['peer'],*context['roles']]
        if any(not isinstance(p,str) or not Path(p).is_absolute() or '..' in Path(p).parts for p in paths):
            raise LifecycleError('executor_path_scope')
        a,b=Path(context['root']),Path(context['peer'])
        if a==b or a.is_relative_to(b) or b.is_relative_to(a):
            raise LifecycleError('executor_shared_storage')
        self.context=context;self.root=a;self.peer=b;self.hook=None

    @classmethod
    def environment(cls):
        try:return cls(json.loads(os.environ[ENV]))
        except (OSError,ValueError,TypeError,KeyError):raise LifecycleError('executor_context_invalid') from None

    def guard(self):
        c=self.context
        if c['site'] != c['expected']['active']:
            raise LifecycleError('executor_passive_host')
        try:
            for name in c['roles']:
                path=Path(name)
                if path.is_symlink() or json.loads(path.read_bytes()) != c['expected']:
                    raise LifecycleError('executor_stale_or_incomplete_owner')
            if self.root.is_symlink() or self.peer.is_symlink() or not self.root.is_dir() or not self.peer.is_dir():
                raise LifecycleError('executor_storage_missing')
        except (OSError,ValueError,TypeError):
            raise LifecycleError('executor_stale_or_incomplete_owner') from None

    def pair(self,path):
        path=Path(path)
        if path.parent != self.root or path.name not in FILES or path.is_symlink():
            raise LifecycleError('executor_file_scope')
        peer=self.peer/path.name
        if peer.is_symlink():raise LifecycleError('executor_file_symlink')
        return path,peer

    def record(self,path):
        self.guard();a,b=self.pair(path)
        left,right=read(a),read(b)
        if left != right:raise LifecycleError('executor_journal_divergence_requires_fence')
        if left is not None:self.record_scope(left)
        return left

    def record_scope(self,record):
        expected=self.context['expected']
        if (not isinstance(record,dict) or record.get('project')!=expected['project']
                or record.get('image')!=expected['graph_image']):
            raise LifecycleError('executor_journal_project_or_image')

    def save_record(self,path,record):
        self.guard();a,b=self.pair(path);self.record_scope(record)
        if Path(path).name!='management-transition.json':raise LifecycleError('executor_journal_scope')
        write(b,record)
        if self.hook:self.hook('journal_peer_saved',record)
        self.guard();write(a,record)

    def save_json(self,name,value):
        self.guard();a,b=self.pair(self.root/name)
        if name=='management-transition.json':raise LifecycleError('executor_json_scope')
        raw=json.dumps(value,sort_keys=True)
        replace_file(b,raw);durable_parent(b)
        self.guard();replace_file(a,raw);durable_parent(a)

    def load_json(self,name):
        self.guard();a,b=self.pair(self.root/name)
        try:
            left=json.loads(a.read_bytes());right=json.loads(b.read_bytes())
        except (OSError,ValueError,TypeError):raise LifecycleError('executor_cache_invalid') from None
        if left != right:raise LifecycleError('executor_cache_divergence_requires_fence')
        return left
