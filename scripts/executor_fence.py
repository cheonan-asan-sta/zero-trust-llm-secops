"""Epoch guard for temporary jobs dispatched by a trusted executor host."""

import json
import os
import re
import sys
from pathlib import Path

from scripts.certificate_controller import LifecycleError

ENV='SECOPS_EXECUTOR_FENCE'


def owner(value):
    fields={'schema','project','epoch','active','graph_image','executor_image','generations'}
    if (not isinstance(value,dict) or set(value)!=fields or value['schema']!='executor-owner-1'
            or not isinstance(value['project'],str) or not re.fullmatch(r'c02-[a-f0-9]{12}',value['project'])
            or type(value['epoch']) is not int or value['epoch']<1 or value['active'] not in {'a','b'}
            or not isinstance(value['generations'],dict) or set(value['generations'])!={'a','b'}
            or any(type(n) is not int or n<1 for n in value['generations'].values())
            or any(not isinstance(value[k],str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',value[k]) for k in ['graph_image','executor_image'])):
        raise LifecycleError('executor_owner_shape')


def guard():
    raw=os.environ.get(ENV)
    if raw is None:return
    try:
        value=json.loads(raw)
        if set(value)!={'expected','roles'} or len(value['roles'])!=2 or len(set(value['roles']))!=2:
            raise ValueError
        owner(value['expected'])
        for name in value['roles']:
            path=Path(name)
            if not path.is_absolute() or '..' in path.parts or path.is_symlink() or json.loads(path.read_bytes())!=value['expected']:
                raise ValueError
    except (OSError,ValueError,TypeError,KeyError):
        raise LifecycleError('executor_job_stale_or_incomplete_owner') from None


def main():
    if len(sys.argv)<3 or sys.argv[1]!='exec':raise LifecycleError('executor_job_command_scope')
    guard();os.execvp(sys.argv[2],sys.argv[2:])


if __name__=='__main__':main()
