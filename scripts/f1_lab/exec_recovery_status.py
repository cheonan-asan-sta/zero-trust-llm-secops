"""Opt-in public recovery aggregates; unresolved work never becomes permission."""

import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.f1_lab.capture_archive import MAX_BYTES, MAX_RECORDS
from scripts.f1_lab.collector_status_bridge import MAX_REPORT, read_public, scope_hash, timestamp
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical

SCHEMA='zt-exec-recovery-status-1'
REPORT_TTL=60
COUNTERS={'intents','raw_bytes','sealed','indeterminate','published','unpublished'}
AGES={'indeterminate','unpublished'}


def validate(value,binding):
    require(isinstance(binding,str) and re.fullmatch('[a-f0-9]{64}',binding),'exec_recovery_status_scope')
    require(type(value) is dict and set(value)=={
        'schema','scope_sha256','checked_at','state','values','oldest_indeterminate_at','oldest_unpublished_at',
        'automatic_execution_allowed','authorization_asserted'},'exec_recovery_status_shape')
    require(value['schema']==SCHEMA and value['scope_sha256']==binding
            and value['state'] in {'ready','pending','unavailable'}
            and value['automatic_execution_allowed'] is False and value['authorization_asserted'] is False,
            'exec_recovery_status_binding')
    checked=timestamp(value['checked_at'])
    data=value['values']
    require(type(data) is dict and set(data)==(set() if value['state']=='unavailable' else COUNTERS),
            'exec_recovery_status_values')
    if data:
        require(all(type(v) is int and 0<=v<=MAX_RECORDS for k,v in data.items() if k!='raw_bytes')
                and type(data['raw_bytes']) is int and 0<=data['raw_bytes']<=MAX_BYTES
                and data['sealed']+data['indeterminate']==data['intents']
                and data['published']+data['unpublished']==data['sealed']
                and (value['state']=='pending')==(data['indeterminate']+data['unpublished']>0),
                'exec_recovery_status_counts')
        for kind in AGES:
            oldest=value['oldest_'+kind+'_at']
            require((data[kind]>0 and oldest is not None and timestamp(oldest)<=checked)
                    or (data[kind]==0 and oldest is None),'exec_recovery_status_age')
    else:
        require(all(value['oldest_'+k+'_at'] is None for k in AGES),'exec_recovery_status_unavailable')
    return checked


def report(scope,values=None,*,now=None):
    now=datetime.now(UTC) if now is None else now
    value={'schema':SCHEMA,'scope_sha256':scope_hash(scope),'checked_at':now.isoformat(),
           'state':'unavailable' if values is None else 'pending' if values['indeterminate']+values['unpublished'] else 'ready',
           'values':{k:values[k] for k in COUNTERS} if values is not None else {},
           'automatic_execution_allowed':False,'authorization_asserted':False}
    for kind in AGES:
        oldest=values['oldest_'+kind+'_at'] if values is not None else None
        value['oldest_'+kind+'_at']=oldest.isoformat() if oldest is not None else None
    validate(value,value['scope_sha256'])
    return value


def publish(path,value):
    path=Path(path)
    checked=validate(value,value['scope_sha256'])
    info=path.parent.lstat()
    require(path.is_absolute() and not path.is_symlink() and not path.parent.is_symlink()
            and stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid()
            and not stat.S_IMODE(info.st_mode)&0o022,'exec_recovery_status_public_parent')
    if path.exists():
        require(path.stat().st_uid==os.geteuid() and validate(read_public(path),value['scope_sha256'])<=checked,
                'exec_recovery_status_publication_clock')
    raw=canonical(value)+b'\n'
    require(len(raw)<=MAX_REPORT,'exec_recovery_status_public_bound')
    fd,temporary=tempfile.mkstemp(prefix='.exec-recovery-status-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(),0o644)
            stream.flush()
            os.fsync(stream.fileno())
        require(not path.is_symlink(),'exec_recovery_status_destination_link')
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def load_profile(path):
    value=read_public(path)
    require(type(value) is dict and set(value)=={'schema','scope_sha256','status_file',
        'max_indeterminate_age_seconds','max_unpublished_age_seconds','max_intents'}
        and value['schema']=='zt-exec-recovery-metrics-profile-1'
        and isinstance(value['scope_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['scope_sha256']),
        'exec_recovery_profile')
    require(isinstance(value['status_file'],str) and 0<len(value['status_file'])<=4096
            and Path(value['status_file']).is_absolute()
            and all(type(value['max_'+k+'_age_seconds']) is int
                    and 1<=value['max_'+k+'_age_seconds']<=86400 for k in AGES)
            and type(value['max_intents']) is int and 1<=value['max_intents']<=MAX_RECORDS,
            'exec_recovery_profile_policy')
    return value


def metrics(profile,*,now=None):
    now=datetime.now(UTC) if now is None else now
    rows=['# TYPE secops_exec_recovery_bridge_enabled gauge','secops_exec_recovery_bridge_enabled 1']
    valid=False
    value=None
    try:
        value=read_public(profile['status_file'])
        checked=validate(value,profile['scope_sha256'])
        require(timedelta(0)<=now-checked<timedelta(seconds=REPORT_TTL),'exec_recovery_status_expired')
        valid=value['state']!='unavailable'
    except (ValueError,OSError,TypeError,KeyError,RecursionError):
        pass
    rows.append(f'secops_exec_recovery_status_success {int(valid)}')
    if valid:
        data=value['values']
        for key,count in data.items():rows.append(f'secops_exec_recovery_{key} {count}')
        for kind in sorted(AGES):
            age=(now-timestamp(value['oldest_'+kind+'_at'])).total_seconds() if data[kind] else 0
            rows.append(f'secops_exec_recovery_oldest_{kind}_age_seconds {age}')
            rows.append(f"secops_exec_recovery_{kind}_overdue {int(data[kind]>0 and age>profile['max_'+kind+'_age_seconds'])}")
        rows.append(f"secops_exec_recovery_capacity_pressure {int(data['intents']>=profile['max_intents'])}")
    return '\n'.join(rows)+'\n'
