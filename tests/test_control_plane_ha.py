"""Local management replication is fenced, peer-first and fail-closed."""

import copy
import json
from pathlib import Path

import pytest

from scripts import certificate_controller as lifecycle
from scripts import control_mirror as mirror
from scripts.control_plane_ha import Management
from scripts.control_store import COMPONENTS, validate


@pytest.fixture
def paired(tmp_path, monkeypatch):
    a,b=tmp_path/'active',tmp_path/'peer';a.mkdir();b.mkdir()
    role={'schema':'control-role-1','epoch':1,'active':'a'}
    roles=[tmp_path/'role-a.json',tmp_path/'role-b.json']
    for p in roles:p.write_text(json.dumps(role))
    cfg={'expected':role,'roles':list(map(str,roles)),'mirrors':{str(a):str(b)},'shared':[str(tmp_path/'workload')]}
    monkeypatch.setenv(mirror.ENV,json.dumps(cfg))
    return a,b,roles,cfg


def test_peer_is_durable_before_active_file_is_replaced(paired,monkeypatch):
    a,b,_,_=paired;events=[]
    original=lifecycle.replace_file
    def replace(path,body):
        events.append(Path(path));original(path,body)
    monkeypatch.setattr(lifecycle,'replace_file',replace)
    lifecycle.atomic(a/'state.json','new-state')
    assert events==[b/'state.json',a/'state.json']
    assert (a/'state.json').read_bytes()==(b/'state.json').read_bytes()


def test_failed_peer_write_never_changes_active_state(paired,monkeypatch):
    a,b,_,_=paired;(a/'state.json').write_text('old');original=lifecycle.replace_file
    def replace(path,body):
        if Path(path).is_relative_to(b):raise OSError('peer disk unavailable')
        original(path,body)
    monkeypatch.setattr(lifecycle,'replace_file',replace)
    with pytest.raises(OSError):lifecycle.atomic(a/'state.json','new')
    assert (a/'state.json').read_text()=='old'


def test_active_loss_after_peer_write_leaves_recoverable_peer_prefix(paired,monkeypatch):
    a,b,_,_=paired;(a/'state.json').write_text('old');original=lifecycle.replace_file
    def replace(path,body):
        if Path(path).is_relative_to(a):raise OSError('active node lost')
        original(path,body)
    monkeypatch.setattr(lifecycle,'replace_file',replace)
    with pytest.raises(OSError):lifecycle.atomic(a/'state.json','new')
    assert (b/'state.json').read_text()=='new' and (a/'state.json').read_text()=='old'


@pytest.mark.parametrize('index',[0,1])
@pytest.mark.parametrize('fault',['missing','new_epoch','foreign_active','invalid_json'])
def test_missing_or_changed_role_fences_all_writes(paired,index,fault):
    a,b,roles,cfg=paired
    if fault=='missing':roles[index].unlink()
    elif fault=='invalid_json':roles[index].write_text('{')
    else:roles[index].write_text(json.dumps(cfg['expected']|({'epoch':2} if fault=='new_epoch' else {'active':'b'})))
    with pytest.raises(lifecycle.LifecycleError,match='role'):lifecycle.atomic(a/'private.key',b'fixture-only')
    assert not (a/'private.key').exists() and not (b/'private.key').exists()


def test_stale_controller_is_fenced_before_connecting_to_ca(paired,monkeypatch):
    a,_,roles,_=paired;roles[1].unlink()
    monkeypatch.setattr(lifecycle.ssl,'create_default_context',lambda **_k:pytest.fail('TLS connection attempted'))
    with pytest.raises(lifecycle.LifecycleError):lifecycle.ca_post(a,'/1.0/sign',{'ott':'unit-fixture'})


def test_retired_secret_is_removed_from_peer_before_active(paired,monkeypatch):
    a,b,_,_=paired
    for root in [a,b]:(root/'retired.key').write_bytes(b'fixture-only')
    events=[];original=Path.unlink
    def unlink(path,*args,**kwargs):events.append(path);return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'unlink',unlink)
    lifecycle.remove_file(a/'retired.key')
    assert events==[b/'retired.key',a/'retired.key']


def test_shared_workload_writes_are_still_role_guarded(paired):
    _,_,roles,cfg=paired;p=Path(cfg['shared'][0]);p.mkdir()
    lifecycle.atomic(p/'profile.json','new');assert (p/'profile.json').read_text()=='new'
    roles[0].unlink()
    with pytest.raises(lifecycle.LifecycleError):lifecycle.atomic(p/'profile.json','stale')
    assert (p/'profile.json').read_text()=='new'


def test_unmapped_or_parent_traversal_writes_are_denied(paired,tmp_path):
    a,_,_,_=paired
    for p in [tmp_path/'unexpected',a/'..'/'escaped']:
        with pytest.raises(lifecycle.LifecycleError,match='scope'):lifecycle.atomic(p,'bad')


@pytest.mark.skipif(__import__('os').name=='nt',reason='Windows symlink creation requires separate OS privileges')
def test_peer_symlink_never_escapes_replica(paired,tmp_path):
    a,b,_,_=paired;outside=tmp_path/'outside';outside.write_text('retain');(b/'secret').symlink_to(outside)
    with pytest.raises(lifecycle.LifecycleError,match='symlink'):lifecycle.atomic(a/'secret','bad')
    assert outside.read_text()=='retain'


@pytest.mark.parametrize('raw',['{','null','[]','{}'])
def test_malformed_mirror_configuration_never_falls_back(monkeypatch,tmp_path,raw):
    monkeypatch.setenv(mirror.ENV,raw)
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.atomic(tmp_path/'file','bad')
    assert not (tmp_path/'file').exists()


def test_legacy_writer_retains_original_behavior_without_opt_in(monkeypatch,tmp_path):
    monkeypatch.delenv(mirror.ENV,raising=False);p=tmp_path/'ordinary'
    lifecycle.atomic(p,'legacy');assert p.read_text()=='legacy';lifecycle.remove_file(p);assert not p.exists()


def backend():
    b=object.__new__(Management);b.depth=0;b.guard=lambda:None;events=[];b._operation=lambda value:events.append(value)
    return b,events


def test_successful_operation_releases_durable_busy_marker():
    b,events=backend()
    with b.management_operation(), b.management_operation():assert b.depth==1
    assert events==[True,False] and b.depth==0


def test_unknown_operation_failure_never_clears_busy_marker():
    b,events=backend()
    with pytest.raises(OSError),b.management_operation():raise OSError('lost reply')
    assert events==[True] and b.depth==0


@pytest.fixture
def candidate(tmp_path,monkeypatch):
    monkeypatch.delenv(mirror.ENV,raising=False)
    roots={n:tmp_path/n for n in COMPONENTS}
    for root in roots.values():root.mkdir()
    role={'epoch':1,'active':'a'}
    lifecycle.save(roots['control']/'role.json',role)
    lifecycle.save(roots['control']/'coordinator.json',{'phase':'idle','epoch':0})
    lifecycle.save(roots['control']/'operation.json',{'busy':False})
    lifecycle.save(roots['leaf']/'management-activity.json',{'busy':False})
    lifecycle.save(roots['leaf']/'state.json',{'transaction':None})
    return roots,role


@pytest.mark.parametrize('phase',['quiescing','trust_staged','migrating','committing','unknown'])
def test_unproven_authority_checkpoint_refuses_promotion_before_key_access(candidate,phase):
    roots,role=candidate;lifecycle.save(roots['control']/'coordinator.json',{'phase':phase})
    with pytest.raises(lifecycle.LifecycleError,match='unproven_transition'):validate(roots,role)


@pytest.mark.parametrize('component',['control','leaf'])
def test_unfinished_operation_blocks_promotion(candidate,component):
    roots,role=candidate
    p=roots[component]/('operation.json' if component=='control' else 'management-activity.json');lifecycle.save(p,{'busy':True})
    with pytest.raises(lifecycle.LifecycleError,match='unfinished_operation'):validate(roots,role)


def test_foreign_role_blocks_promotion_before_any_private_key_access(candidate):
    roots,role=candidate
    with pytest.raises(lifecycle.LifecycleError,match='candidate_role'):validate(roots,role|{'epoch':2})


def test_pending_leaf_publication_blocks_promotion(candidate):
    roots,role=candidate;lifecycle.save(roots['leaf']/'state.json',{'transaction':{'phase':'activated'}})
    with pytest.raises(lifecycle.LifecycleError,match='publication_pending'):validate(roots,role)


def profile():
    project='c02-'+'a'*12
    value={'project':project,'image':'sha256:'+'a'*64,'ca':{'name':project+'-ca','id':'a'*64},
        'leaf':{'name':project+'-leaf','id':'b'*64},'volumes':{n:project+'-a-'+n for n in ['ca','vault','leaf','renewal']},
        'service_hosts':{n:{'name':project+'-host-'+n,'id':n*64,'image':'sha256:'+'c'*64} for n in ['a','b']}}
    value['management']={'active':'a','epoch':1,'cells':{n:{'generation':1,'volumes':{k:project+'-'+n+'-'+k.replace('_','-') for k in COMPONENTS}} for n in ['a','b']}}
    return value


@pytest.mark.parametrize('change',['shared_volume','foreign_volume','bad_active','epoch_zero','bad_members','bad_generation'])
def test_management_profile_scope_cannot_alias_replicas_or_other_projects(change):
    p=copy.deepcopy(profile());m=p['management']
    if change=='shared_volume':m['cells']['b']['volumes']['ca']=m['cells']['a']['volumes']['ca']
    elif change=='foreign_volume':m['cells']['a']['volumes']['ca']='unrelated-project'
    elif change=='bad_active':m['active']='x'
    elif change=='epoch_zero':m['epoch']=0
    elif change=='bad_members':del m['cells']['b']
    else:m['cells']['a']['generation']=False
    with pytest.raises(lifecycle.LifecycleError,match='control_'):Management(p)


@pytest.mark.parametrize('recovery,incarnation',[('t','current'),('f','foreign')])
def test_candidate_database_identity_failure_never_fences_publishers(recovery,incarnation):
    b=Management(profile())
    b.job=lambda *a,**k:{'database_incarnation':'current'}
    b.sql=lambda node,query:recovery if 'pg_is_in_recovery' in query else incarnation
    b.ensure_no_jobs=lambda:pytest.fail('fencing sequence started before database identity proof')
    with pytest.raises(lifecycle.LifecycleError,match='primary_identity'):b._promote('b','a')


def test_orphan_management_writer_blocks_takeover():
    b=Management(profile());p=b.profile
    p['management']['standby']={'id':'d'*64};p['gateway_ids']=['e'*64,'f'*64]
    records=[{'Id':'9'*64,'Mounts':[{'Name':b.volumes()['vault'],'RW':True}]}]
    b.raw=lambda args:'9'*64 if args[0]=='ps' else json.dumps(records)
    with pytest.raises(lifecycle.LifecycleError,match='orphan_job'):b.ensure_no_jobs()


def test_fenced_admission_health_probe_uses_mount_free_disposable_process():
    b=Management(profile());b.profile['cluster_network']=b.project+'-cluster'
    calls=[];b.guard=lambda:None
    b.raw=lambda args,payload,timeout:calls.append((args,payload,timeout))
    request={'node':'a','roots':'public-ca','issuer':'public-issuer'}
    b.node_tls_probe('tls-check',request)
    args,payload,_=calls[0]
    assert args[:4]==['run','--rm','-i','--network'] and b.profile['cluster_network'] in args
    assert '--mount' not in args and 'exec' not in args and '--read-only' in args
    assert payload==request


@pytest.mark.parametrize('active',['a','b'])
def test_selected_storage_removes_old_cell_references_before_health_probe(active):
    b=Management(profile());b.profile['management']['active']=active
    b.select_active_storage();v=b.volumes()
    assert b.profile['volumes']=={k:v[k] for k in ['ca','vault','leaf','renewal']}
    assert b.profile['witness_volume']==v['witness']
    assert b.profile['backup_volume']==v['backups'] and b.profile['backup_key_volume']==v['backup_key']


def test_backup_quiescence_reads_replicated_control_after_host_cache_loss():
    b=Management(profile());b.leaf=lambda *a,**k:{'paused':True}
    b.load_control=lambda:{'phase':'idle'}
    b.directory=lambda:pytest.fail('host coordinator cache used as authority')
    events=[];b.wait_quiet=lambda:events.append('quiet')
    b.quiesce()
    assert events==['quiet']
