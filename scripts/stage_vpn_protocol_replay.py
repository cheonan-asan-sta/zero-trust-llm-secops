"""Build an allowlisted label-free replay package from a pinned local catalog."""

import argparse
import io
import json
import re
import shutil
import tarfile
from pathlib import Path

from scripts.f1_lab.audit_intent_context import PROFILE as INTENT_PROFILE
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha

ROOT=Path(__file__).resolve().parents[1]
PREDICTION_FIELDS={'case_id','source_index','before','after','before_score','after_score','reason','error'}


def stage(catalog_path,pin,output,*,profile='vpn'):
    require(profile in {'vpn','apparmor-causal','audit-native-normal'},'protocol_stage_profile')
    require(sha(catalog_path)==pin,'protocol_catalog_pin')
    catalog=decode(Path(catalog_path).read_bytes())
    require(catalog['schema']=='vpn-protocol-replay-catalog-1' and catalog['goal_qualified'] is False
        and catalog['scope']=='observed_development' and 1<=len(catalog['scenarios'])<=16,'protocol_catalog_scope')
    out=Path(output);out.mkdir(parents=True,exist_ok=False);inputs=out/'inputs';inputs.mkdir()
    (inputs/'raw').mkdir();(inputs/'baseline').mkdir();(inputs/'models').mkdir();(out/'results').mkdir()
    original={};projection=[];names=set();baseline={'completed':True,'goal_qualified':False,'scenarios':{}}
    plan={'schema':'ordered-audit-replay-1','scope':'observed_development_only','goal_qualified':False,
        'baseline':'/inputs/baseline.json','scenarios':[]}
    for spec in catalog['scenarios']:
        name=spec['name']
        require(type(name) is str and re.fullmatch('[a-z0-9_-]{1,64}',name) and name not in names,'protocol_catalog_name')
        names.add(name)
        prep_path=Path(spec['preparation']);raw=Path(spec['raw']);before=Path(spec['baseline'])
        require(sha(prep_path)==spec['preparation_sha256'] and sha(before)==spec['baseline_sha256'],'protocol_catalog_input_pin')
        prep=decode(prep_path.read_bytes());manifest_path=raw/'audit.json'
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False
            and sha(manifest_path)==prep['source_manifest_sha256'],'protocol_catalog_preparation')
        require(1<=len(prep['pairs'])<=64 and all(type(p['rows']) is int and 0<p['rows']<=2000000
            and type(p['raw_member']) is str and 1<=len(p['raw_member'])<=4096
            and re.fullmatch('[a-f0-9]{64}',p['raw_sha256']) for p in prep['pairs']),'protocol_catalog_pair_contract')
        manifest=decode(manifest_path.read_bytes());folder=inputs/'raw'/name;folder.mkdir()
        projected_manifest={'completed':manifest['completed'],'timestamp_basis':manifest['timestamp_basis'],
            'pairs':[{'provenance':{k:p['provenance'][k] for k in
                ('raw_member','raw_sha256','simulation_start','simulation_end')}} for p in manifest['pairs']]}
        (folder/'audit.json').write_bytes(canonical(projected_manifest)+b'\n')
        projected_prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(folder/'audit.json'),
            'pairs':[{k:p[k] for k in ('raw_member','raw_sha256','rows')} for p in prep['pairs']]}
        projected=inputs/(name+'-preparation.json');projected.write_bytes(canonical(projected_prep)+b'\n')
        count=0;destination=inputs/'baseline'/(name+'.jsonl')
        with before.open('rb') as source,destination.open('xb') as target:
            while body:=source.readline(MAX_ROW+1):
                require(len(body)<=MAX_ROW and set(decode(body))==PREDICTION_FIELDS,'protocol_baseline_field_allowlist')
                count+=1;require(count<=2000000,'protocol_catalog_population_bound');target.write(body)
        require(count==sum(p['rows'] for p in prep['pairs'])==spec['population']
            and sha(destination)==spec['baseline_sha256'],'protocol_catalog_population')
        original[prep_path]=sha(prep_path);original[manifest_path]=sha(manifest_path);original[before]=sha(before)
        for index,pair in enumerate(prep['pairs']):
            suffixes=('/openvpn.log',) if profile=='vpn' else ('/logs/audit/audit.log','/logs/auth.log')
            if pair['raw_member'].endswith(suffixes):
                path=raw/f'pair-{index}-raw.source';require(sha(path,64*1024**2)==pair['raw_sha256'],'protocol_stage_raw_pin')
                original[path]=sha(path);shutil.copyfile(path,folder/path.name)
                require(sha(folder/path.name)==pair['raw_sha256'],'protocol_stage_copy_pin')
        baseline['scenarios'][name]={'population':count,'prediction':{'predictions_sha256':sha(destination)}}
        plan['scenarios'].append({'name':name,'preparation':'/inputs/'+projected.name,'preparation_sha256':sha(projected),
            'raw':'/tmp/raw/'+name,'prediction':'/tmp/baseline/'+name+'.jsonl'})
        projection.append({'scenario':name,'original_preparation_sha256':sha(prep_path),
            'original_raw_manifest_sha256':sha(manifest_path),'projected_preparation_sha256':sha(projected),
            'projected_raw_manifest_sha256':sha(folder/'audit.json'),'original_prediction_sha256':sha(before)})
    (inputs/'baseline.json').write_bytes(canonical(baseline)+b'\n')
    plan['baseline_sha256']=sha(inputs/'baseline.json');(inputs/'plan.json').write_bytes(canonical(plan)+b'\n')
    directory={'vpn':'frozen-vpn-protocol-v109','apparmor-causal':'frozen-apparmor-causal-v111',
        'audit-native-normal':'frozen-audit-native-normal-v113'}[profile]
    bundle_dir=ROOT/'infra/f1-lab'/directory;bundle=decode((bundle_dir/'bundle.json').read_bytes())
    if profile=='audit-native-normal':require(bundle['feature_profile']==INTENT_PROFILE,'protocol_intent_feature_profile')
    model_files=('web.json','heads.json','vpn.json','policy.json','legacy.json','head.json') if profile=='vpn' else ('head.json',)
    if profile=='audit-native-normal':model_files+=('supplemental.json',)
    for name in model_files:
        shutil.copyfile(bundle_dir/name,inputs/'models'/name)
    require(sha(inputs/'models/head.json')==bundle['head']['sha256'],'protocol_bundle_copy_pin')
    if profile=='vpn':require(sha(inputs/'models/legacy.json')==bundle['legacy']['sha256'],'protocol_bundle_copy_pin')
    if profile=='audit-native-normal':
        require(sha(inputs/'models/supplemental.json')==bundle['supplemental']['sha256'],'protocol_bundle_copy_pin')
    source_manifest=[]
    with tarfile.open(inputs/'code.tar','w') as archive:
        for directory in ('app','scripts'):
            for path in sorted((ROOT/directory).rglob('*.py')):
                require(path.is_file() and not path.is_symlink() and path.stat().st_size<=2*1024**2,'protocol_code_file')
                body=path.read_bytes();name=path.relative_to(ROOT).as_posix()
                info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o644;info.mtime=0
                archive.addfile(info,io.BytesIO(body));source_manifest.append({'path':name,'sha256':sha(path)})
    (out/'source-manifest.json').write_bytes(canonical(source_manifest)+b'\n')
    (out/'projection-provenance.json').write_bytes(canonical(projection)+b'\n')
    require(all(sha(p)==value for p,value in original.items()),'protocol_stage_source_drift')
    report={'completed':True,'catalog_sha256':pin,'plan_sha256':sha(inputs/'plan.json'),
        'model_sha256':bundle['head']['sha256'],'legacy_models_sha256':bundle['legacy']['sha256'] if profile=='vpn' else None,
        'profile':profile,
        'supplemental_model_sha256':bundle['supplemental']['sha256'] if profile=='audit-native-normal' else None,
        'source_archive_sha256':sha(inputs/'code.tar'),'source_manifest_sha256':sha(out/'source-manifest.json'),
        'projection_provenance_sha256':sha(out/'projection-provenance.json'),
        'source_pins':[{'path':str(p),'sha256':value} for p,value in original.items()],
        'input_pins':{p.relative_to(inputs).as_posix():sha(p) for p in inputs.rglob('*') if p.is_file()},
        'validation_labels_or_aggregates_staged':False,'frozen_training_parameters_staged':True,
        'scenarios':len(names),'goal_qualified':False,'new_independent_evaluation':False,'aws_calls':0,'paid_api_calls':0}
    (out/'stage.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('catalog','sha256','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--profile',choices=('vpn','apparmor-causal','audit-native-normal'),default='vpn')
    a=parser.parse_args();r=stage(a.catalog,a.sha256,a.output,profile=a.profile)
    print(json.dumps({'completed':r['completed'],'scenarios':r['scenarios'],'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
