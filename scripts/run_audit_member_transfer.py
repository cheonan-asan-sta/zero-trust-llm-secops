"""Frozen audit/auth member transfer; old whole-archive exposure is preserved."""

import argparse
import hashlib
from pathlib import Path

from scripts.f1_lab.audit_member_transfer import (
    POLICY,
    MemberAccessLedger,
    check_prior_access,
    header_for,
    select_pairs,
)
from scripts.f1_lab.bounded_zip import copy_member, inspect
from scripts.f1_lab.line_truth import annotations, pair_members
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_transfer import POLICY as WILSON_POLICY
from scripts.f1_lab.rotation_transfer import pair_predictions
from scripts.f1_lab.scanner_transfer import POLICY as WARDBECK_POLICY
from scripts.f1_lab.scanner_transfer import check_original_role
from scripts.f1_lab.transfer_evaluation import load_detector, score, sha, source_pins
from scripts.f1_lab.transfer_evaluation import predict as base_predict
from scripts.prepare_native_stream import prepare as prepare_features
from scripts.prepare_transfer_source import timezone
from scripts.run_apparmor_noop_review import predict as noop_predict
from scripts.run_audit_auth_review import predict as audit_predict

ROOT = Path(__file__).resolve().parents[1]


def freeze(catalog_path,catalog_hash,output):
    require(sha(catalog_path) == catalog_hash,'audit_transfer_catalog_hash')
    catalog = decode(Path(catalog_path).read_bytes())
    require(catalog['schema'] == 'audit-member-source-catalog-1'
            and [s['name'] for s in catalog['sources']] == ['wilson','wardbeck'], 'audit_transfer_catalog')
    check_original_role(ROOT)
    output = Path(output)
    require(not output.exists() and not output.is_symlink(),'audit_transfer_fresh_freeze')
    config = decode((ROOT/'infra/f1-lab/operation-refinement-protocol.json').read_bytes())
    models = config['models']
    policy = {'path':'runtime/f1/operation-refinement-v40-20261113/policy.json',
              'sha256':sha(ROOT/'runtime/f1/operation-refinement-v40-20261113/policy.json')}
    for spec in [*models.values(),policy]:
        require(sha(ROOT/spec['path']) == spec['sha256'],'audit_transfer_model_pin')
    value = {'schema':'audit-auth-member-transfer-freeze-1','policy':POLICY,
             'source_pins':source_pins(ROOT),'models':models,'operation_policy':policy,
             'catalog_sha256':catalog_hash,'goal_qualified':False,'sources':[]}
    for item in catalog['sources']:
        receipt_path = Path(item['acquisition'])
        receipt = decode(receipt_path.read_bytes())
        archive = Path(item['archive'])
        publisher = {'wilson':WILSON_POLICY,'wardbeck':WARDBECK_POLICY}[item['name']]
        for asset_key,policy_key in [('asset_id','asset_id'),('record_id','publisher_record'),
                                     ('record_version','publisher_version'),('filename','filename'),
                                     ('publisher_md5','publisher_md5'),('license_id','license_id')]:
            require(receipt['asset'][asset_key] == publisher[policy_key],'audit_transfer_publisher_contract')
        require((item['simulation_start'],item['simulation_end'])
                == (publisher['simulation_start'],publisher['simulation_end']),'audit_transfer_publisher_bounds')
        require(receipt['completed'] is True and receipt['publisher_md5_verified'] is True
                and receipt['asset']['filename'] == archive.name
                and receipt['asset']['license_id'] == 'cc-by-nc-sa-4.0'
                and sha(archive) == receipt['local_sha256'],'audit_transfer_acquisition')
        original_path = Path(item['prior_manifest'])
        original = decode(original_path.read_bytes())
        require(original['completed'] is True and original['archive_sha256'] == receipt['local_sha256'],
                'audit_transfer_original_manifest')
        global_access = archive.parent/'evaluation-access.json'
        require(global_access.is_file(),'audit_transfer_prior_exposure_required')
        selected,excluded = select_pairs(inspect(archive,receipt['local_sha256'])['entries'],original['pairs'])
        member_ledger = archive.parent/'audit-auth-member-access-v87.jsonl'
        require(not member_ledger.exists() and not member_ledger.is_symlink(),'audit_transfer_members_already_reserved')
        value['sources'].append({
            'name':item['name'],'role':POLICY['source_roles'][item['name']],
            'archive_sha256':receipt['local_sha256'],'acquisition_receipt_sha256':sha(receipt_path),
            'publisher_record':receipt['asset']['record_id'],'license_id':receipt['asset']['license_id'],
            'metadata_source':f"https://zenodo.org/records/{receipt['asset']['record_id']}",
            'simulation_start':item['simulation_start'],'simulation_end':item['simulation_end'],
            'prior_selected_manifest_sha256':sha(original_path),
            'prior_global_access_sha256':sha(global_access),'prior_global_access':decode(global_access.read_bytes()),
            'selected':selected,'excluded_unpaired':excluded,'archive_already_partly_exposed':True,
            'selected_member_bodies_opened_in_this_run':0,'selected_label_bodies_opened_in_this_run':0,
        })
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(canonical(value)+b'\n')
    return {'freeze_sha256':sha(output),'sources':len(value['sources'])}


def check_freeze(path,expected_hash):
    require(sha(path) == expected_hash,'audit_transfer_freeze_hash')
    value = decode(Path(path).read_bytes())
    check_original_role(ROOT)
    require(value['schema'] == 'audit-auth-member-transfer-freeze-1' and canonical(value['policy']) == canonical(POLICY)
            and value['goal_qualified'] is False and value['source_pins'] == source_pins(ROOT),
            'audit_transfer_candidate_changed')
    for spec in [*value['models'].values(),value['operation_policy']]:
        require(sha(ROOT/spec['path']) == spec['sha256'],'audit_transfer_model_changed')
    return value


def source_spec(value,name):
    matches = [s for s in value['sources'] if s['name'] == name]
    require(len(matches) == 1,'audit_transfer_source_name')
    return matches[0]


def validate_raw(audit,spec,freeze_hash):
    require(audit['completed'] is True and audit['candidate_freeze_sha256'] == freeze_hash
            and audit['archive_sha256'] == spec['archive_sha256'] and audit['label_bodies_opened'] == 0
            and len(audit['pairs']) == len(spec['selected']), 'audit_transfer_raw_contract')
    for pair,selected in zip(audit['pairs'],spec['selected'],strict=True):
        provenance = pair['provenance']
        require(all(provenance.get(k) == v for k,v in selected.items())
                and provenance['simulation_start'] == spec['simulation_start']
                and provenance['simulation_end'] == spec['simulation_end']
                and provenance['archive_sha256'] == spec['archive_sha256']
                and provenance['source_timezone'] == 'UTC' and provenance['label_body_opened'] is False
                and type(pair['raw_rows']) is int and 1 <= pair['raw_rows'] <= POLICY['maximum_source_rows'],
                'audit_transfer_selected_pair_changed')
    require(audit['population'] == sum(p['raw_rows'] for p in audit['pairs'])
            and audit['population'] <= POLICY['maximum_total_rows'], 'audit_transfer_raw_population')


def prepare(archive,freeze_path,freeze_hash,name,output):
    value = check_freeze(freeze_path,freeze_hash)
    spec = source_spec(value,name)
    archive,output = Path(archive),Path(output)
    require(sha(archive) == spec['archive_sha256'],'audit_transfer_archive_hash')
    check_prior_access(spec,archive.parent/'evaluation-access.json')
    require(not output.exists() and not output.is_symlink(),'audit_transfer_fresh_raw')
    book = MemberAccessLedger(archive.parent/'audit-auth-member-access-v87.jsonl',header_for(spec,freeze_hash))
    output.mkdir(parents=True)
    report = {'schema':'f1-frozen-transfer-raw-intake-1','completed':False,
              'scope':POLICY['scope'],'candidate_freeze_sha256':freeze_hash,
              'archive_sha256':spec['archive_sha256'],'label_bodies_opened':0,
              'timestamp_basis':'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
              'bounds_source':spec['metadata_source'],'pairs':[],
              'excluded_unpaired':spec['excluded_unpaired'],'goal_qualified':False}
    hosts,total = {},0
    try:
        for index,pair in enumerate(spec['selected']):
            facts = pair['facts_member']
            if facts not in hosts:
                p = output/f'host-{len(hosts)}.metadata'
                copied = copy_member(archive,spec['archive_sha256'],facts,p,maximum_bytes=4*1024**2)
                hosts[facts] = {'sha256':copied['sha256'],'timezone':timezone(decode(p.read_bytes()))}
            book.append('raw',pair['raw_member'])
            raw_path = output/f'pair-{index}-raw.source'
            copied = copy_member(archive,spec['archive_sha256'],pair['raw_member'],raw_path,
                                 maximum_bytes=POLICY['maximum_source_bytes'])
            rows = 0
            with raw_path.open('rb') as stream:
                while body := stream.readline(MAX_ROW+1):
                    rows += 1
                    require(len(body) <= MAX_ROW and rows <= POLICY['maximum_source_rows'],'audit_transfer_raw_bound')
            total += rows
            require(rows > 0 and total <= POLICY['maximum_total_rows'],'audit_transfer_population_bound')
            provenance = {**pair,'raw_sha256':copied['sha256'],'archive_sha256':spec['archive_sha256'],
                          'simulation_start':spec['simulation_start'],'simulation_end':spec['simulation_end'],
                          'source_timezone':'UTC','label_body_opened':False,'publisher_trimmed_pair':True,
                          'timezone_metadata':hosts[facts]}
            report['pairs'].append({'pair_id':copied['sha256'],'raw_rows':rows,'provenance':provenance})
        check_freeze(freeze_path,freeze_hash)
        check_prior_access(spec,archive.parent/'evaluation-access.json')
        report.update(completed=True,population=total,member_ledger_sha256=sha(book.path))
    finally:
        (output/'audit.json').write_bytes(canonical(report)+b'\n')
    return report


def predict(freeze_path,freeze_hash,name,raw_directory,prepared_directory,output):
    value = check_freeze(freeze_path,freeze_hash)
    spec = source_spec(value,name)
    raw_directory,prepared_directory,output = map(Path,(raw_directory,prepared_directory,output))
    audit = decode((raw_directory/'audit.json').read_bytes())
    validate_raw(audit,spec,freeze_hash)
    require(not list(raw_directory.glob('*labels.source')) and not (prepared_directory/'truth.jsonl').exists(),
            'audit_transfer_predict_label_files')
    preparation = decode((prepared_directory/'preparation.json').read_bytes())
    require(preparation['completed'] is True and preparation['labels_loaded'] is False
            and preparation['truth_sidecar_written'] is False
            and set(preparation['files']) == {'inputs.jsonl','references.jsonl'}
            and preparation['source_manifest_sha256'] == sha(raw_directory/'audit.json'),
            'audit_transfer_predict_preparation')
    require(not output.exists() and not output.is_symlink(),'audit_transfer_fresh_predictions')
    output.mkdir(parents=True)
    model = load_detector(ROOT,value['models'],value['operation_policy'])
    baseline = base_predict(prepared_directory,preparation,raw_directory,model,output/'v49-predictions.jsonl')
    audit_result = audit_predict(prepared_directory,preparation,raw_directory,output/'v49-predictions.jsonl',
                                 baseline['predictions_sha256'],output/'v67-predictions.jsonl')
    noop = noop_predict(preparation,raw_directory,output/'v67-predictions.jsonl',audit_result['predictions_sha256'],
                        output/'v85-predictions.jsonl')
    paired = pair_predictions(output/'v67-predictions.jsonl',output/'v85-predictions.jsonl',
                               audit_result['predictions_sha256'],noop['predictions_sha256'],output/'predictions.jsonl')
    require(all(s['population'] == audit['population'] for s in (baseline,audit_result,noop,paired)),
            'audit_transfer_prediction_population')
    check_freeze(freeze_path,freeze_hash)
    seal = {**paired,'schema':'audit-auth-member-prediction-seal-1','phase':'predictions_sealed',
            'candidate_freeze_sha256':freeze_hash,'raw_manifest_sha256':sha(raw_directory/'audit.json'),
            'preparation_sha256':sha(prepared_directory/'preparation.json'),
            'stages':{'v49':baseline,'v67':audit_result,'v85':noop},
            'labels_opened':False,'goal_qualified':False,'automatic_enforcement_allowed':False,
            'archive_already_partly_exposed':True,'original_role':spec['role']}
    (output/'prediction-manifest.json').write_bytes(canonical(seal)+b'\n')
    return seal


def score_packet(archive,freeze_path,freeze_hash,name,raw_directory,prediction_directory,manifest_hash,output):
    value = check_freeze(freeze_path,freeze_hash)
    spec = source_spec(value,name)
    archive,raw_directory,prediction_directory,output = map(Path,(archive,raw_directory,prediction_directory,output))
    manifest_path = prediction_directory/'prediction-manifest.json'
    require(sha(manifest_path) == manifest_hash,'audit_transfer_prediction_manifest_hash')
    sealed = decode(manifest_path.read_bytes())
    require(sealed['schema'] == 'audit-auth-member-prediction-seal-1' and sealed['phase'] == 'predictions_sealed'
            and sealed['candidate_freeze_sha256'] == freeze_hash and sealed['labels_opened'] is False
            and sha(prediction_directory/'predictions.jsonl') == sealed['predictions_sha256'],
            'audit_transfer_unsealed_prediction')
    audit_path = raw_directory/'audit.json'
    require(sha(audit_path) == sealed['raw_manifest_sha256'],'audit_transfer_raw_manifest_changed')
    audit = decode(audit_path.read_bytes())
    validate_raw(audit,spec,freeze_hash)
    require(set(sealed['stages']) == {'v49','v67','v85'}
            and sealed['population'] == audit['population'],'audit_transfer_sealed_stage_coverage')
    check_prior_access(spec,archive.parent/'evaluation-access.json')
    require(not output.exists() and not output.is_symlink(),'audit_transfer_fresh_score')
    book = MemberAccessLedger(archive.parent/'audit-auth-member-access-v87.jsonl',header_for(spec,freeze_hash))
    book.append('sealed','prediction-manifest.json',manifest_hash)
    output.mkdir(parents=True)
    fingerprints = []
    with (output/'truth.jsonl').open('xb') as target:
        for index,pair in enumerate(audit['pairs']):
            provenance = pair['provenance']
            pair_members(provenance['raw_member'],provenance['label_member'])
            book.append('label',provenance['label_member'],manifest_hash)
            label_path = output/f'pair-{index}-labels.source'
            copied = copy_member(archive,spec['archive_sha256'],provenance['label_member'],label_path,
                                 maximum_bytes=POLICY['maximum_source_bytes'])
            labels,_ = annotations(label_path,copied['sha256'])
            require(not labels or max(labels) <= pair['raw_rows'],'audit_transfer_labels_outside_population')
            for ordinal in range(1,pair['raw_rows']+1):
                case = hashlib.sha256((provenance['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                target.write(canonical({'case_id':case,'malicious':ordinal in labels,
                                        'attack_labels':labels.get(ordinal,())})+b'\n')
            fingerprints.append(copied)
    truth_hash = sha(output/'truth.jsonl')
    result = score(prediction_directory/'predictions.jsonl',output/'truth.jsonl',sealed['predictions_sha256'],truth_hash)
    stages = {}
    for stage,metadata in sealed['stages'].items():
        stages[stage] = score(prediction_directory/(stage+'-predictions.jsonl'),output/'truth.jsonl',
                              metadata['predictions_sha256'],truth_hash)
    for scored in [result,*stages.values()]:
        require(len(scored['per_source']) == len(audit['pairs']) and scored['population'] == audit['population'],
                'audit_transfer_score_population')
        for index,(row,pair) in enumerate(zip(scored['per_source'],audit['pairs'],strict=True)):
            require(row['source_index'] == index
                    and all(m['population'] == pair['raw_rows'] for m in row['metrics'].values()),
                    'audit_transfer_score_source_population')
    check_freeze(freeze_path,freeze_hash)
    check_prior_access(spec,archive.parent/'evaluation-access.json')
    result.update(completed=True,scope=POLICY['scope'],original_role=spec['role'],stages=stages,
                  original_six_domain_goal_replaced=False,archive_already_partly_exposed=True,
                  truth_sha256=truth_hash,member_ledger_sha256=sha(book.path),label_sources=fingerprints,
                  label_basis='publisher exact mirrored trimmed attack-related line labels; no independent human adjudication',
                  paid_api_calls=0,aws_calls=0)
    (output/'run.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    p = commands.add_parser('freeze')
    p.add_argument('--catalog',type=Path,required=True)
    p.add_argument('--catalog-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    for name in ('raw','features','predict','score'):
        p = commands.add_parser(name)
        if name != 'features':
            p.add_argument('--freeze',type=Path,required=True)
            p.add_argument('--freeze-sha256',required=True)
            p.add_argument('--source',choices=('wilson','wardbeck'),required=True)
        if name in {'raw','score'}:p.add_argument('--archive',type=Path,required=True)
        if name != 'raw':p.add_argument('--raw',type=Path,required=True)
        if name == 'features':p.add_argument('--raw-sha256',required=True)
        if name == 'predict':p.add_argument('--prepared',type=Path,required=True)
        if name == 'score':
            p.add_argument('--predictions',type=Path,required=True)
            p.add_argument('--manifest-sha256',required=True)
        p.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if args.command == 'freeze':result = freeze(args.catalog,args.catalog_sha256,args.output)
    elif args.command == 'raw':result = prepare(args.archive,args.freeze,args.freeze_sha256,args.source,args.output)
    elif args.command == 'features':result = prepare_features(args.raw,args.raw_sha256,args.output,include_truth=False)
    elif args.command == 'predict':result = predict(args.freeze,args.freeze_sha256,args.source,args.raw,args.prepared,args.output)
    else:result = score_packet(args.archive,args.freeze,args.freeze_sha256,args.source,args.raw,args.predictions,args.manifest_sha256,args.output)
    print(canonical({'completed':result.get('completed',True),'goal_qualified':False}).decode())


if __name__ == '__main__':
    main()
