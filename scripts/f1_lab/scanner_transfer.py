"""Fixed Wardbeck calibration-source check; never redesignated as final holdout."""

from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.rotation_transfer import POLICY as PRIOR_POLICY
from scripts.f1_lab.rotation_transfer import check_freeze_with_policy, freeze_with_policy
from scripts.f1_lab.transfer_evaluation import sha

POLICY = {
    **PRIOR_POLICY,
    'schema': 'f1-scanner-calibration-transfer-1',
    'candidate_chain': [*PRIOR_POLICY['candidate_chain'], 'v62-scanner-read-review'],
    'source_id': 'ait-wardbeck', 'asset_id': 'ait-lds21-wardbeck-sealed',
    'filename': 'wardbeck_no-pcaps.zip', 'publisher_md5': '14eeacd83571a83615c2cce1f6a6eacf',
    'simulation_start': int(datetime(2022, 1, 19, tzinfo=UTC).timestamp()),
    'simulation_end': int(datetime(2022, 1, 24, tzinfo=UTC).timestamp()),
    'original_planned_role': 'calibration', 'redesignated_as_final_holdout': False,
    'comparison': 'v52 versus v62; earlier stages retained separately',
    'scope': 'prospective fixed-candidate check on an originally designated calibration source; shared simulated family',
}


def check_original_role(root):
    path = Path(root)/'infra/f1-lab/native-data-protocol.json'
    sha(path, 65536)  # Enforce the same bounded regular-file input contract.
    plan = decode(path.read_bytes())
    roles = plan.get('scenario_split_proposal')
    require(plan.get('schema_version') == 'f1-native-data-protocol-1'
            and plan.get('source_records', {}).get('raw_logs') == POLICY['metadata_source']
            and plan.get('original_six_domain_goal_replaced') is False
            and plan.get('full_six_domain_goal_eligible') is False
            and isinstance(roles, dict) and set(roles) == {'development', 'calibration', 'reserved_final'},
            'scanner_original_role_contract')
    require(all(isinstance(values, list) and len(values) <= 16
                and all(isinstance(name, str) for name in values) for values in roles.values())
            and roles['calibration'].count('wardbeck') == 1
            and all('wardbeck' not in roles[name] for name in ('development', 'reserved_final')),
            'scanner_original_role_changed')


def freeze(root, acquisition, archive, output):
    check_original_role(root)
    return freeze_with_policy(root, acquisition, archive, output, POLICY)


def check_freeze(root, path, expected_sha256):
    value = check_freeze_with_policy(root, path, expected_sha256, POLICY)
    check_original_role(root)
    return value
