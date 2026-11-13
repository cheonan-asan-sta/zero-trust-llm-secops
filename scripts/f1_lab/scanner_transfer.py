"""Fixed Wardbeck calibration-source check; never redesignated as final holdout."""

from datetime import UTC, datetime

from scripts.f1_lab.rotation_transfer import POLICY as PRIOR_POLICY
from scripts.f1_lab.rotation_transfer import check_freeze_with_policy, freeze_with_policy

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


def freeze(root, acquisition, archive, output):
    return freeze_with_policy(root, acquisition, archive, output, POLICY)


def check_freeze(root, path, expected_sha256):
    return check_freeze_with_policy(root, path, expected_sha256, POLICY)
