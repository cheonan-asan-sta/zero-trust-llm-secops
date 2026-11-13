"""Post-seal overlap audit; never removes cases or supplies model-selection feedback."""

import argparse
import hashlib
import sqlite3
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import ROOT, check_freeze, observations, sha


def audit(root, freeze_path, freeze_hash, prediction_manifest, manifest_hash, prepared, development, output):
    frozen = check_freeze(root, freeze_path, freeze_hash)
    require(sha(prediction_manifest) == manifest_hash, 'overlap_prediction_seal')
    sealed = decode(Path(prediction_manifest).read_bytes())
    require(sealed['phase'] == 'predictions_sealed' and sealed['candidate_freeze_sha256'] == freeze_hash
            and sha(Path(prediction_manifest).parent/'predictions.jsonl') == sealed['predictions_sha256'],
            'overlap_predictions_required')
    output, prepared = Path(output), Path(prepared)
    require(not output.exists() and not output.is_symlink(), 'overlap_fresh_output')
    output.mkdir(parents=True)
    db = output/'overlap.sqlite3'
    connection = sqlite3.connect(db)
    try:
        connection.execute('PRAGMA max_page_count=262144')  # 1 GiB cap, never a population filter.
        connection.execute('PRAGMA cache_size=-16384')
        connection.execute('CREATE TABLE patterns (digest TEXT PRIMARY KEY) WITHOUT ROWID')
        counts, raw_sources = {}, set()
        for index, directory in enumerate(development):
            directory = Path(directory)
            preparation = decode((directory/'preparation.json').read_bytes())
            raw_sources.update(pair['raw_sha256'] for pair in preparation['pairs'])
            count = 0
            for _, row in observations(directory, preparation):
                if row['features'] is not None:
                    key = hashlib.sha256(canonical(row['features'])).hexdigest()
                    connection.execute('INSERT OR IGNORE INTO patterns VALUES (?)', (key,))
                count += 1
            connection.commit()
            counts[str(index)] = count
        preparation_path = prepared/'preparation.json'
        require(sha(preparation_path) == sealed['observations_manifest_sha256'], 'overlap_prepared_binding')
        preparation = decode(preparation_path.read_bytes())
        heldout, overlap, missing = 0, 0, 0
        for _, row in observations(prepared, preparation):
            heldout += 1
            if row['features'] is None:
                missing += 1
            else:
                key = hashlib.sha256(canonical(row['features'])).hexdigest()
                overlap += connection.execute('SELECT 1 FROM patterns WHERE digest=?', (key,)).fetchone() is not None
        require(heldout == sealed['population'], 'overlap_population_binding')
        result = {'schema': 'f1-postseal-overlap-audit-1', 'completed': True, 'source_id': frozen['source_id'],
            'candidate_freeze_sha256': freeze_hash, 'prediction_manifest_sha256': manifest_hash,
            'development_rows': counts, 'heldout_rows': heldout, 'feature_extraction_errors': missing,
            'rows_matching_development_feature_vector': overlap,
            'exact_raw_source_overlap': sorted(raw_sources & {p['raw_sha256'] for p in preparation['pairs']}),
            'rows_removed_from_evaluation': 0, 'labels_opened_by_audit': False,
            'subject_session_attack_family_independence_established': False,
            'interpretation': 'coarse feature equality is not proof of duplicate raw events; all cases retained',
            'goal_qualified': False, 'model_selection_feedback_allowed': False}
        check_freeze(root, freeze_path, freeze_hash)
        (output/'audit.json').write_bytes(canonical(result)+b'\n')
        return result
    finally:
        connection.close()
        require(db.parent == output and db.is_file() and not db.is_symlink(), 'overlap_owned_spool')
        db.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--prediction-manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--prepared-directory', type=Path, required=True)
    parser.add_argument('--development', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(canonical(audit(ROOT, args.freeze, args.freeze_sha256, args.prediction_manifest, args.manifest_sha256,
                          args.prepared_directory, args.development, args.output)).decode())


if __name__ == '__main__':
    main()
