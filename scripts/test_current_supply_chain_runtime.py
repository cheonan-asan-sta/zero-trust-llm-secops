"""Current app/monitoring scan batch. Public DB downloads, then offline scans only.

No cloud deployment, model calls, services, detector tuning or finding suppression.
Use a fresh directory below runtime/c03. Preserve the historical DB and records.
"""

import argparse
import json
import re
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts import compare_supply_chain as scan
from scripts import runtime_release as release
from scripts.current_supply_chain import current_review, pair_reviews, source_manifest
from scripts.monitored_mtls_runtime import MonitoredRuntime
from scripts.recheck_supply_chain import inspect_image, prepare
from scripts.review_supply_chain import ReviewError, require

HISTORY = 'docs/infrastructure-results/c03-windows-20261103.json'
HISTORY_SHA256 = '4860aaeec2d02019afcef1c74b475fc67e2198e7f7dbdd71d2f25ce9bfcb932f'


def image_proof(image, manifest, commit, label):
    detail = json.loads(scan.run(['docker', 'image', 'inspect', image]))[0]
    release.image_identity(detail)
    payload = {p: v for p, v in manifest.items()
               if p.startswith(('app/', 'scripts/', 'infra/runtime/')) or p in {'README.md', 'pyproject.toml'}}
    program = """import hashlib,json,sys
from pathlib import Path
names=json.load(sys.stdin)
def path(name):
 return Path('/opt/secops-runtime/install')/name.removeprefix('infra/runtime/') if name.startswith('infra/runtime/') else Path('/app')/name
print(json.dumps({n:hashlib.sha256(path(n).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for n in names}))
"""
    args = ['docker', 'run', '--rm', '--label', 'secops.c03=' + label, '--network', 'none',
            '--read-only', '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,uid=10001,gid=10001',
            '--tmpfs', '/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001', '--entrypoint', 'python', '-i', image]
    result = subprocess.run([*args, '-c', program], input=json.dumps(list(payload)), text=True, encoding='utf-8',
                            capture_output=True, timeout=60, check=True)
    require(json.loads(result.stdout) == payload, 'current_image_payload_mismatch')
    runtime = json.loads(scan.run([*args[:-1], image, '/opt/secops-runtime/install/verify_security.py', '--require-patched']))
    require(runtime['passed'] is True and len(runtime['checks']) == 23
            and all(v is True for v in runtime['checks'].values()), 'current_runtime_checks')
    return {'schema': 'c03-current-image-proof-1', 'source_commit': commit, 'image_id': detail['Id'],
        'platform': 'linux/amd64', 'source_lf_sha256': manifest, 'image_payload_lf_sha256': payload,
        'runtime_security_checks': 23, 'runtime_security_passed': True, 'runtime_security_report': runtime,
        'proof_kind': 'trusted local Docker/source comparison; not remote attestation'}


def original_database_hashes(volume, label):
    require(re.fullmatch(r'c03-[a-f0-9]{12}-db', volume) is not None, 'original_db_name')
    code = """import hashlib,json
from pathlib import Path
root=Path('/original')
files=[p for p in root.rglob('*') if p.is_file() and ('grype' in p.parts or p.name in {'trivy.db','metadata.json'})]
result={}
for p in files:
 h=hashlib.sha256()
 with p.open('rb') as f:
  while block:=f.read(1048576): h.update(block)
 result[str(p.relative_to(root))]=h.hexdigest()
print(json.dumps(result))
"""
    return json.loads(scan.run(['docker', 'run', '--rm', '--label', 'secops.c03=' + label,
        '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop=ALL',
        '--security-opt=no-new-privileges:true', '--mount', f'type=volume,src={volume},dst=/original,readonly',
        '--entrypoint', 'python', scan.BASE, '-c', code]))


def build_images(directory, label):
    app = label + '-app'
    scan.run(['docker', 'build', '--platform', 'linux/amd64', '--tag', app, '.'])
    native = MonitoredRuntime(scan.ROOT / 'runtime/c02' / label)
    require(not native.directory.exists(), 'current_build_directory_exists')
    native.directory.mkdir(parents=True)
    native.state = {'image': app, 'image_id': scan.run(['docker', 'image', 'inspect', app, '--format', '{{.Id}}']).strip(),
                    'project': label}
    native.prepare_extra_images()  # Build only; never start a service or create service keys.
    state = native.state
    (directory / 'build.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    return {'application': app, 'monitoring': state['monitoring_image']}, state


def owned_cleanup(pilot):
    for name in pilot.containers:
        result = subprocess.run(['docker', 'inspect', name], text=True, encoding='utf-8', capture_output=True, check=False)
        if result.returncode == 0:
            detail = json.loads(result.stdout)[0]
            require(detail['Config']['Labels'].get('secops.c03') == pilot.ident
                    and detail['Name'] == '/' + name, 'current_cleanup_ownership')
    pilot.cleanup()


def execute(directory):
    directory = Path(directory).resolve()
    allowed = (scan.ROOT / 'runtime/c03').resolve()
    require(directory.is_relative_to(allowed) and directory != allowed and not directory.exists(),
            'current_fresh_directory_required')
    history_path = scan.ROOT / HISTORY
    require(release.file_digest(history_path) == HISTORY_SHA256, 'current_history_pin')
    history = json.loads(history_path.read_text('utf-8'))
    commit = scan.run(['git', 'rev-parse', 'HEAD']).strip()
    manifest = source_manifest()
    directory.mkdir(parents=True)
    label = 'c03-' + uuid.uuid4().hex[:12]
    report = {'schema': 'c03-current-local-batch-1', 'completed': False, 'started_at': datetime.now(UTC).isoformat(),
        'source_commit': commit, 'source_dirty': bool(scan.run(['git', 'status', '--porcelain', '--untracked-files=no']).strip()),
        'source_lf_sha256': manifest, 'label': label, 'images': {}, 'aws_calls': 0, 'model_calls': 0}
    pilots = []

    def save():
        (directory / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    save()
    original = history['cache_volume']
    try:
        require(original_database_hashes(original, label) == history['db_files_after'], 'original_database_drift')
        images, state = build_images(directory, label)
        report['monitoring_build'] = state
        reviews = {}
        previous = history_path
        for name, image in images.items():
            require(source_manifest() == manifest and scan.run(['git', 'rev-parse', 'HEAD']).strip() == commit,
                    'current_source_changed')
            proof = image_proof(image, manifest, commit, label)
            pilot = scan.Pilot(directory / name, commit, 3)
            pilot.directory.mkdir()
            pilot.app_image = pilot.ident + '-unused-input'
            pilots.append(pilot)
            pilot.report.update(source_input_sha256={p: scan.sha256(scan.ROOT / p) for p in manifest},
                source_dirty=report['source_dirty'], database_mode='refreshed_then_frozen' if name == 'application' else 'same_refreshed_snapshot')
            prepare(pilot, previous)
            inspect_image(pilot, image)
            if name == 'application':
                pilot.container('grype-db-update', ['/tools/grype', 'db', 'update'], network=True)
                pilot.container('trivy-db-update', ['/tools/trivy', 'image', '--download-db-only', '--no-progress'], network=True)
            pilot.report['scan_started_at'] = datetime.now(UTC).isoformat()
            pilot.scan(initialize_db=False, trivy_timeout='15m')
            pilot.report.update(completed=True, finished_at=datetime.now(UTC).isoformat())
            pilot.save()
            pilot.report = scan.summarize(pilot.directory)
            summary = pilot.directory / 'summary.json'
            review = current_review(summary, pilot.directory / 'out', scan.sha256(summary), proof, manifest)
            (pilot.directory / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
            (pilot.directory / 'review.json').write_text(json.dumps(review, indent=2) + '\n', encoding='utf-8')
            reviews[name] = review
            report['images'][name] = {'image_id': proof['image_id'], 'counts': review['counts'],
                'summary_sha256': scan.sha256(summary), 'review_sha256': scan.sha256(pilot.directory / 'review.json')}
            previous = summary
            save()
        report['pair'] = pair_reviews(reviews['application'], reviews['monitoring'])
        require(source_manifest() == manifest, 'current_source_changed')
        require(original_database_hashes(original, label) == history['db_files_after'], 'original_database_changed')
        report['original_database_unchanged'] = True
        report['completed'] = True
    except Exception as exc:
        report.update(completed=False, failure=str(exc) if isinstance(exc, ReviewError) else type(exc).__name__)
        raise
    finally:
        cleanup_errors = []
        for pilot in pilots:
            try:
                owned_cleanup(pilot)
                info = subprocess.run(['docker', 'volume', 'inspect', pilot.cache_volume], text=True,
                                      encoding='utf-8', capture_output=True, check=False)
                if info.returncode == 0:
                    require(json.loads(info.stdout)[0]['Labels'].get('secops.c03') == pilot.ident, 'current_db_cleanup_ownership')
                    scan.run(['docker', 'volume', 'rm', pilot.cache_volume])
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                cleanup_errors.append(type(exc).__name__)
        leftovers = []
        for ident in [label, *(p.ident for p in pilots)]:
            for argv in (['ps', '-aq'], ['volume', 'ls', '-q'], ['network', 'ls', '-q']):
                leftovers.extend(scan.run(['docker', *argv, '--filter', 'label=secops.c03=' + ident]).split())
        report['cleanup'] = {'owned_resources_remaining': len(leftovers)}
        if leftovers or cleanup_errors:
            report.update(completed=False, cleanup_errors=cleanup_errors)
            report.setdefault('failure', 'current_cleanup_incomplete')
        report['finished_at'] = datetime.now(UTC).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    report = execute(args.directory)
    print(json.dumps({'completed': report['completed'], 'images': report['images'], 'cleanup': report['cleanup']}))
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    main()
