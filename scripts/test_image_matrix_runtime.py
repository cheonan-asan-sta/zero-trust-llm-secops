"""Build-only seven-image scan batch: one refreshed DB, offline scans, scoped cleanup.

Never starts the CA, PostgreSQL, NGINX, Lambda RIE, or application services.
All findings stay pending independent review. Raw outputs remain local.
"""

import argparse
import json
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts import compare_supply_chain as scan
from scripts import image_matrix as matrix
from scripts import runtime_release as release
from scripts.persistent_authority_runtime import PersistentAuthorityRuntime
from scripts.recheck_supply_chain import prepare
from scripts.review_supply_chain import ReviewError, require
from scripts.test_current_supply_chain_runtime import (
    HISTORY,
    HISTORY_SHA256,
    original_database_hashes,
)

OS_PROBE = r'''set -eu
cat /etc/os-release
printf '\nC03_MANAGER\n'
if command -v dpkg-query >/dev/null; then
 printf 'deb\nC03_PACKAGES\n'
 dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Status}\n'
elif command -v rpm >/dev/null; then
 printf 'rpm\nC03_PACKAGES\n'
 rpm -qa --qf '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{EPOCHNUM}\t%{ARCH}\n'
elif test -f /lib/apk/db/installed; then
 printf 'apk\nC03_PACKAGES\n'
 cat /lib/apk/db/installed
else exit 65; fi
'''


def parse_inventory(text, pypi):
    os_release, tail = text.split('\nC03_MANAGER\n', 1)
    manager, raw = tail.split('\nC03_PACKAGES\n', 1)
    rows = []
    if manager == 'apk':
        for stanza in raw.split('\n\n'):
            fields = {line[:1]: line[2:] for line in stanza.splitlines() if len(line) > 2 and line[1] == ':'}
            if fields:
                require('P' in fields and 'V' in fields, 'matrix_apk_record')
                rows.append({'name': fields['P'], 'version': fields['V'], 'architecture': fields.get('A')})
    else:
        require(manager in {'deb', 'rpm'}, 'matrix_package_manager')
        for line in raw.splitlines():
            fields = line.split('\t')
            if manager == 'deb':
                name, version, state = fields
                if state == 'installed':
                    rows.append({'name': name, 'version': version})
            else:
                name, version, release_part, epoch, architecture = fields
                rows.append({'name': name, 'version': matrix.epoch_version(version, release_part, epoch),
                             'architecture': architecture, 'epoch': epoch})
    result = {'schema': 'c03-installed-packages-1', 'os_release': os_release,
              'manager': manager, 'packages': rows, 'pypi': pypi}
    matrix.installed_inventory(result)
    return result


class Batch:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        allowed = (scan.ROOT/'runtime/c03').resolve()
        require(self.directory.is_relative_to(allowed) and self.directory != allowed
                and not self.directory.exists(), 'matrix_fresh_directory')
        self.commit = scan.run(['git', 'rev-parse', 'HEAD']).strip()
        require(not scan.run(['git', 'status', '--porcelain', '--untracked-files=no']).strip(), 'matrix_dirty_source')
        self.source = matrix.manifest()
        self.directory.mkdir(parents=True)
        self.scanner = scan.Pilot(self.directory/'_scanner', self.commit, 3, scratch_mib=1536)
        self.scanner.directory.mkdir()
        self.label = self.scanner.ident
        self.probes, self.pilots = [], []
        self.report = {'schema': 'c03-seven-image-local-batch-1', 'completed': False,
            'started_at': datetime.now(UTC).isoformat(), 'source_commit': self.commit,
            'source_dirty': False, 'source_lf_or_raw_sha256': self.source, 'label': self.label,
            'images': {}, 'aws_calls': 0, 'paid_llm_calls': 0,
            'archive_retention': 'One temporary tar per image; hash recorded, tar removed after validated review. Input images and raw scans retained.'}
        self.save()

    def save(self):
        (self.directory/'verification.json').write_text(json.dumps(self.report, indent=2)+'\n', encoding='utf-8')

    def unchanged(self):
        require(matrix.manifest() == self.source and scan.run(['git', 'rev-parse', 'HEAD']).strip() == self.commit,
                'matrix_source_changed')

    def probe(self, image, args, *, entrypoint='python', payload=None, scratch_mib=64):
        name = self.label+'-probe-'+uuid.uuid4().hex[:10]
        self.probes.append(name)
        argv = ['docker', 'run', '--rm', '--name', name, '--label', 'secops.c03='+self.label,
            '--network', 'none', '--read-only', '--user', '10001:10001', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--cpus=2', '--memory=2g', '--memory-swap=2g',
            '--pids-limit=128', '--tmpfs', f'/tmp:rw,nosuid,nodev,size={scratch_mib}m,uid=10001,gid=10001',
            '--tmpfs', '/data:rw,nosuid,nodev,size=1m,uid=10001,gid=10001', '--entrypoint', entrypoint]
        if payload is not None:
            argv.append('-i')
        result = subprocess.run([*argv, image, *args], input=payload, text=True, encoding='utf-8',
                                capture_output=True, timeout=180, check=False)
        require(result.returncode == 0, 'matrix_probe_failed')
        return result

    def build_images(self):
        app = self.label+'-app'
        print(json.dumps({'stage': 'build-seven-images', 'source': self.commit}), flush=True)
        scan.run(['docker', 'build', '--platform', 'linux/amd64', '-t', app, '.'])
        runtime = PersistentAuthorityRuntime(scan.ROOT/'runtime/c02'/self.label)
        require(not runtime.directory.exists(), 'matrix_build_directory_exists')
        runtime.directory.mkdir(parents=True)
        runtime.state = {'image': app, 'image_id': scan.run(['docker', 'image', 'inspect', app, '--format', '{{.Id}}']).strip(),
                         'project': self.label}
        runtime.prepare_extra_images()  # No up(), make_assets(), keys, enrollment or service initialization.
        self.build = runtime.state
        nginx = release.capture(scan.ROOT, {})['payload']['nginx_reference']
        scan.run(['docker', 'pull', '--platform', 'linux/amd64', nginx])
        detail = json.loads(scan.run(['docker', 'image', 'inspect', nginx]))[0]
        release.image_identity(detail, reference=nginx)
        images = {'application': app, 'monitoring': self.build['monitoring_image'],
            'authority': self.build['authority_image'], 'database': self.build['authority_database_image'], 'nginx': nginx}
        for name, recipe in [('lambda', 'Dockerfile.lambda'), ('tests', 'Dockerfile.test')]:
            tag = self.label+'-'+name
            scan.run(['docker', 'build', '--platform', 'linux/amd64', '-f', recipe, '-t', tag, '.'])
            images[name] = tag
        self.report['build'] = self.build
        self.report['input_images'] = images
        self.save()
        return images

    def image_proof(self, profile, image):
        detail = json.loads(scan.run(['docker', 'image', 'inspect', image]))[0]
        identity = release.image_identity(detail)
        proof = {'schema': 'c03-matrix-image-proof-1', 'profile': profile, 'image_id': identity,
            'source_commit': self.commit, 'platform': 'linux/amd64', 'source_lf_or_raw_sha256': self.source,
            'image_identity_verified': True, 'build_binding_verified': True, 'payload_sha256': {},
            'proof_kind': 'Trusted local Docker build/source/parent inspection; not remote attestation'}
        if profile in matrix.PYTHON_PROFILES:
            paths = matrix.payload_paths(profile, self.source)
            inputs = {n: {'path': p, 'lf': matrix.text_input(n.removeprefix('installed-runtime:'))} for n, p in paths.items()}
            program = """import hashlib,json,sys
from pathlib import Path
v=json.load(sys.stdin);result={}
for name,item in v.items():
 data=Path(item['path']).read_bytes()
 result[name]=hashlib.sha256(data.replace(b'\\r\\n',b'\\n') if item['lf'] else data).hexdigest()
print(json.dumps(result))
"""
            proof['payload_sha256'] = json.loads(self.probe(identity, ['-c', program], payload=json.dumps(inputs)).stdout)
            proof['runtime_security_report'] = json.loads(self.probe(identity,
                ['/opt/secops-runtime/install/verify_security.py', '--require-patched']).stdout)
        if profile in {'monitoring', 'authority'}:
            binaries = dict(self.build['monitoring_binary_sha256'])
            if profile == 'authority':
                binaries.update(self.build['authority_binary_sha256'])
            program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path('/tools')/n).read_bytes()).hexdigest() for n in json.load(sys.stdin)}))"
            actual = json.loads(self.probe(identity, ['-c', program], payload=json.dumps(list(binaries))).stdout)
            require(actual == binaries, 'matrix_tool_binary_drift')
            proof.update(binary_sha256=actual, binary_payload_verified=True)
        if profile in {'database', 'nginx'}:
            lock_path = 'infra/mtls/ca-ha-tools.lock.json' if profile == 'database' else 'infra/pep/tools.lock.json'
            lock = json.loads((scan.ROOT/lock_path).read_text('utf-8'))
            reference = lock['postgres']['image'] if profile == 'database' else lock['tools']['nginx']['image']
            canonical = reference
            if profile == 'database':
                repo, digest = reference.rsplit('@', 1)
                canonical = repo.rsplit(':', 1)[0]+'@'+digest
            base = json.loads(scan.run(['docker', 'image', 'inspect', reference]))[0]
            release.image_identity(base, reference=canonical)
            require(detail['RootFS']['Layers'][:len(base['RootFS']['Layers'])] == base['RootFS']['Layers'],
                    'matrix_upstream_layers')
            binary = 'postgres' if profile == 'database' else 'nginx'
            result = self.probe(identity, ['--version'] if profile == 'database' else ['-v'], entrypoint=binary)
            observed = result.stdout+result.stderr
            version = lock['postgres']['observed_version'].split('-')[0] if profile == 'database' else lock['tools']['nginx']['version']
            require(re.search(r'(?<![\d.])'+re.escape(version)+r'(?![\d.])', observed) is not None,
                    'matrix_upstream_binary_version')
            proof.update(upstream_reference=reference, upstream_image_id=base['Id'],
                         binary_version_verified=True, binary_version=observed.strip())
        matrix.verify_proof(proof, self.source)
        return proof

    def image_input(self, pilot, profile, image, proof):
        detail = json.loads(scan.run(['docker', 'image', 'inspect', image]))[0]
        require(release.image_identity(detail) == proof['image_id'], 'matrix_export_image_changed')
        require(detail['Size'] < 1400*1024**2, 'matrix_image_exceeds_scratch_budget')
        require(shutil.disk_usage(self.directory).free > detail['Size']+512*1024**2, 'matrix_export_disk_budget')
        os_metadata = self.probe(proof['image_id'], ['-c', OS_PROBE], entrypoint='sh').stdout
        pypi = []
        if profile in matrix.PYTHON_PROFILES:
            pypi = json.loads(self.probe(proof['image_id'], ['-c',
                "import importlib.metadata,json;print(json.dumps([(d.metadata['Name'],d.version) for d in importlib.metadata.distributions()]))"]).stdout)
        inventory = parse_inventory(os_metadata, pypi)
        (pilot.directory/'out/installed.json').write_text(json.dumps(inventory), encoding='utf-8')
        for version in ('2.31.0', '2.32.0'):
            (pilot.directory/f'input/requests-{version}.json').write_text(json.dumps(scan.control(version)), encoding='utf-8')
        pilot.report.update(app_image_id=proof['image_id'], image_uncompressed_bytes=detail['Size'],
            image_profile=profile, source_dirty=False, image_origin='Current build/pinned reference; no historical base replacement',
            build_recipe_override=None, database_mode='same_single_refreshed_snapshot')
        pilot.save()

    def cleanup(self):
        owners = [self.scanner, *self.pilots]
        identifiers = {self.label, *(p.ident for p in owners)}
        errors = []
        for ident in identifiers:
            for name in scan.run(['docker', 'ps', '-aq', '--filter', 'label=secops.c03='+ident]).split():
                detail = json.loads(scan.run(['docker', 'inspect', name]))[0]
                require(detail['Config']['Labels'].get('secops.c03') == ident, 'matrix_cleanup_container_owner')
                scan.run(['docker', 'rm', '--force', '--volumes', name])
        info = subprocess.run(['docker', 'volume', 'inspect', self.scanner.cache_volume], capture_output=True,
                              text=True, encoding='utf-8', check=False)
        if info.returncode == 0:
            require(json.loads(info.stdout)[0]['Labels'].get('secops.c03') == self.label, 'matrix_cleanup_volume_owner')
            scan.run(['docker', 'volume', 'rm', self.scanner.cache_volume])
        subprocess.run(['docker', 'image', 'rm', self.scanner.runner_image], capture_output=True, check=False)
        remaining = []
        for ident in identifiers:
            for args in (['ps', '-aq'], ['volume', 'ls', '-q'], ['network', 'ls', '-q']):
                remaining.extend(scan.run(['docker', *args, '--filter', 'label=secops.c03='+ident]).split())
        if remaining:
            errors.append('matrix_owned_resources_remain')
        return {'owned_resources_remaining': len(remaining), 'errors': errors}

    def run(self):
        history_path = scan.ROOT/HISTORY
        require(release.file_digest(history_path) == HISTORY_SHA256, 'matrix_history_pin')
        history = json.loads(history_path.read_text('utf-8'))
        original = history['cache_volume']
        try:
            require(original_database_hashes(original, self.label) == history['db_files_after'], 'matrix_original_db_drift')
            images = self.build_images()
            prepared = {}
            # Check every target's source, runtime and OS metadata before any
            # DB download or expensive repeated scan. Failures stay reviewable.
            for profile in matrix.PROFILES:
                self.unchanged()
                print(json.dumps({'image': profile, 'stage': 'preflight'}), flush=True)
                proof = self.image_proof(profile, images[profile])
                pilot = scan.Pilot(self.directory/profile, self.commit, 3, scratch_mib=1536)
                self.pilots.append(pilot)
                for name in ('input', 'out'):
                    (pilot.directory/name).mkdir(parents=True)
                pilot.runner_image, pilot.cache_volume = self.scanner.runner_image, self.scanner.cache_volume
                pilot.report.update(cache_volume=pilot.cache_volume, source_input_sha256=self.source)
                self.image_input(pilot, profile, images[profile], proof)
                (pilot.directory/'proof.json').write_text(json.dumps(proof, indent=2)+'\n', encoding='utf-8')
                prepared[profile] = (pilot, proof)
            self.report['preflight_completed'] = True
            self.save()
            prepare(self.scanner, history_path)
            self.scanner.container('grype-db-update', ['/tools/grype', 'db', 'update'], network=True)
            self.scanner.container('trivy-db-update', ['/tools/trivy', 'image', '--download-db-only', '--no-progress'], network=True)
            frozen = self.scanner.database_hashes('frozen')
            self.report['database_files'] = frozen
            reviews = {}
            for profile in matrix.PROFILES:
                self.unchanged()
                print(json.dumps({'image': profile, 'stage': 'scan'}), flush=True)
                pilot, proof = prepared[profile]
                pilot.report.update(cache_volume=pilot.cache_volume, shared_scanner_image_id=self.scanner.report['runner_image_id'],
                    runner_image_id=self.scanner.report['runner_image_id'],
                    source_input_sha256=self.source, tools=self.scanner.report['tools'])
                archive = pilot.directory/'input/app.tar'
                require(shutil.disk_usage(self.directory).free > pilot.report['image_uncompressed_bytes']+512*1024**2,
                        'matrix_export_disk_budget')
                scan.run(['docker', 'save', '-o', str(archive), proof['image_id']])
                pilot.report['image_archive_sha256'] = scan.sha256(archive)
                pilot.report['scan_started_at'] = datetime.now(UTC).isoformat()
                pilot.scan(initialize_db=False, trivy_timeout='15m')
                require(pilot.report['db_files'] == pilot.report['db_files_after'] == frozen, 'matrix_shared_db_changed')
                pilot.report.update(completed=True, finished_at=datetime.now(UTC).isoformat())
                pilot.save()
                scan.summarize(pilot.directory, installed_reader=matrix.installed_inventory, inventory_readers=matrix.READERS)
                summary = pilot.directory/'summary.json'
                review = matrix.review(summary, pilot.directory/'out', scan.sha256(summary), proof, self.source)
                for name, value in [('proof', proof), ('review', review)]:
                    (pilot.directory/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
                reviews[profile] = review
                self.report['images'][profile] = {'image_id': proof['image_id'], 'counts': review['counts'],
                    'summary_sha256': scan.sha256(summary), 'review_sha256': scan.sha256(pilot.directory/'review.json')}
                require(scan.sha256(archive) == pilot.report['image_archive_sha256'], 'matrix_archive_changed')
                archive.unlink()  # Validated own temporary file, never input images or historical artifacts.
                self.save()
            self.report['cohort'] = matrix.cohort(reviews)
            require(self.scanner.database_hashes('finished') == frozen, 'matrix_final_db_drift')
            require(all(r['container_exit'] == r['metrics'].get('exit_code') == 0
                        and r['network'] == ('bridge' if r['label'] in {'grype-db-update','trivy-db-update'} else 'none')
                        for r in self.scanner.report['runs']), 'matrix_bootstrap_failed')
            self.scanner.report['results'] = {'raw_artifacts': {
                str(p.relative_to(self.scanner.directory)): {'sha256': scan.sha256(p), 'bytes': p.stat().st_size}
                for p in (self.scanner.directory/'out').iterdir() if p.is_file()}}
            self.scanner.save()
            self.report['database_bootstrap_summary_sha256'] = scan.sha256(self.scanner.directory/'summary.json')
            require(original_database_hashes(original, self.label) == history['db_files_after'], 'matrix_original_db_changed')
            self.report['original_database_unchanged'] = True
            self.unchanged()
            self.report['completed'] = True
        except Exception as exc:
            self.report['failure'] = str(exc) if isinstance(exc, ReviewError) else type(exc).__name__
            raise
        finally:
            try:
                self.report['cleanup'] = self.cleanup()
                if self.report['cleanup']['owned_resources_remaining'] or self.report['cleanup']['errors']:
                    self.report['completed'] = False
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                self.report.update(completed=False, cleanup_failure=type(exc).__name__)
            self.report['finished_at'] = datetime.now(UTC).isoformat()
            self.save()
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    result = Batch(args.directory).run()
    print(json.dumps({k: result[k] for k in ('completed', 'images', 'cleanup')}))
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
