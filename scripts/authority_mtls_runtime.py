"""Opt-in local step-ca issuance/renewal for the persistent C01 mTLS profile."""

import argparse
import copy
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

from scripts import authority_runtime_assets as assets
from scripts import certificate_authority as authority
from scripts import runtime_release as release
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure, command
from scripts.monitored_mtls_runtime import INPUTS, MonitoredRuntime
from scripts.monitored_mtls_runtime import definition as monitored_definition

EXTRA_VOLUMES = ('ca-state', 'certificate-state', 'renewal-tls', *('ack-' + name for name in assets.RELOADS))


def definition(project, image, nginx):
    spec = monitored_definition(project, image, nginx)
    spec['volumes'].update({name: {'external': True, 'name': project + '-' + name} for name in EXTRA_VOLUMES})
    spec['networks']['ca'] = {'internal': True, 'labels': {'secops.runtime': project}}
    for name, identities in assets.RELOADS.items():
        service = spec['services'][name]
        service['volumes'].append(f'ack-{name}:/reload')
        if name == 'proxy':
            service['entrypoint'] = ['sh', '/config/nginx-renewal.sh']
        else:
            old = service['entrypoint']
            service['entrypoint'] = ['python', '-m', 'scripts.certificate_reload_runner', '--ack', '/reload/ack']
            for identity in identities:
                service['entrypoint'] += ['--watch', '/tls/' + identity + '.pem']
            service['entrypoint'] += ['--', *old]
    ca = copy.deepcopy(spec['services']['operator'])
    ca.update(image='sha256:' + '3' * 64, entrypoint=['python', '-m', 'scripts.authority_runtime_assets'],
              volumes=['ca-state:/ca'], networks={'ca': {'aliases': ['ca']}}, mem_limit='256m', memswap_limit='256m', cpus=1)
    controller = copy.deepcopy(ca)
    controller.update(entrypoint=['python', '-m', 'scripts.certificate_controller', 'run'],
        volumes=['certificate-state:/state', *[f'{name}:/managed/{name}' for name in assets.MANAGED],
                 *[f'ack-{name}:/ack/{name}:ro' for name in assets.RELOADS]],
        networks={name: {} for name in spec['networks']}, mem_limit='512m', memswap_limit='512m')
    spec['services'].update(ca=ca, **{'certificate-controller': controller})
    return spec


class AuthorityRuntime(MonitoredRuntime):
    services = MonitoredRuntime.services + ('ca', 'certificate-controller')
    volumes = MonitoredRuntime.volumes + EXTRA_VOLUMES

    def load(self):
        state = super().load()
        if state.get('authority_image', state['project'] + '-authority') != state['project'] + '-authority':
            raise ValueError('authority_image_scope')
        return state

    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition('kmtls-000000000000', 'sha256:' + '0' * 64,
                                                'sha256:' + '1' * 64), (*INPUTS, *assets.INPUTS))

    def expected_image(self, service):
        if service in {'ca', 'certificate-controller'}:
            return self.state.get('authority_image_id', 'sha256:' + '3' * 64)
        return super().expected_image(service)

    def prepare_extra_images(self):
        super().prepare_extra_images()
        from scripts.compare_supply_chain import download
        lock = json.loads((ROOT / assets.INPUTS[0]).read_text(encoding='utf-8'))
        if (lock['platform'] != 'linux/amd64' or len(lock['tools']) != 2
                or {tool['binary'] for tool in lock['tools']} != {'step', 'step-ca'}):
            raise ValueError('authority_tool_inventory')
        build = self.directory / 'authority-build'
        (build / 'bin').mkdir(parents=True)
        cache = ROOT / 'runtime/c02/c04/cache'
        cache.mkdir(parents=True, exist_ok=True)
        hashes = {}
        for tool in lock['tools']:
            download(tool, tool['asset'], cache)
            with tarfile.open(cache / tool['asset']['name'], 'r:gz') as archive:
                matches = [m for m in archive if m.isfile() and m.name.rsplit('/', 1)[-1] == tool['binary']]
                if len(matches) != 1 or not 0 < matches[0].size < 200 * 1024**2:
                    raise ValueError('authority_binary_entry')
                body = archive.extractfile(matches[0]).read()
                (build / 'bin' / tool['binary']).write_bytes(body)
                hashes[tool['binary']] = hashlib.sha256(body).hexdigest()
        base = json.loads(command(['docker', 'image', 'inspect', self.state['monitoring_image']]))[0]
        release.image_identity(base, self.state['monitoring_image_id'])
        (build / 'Dockerfile').write_text(f"FROM {self.state['monitoring_image']}\nUSER 0\nCOPY bin /tools\nRUN chmod 0555 /tools/*\nUSER 10001:10001\nHEALTHCHECK NONE\n", encoding='utf-8')
        (build / '.dockerignore').write_text('*\n!Dockerfile\n!bin/\n!bin/*\n', encoding='utf-8')
        tag = self.state['project'] + '-authority'
        command(['docker', 'build', '--tag', tag, str(build)], timeout=900)
        detail = json.loads(command(['docker', 'image', 'inspect', tag]))[0]
        layers = base['RootFS']['Layers']
        if not layers or detail['RootFS']['Layers'][:len(layers)] != layers:
            raise RuntimeFailure('authority_base_layers_changed')
        self.state.update(authority_image=tag, authority_image_id=release.image_identity(detail),
                          authority_binary_sha256=hashes, authority_tools=lock,
                          authority_base_layers_sha256=release.digest(layers))
        self.save()

    def build_material(self):
        return assets.material()

    def make_assets(self):
        material, self._bootstrap_provisioners = self.build_material()
        cfg = json.loads(material['certificate-state']['config.json'])
        self.state['authority_configuration_sha256'] = release.digest(assets.fixed_configuration(cfg))
        self.state['authority_public_sha256'] = {volume: {name: release.file_digest(ROOT / assets.INPUTS[1])
            if name == 'nginx-renewal.sh' else hashlib.sha256(material[volume][name].encode()).hexdigest()
            for name in names} for volume, names in {
                'ca-state': ('ca.json', 'root.pem', 'issuer.pem'),
                'certificate-state': ('root.pem', 'issuer.pem'), 'config': ('nginx-renewal.sh',)}.items()}
        self.state['monitoring_config_sha256'] = {volume: {name: hashlib.sha256(body.encode()).hexdigest()
            for name, body in material[volume].items() if name.endswith(('.yaml', '.yml'))}
            for volume in ('prometheus-tls', 'alertmanager-tls')}
        self.save()
        return material

    def helper_mounts(self):
        return ['certificate-state:/state', *[f'{name}:/managed/{name}' for name in assets.MANAGED],
                *[f'ack-{name}:/ack/{name}:ro' for name in assets.RELOADS]]

    def helper(self, program, payload=None, *, network='none', timeout=60, readonly=False):
        mounts = self.helper_mounts()
        argv = ['docker', 'run', '--rm', '--network', network, '--read-only', '--user', '10001:10001',
                '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--memory', '256m', '--cpus', '1',
                '--tmpfs', '/data:size=1m']
        for mount in mounts:
            volume, target, *options = mount.split(':')
            argv += ['--mount', f"type=volume,src={self.state['volumes'][volume]},dst={target}" + (',readonly' if options or readonly else '')]
        return command([*argv, '--entrypoint', 'python', '-i', self.state['authority_image_id'], *program],
                       payload=payload, timeout=timeout)

    def controller_status(self):
        return json.loads(self.execute('certificate-controller', ['python', '-m', 'scripts.certificate_controller', 'rpc'],
                                      json.dumps({'operation': 'status'})))

    def controller_configuration(self):
        return json.loads(self.helper(['-c', "from pathlib import Path;print(Path('/state/config.json').read_text())"]))

    def authority_health(self):
        return json.loads(self.execute('ca', ['python', '-c',
            'import json;from scripts.authority_runtime_assets import ca_health;print(json.dumps(ca_health()))'], timeout=5))

    def verify_extra_images(self):
        super().verify_extra_images()
        release.image_identity(json.loads(command(['docker', 'image', 'inspect', self.state['authority_image']]))[0],
                               self.state['authority_image_id'])
        program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path('/tools')/n).read_bytes()).hexdigest() for n in json.load(sys.stdin)}))"
        actual = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--tmpfs', '/data:size=1m',
            '--entrypoint', 'python', '-i', self.state['authority_image_id'], '-c', program], payload=json.dumps(list(self.state['authority_binary_sha256']))))
        if actual != self.state['authority_binary_sha256']:
            raise RuntimeFailure('authority_binary_drift')
        self.verify_authority_configuration()
        self.verify_authority_public_assets()
        self.verify_authority_database()

    def verify_authority_configuration(self):
        cfg = self.controller_configuration()
        if (not assets.configuration_valid(cfg)
                or release.digest(assets.fixed_configuration(cfg)) != self.state['authority_configuration_sha256']):
            raise RuntimeFailure('authority_configuration_drift')

    def verify_authority_public_assets(self):
        for volume, expected in self.state['authority_public_sha256'].items():
            program = "import hashlib,json,sys;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path('/data')/n).read_bytes().replace(b'\\r\\n',b'\\n')).hexdigest() for n in json.load(sys.stdin)}))"
            actual = json.loads(command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp:size=1m',
                '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--mount',
                f"type=volume,src={self.state['volumes'][volume]},dst=/data,readonly", '--entrypoint', 'python', '-i',
                self.state['image_id'], '-c', program], payload=json.dumps(list(expected))))
            if actual != expected:
                raise RuntimeFailure('authority_public_configuration_drift')

    def verify_authority_database(self):
        if self.state.get('authority_initialized'):
            program = "from pathlib import Path;from scripts.authority_runtime_assets import require_existing_database;require_existing_database(Path('/ca'))"
            try:
                command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                    '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/data:size=1m',
                    '--mount', f"type=volume,src={self.state['volumes']['ca-state']},dst=/ca,readonly",
                    '--entrypoint', 'python', self.state['authority_image_id'], '-c', program])
            except RuntimeFailure:
                raise RuntimeFailure('authority_database_required') from None

    def before_start(self):
        if self.state.get('authority_initialized'):
            return
        if not getattr(self, '_bootstrap_provisioners', None):
            raise RuntimeFailure('authority_initialization_requires_new_approved_bootstrap')
        self.compose('up', '--detach', *[name for name in self.services if name != 'certificate-controller'], timeout=300)
        inventory = json.loads(self.helper(['-m', 'scripts.certificate_controller', 'init']))
        ready = {}

        def healthy():
            try:
                result = self.authority_health()
            except (RuntimeFailure, ValueError):
                return False
            if result.get('healthy') is True and type(result.get('server_time')) is int:
                ready.update(result)
                return True
            return False

        try:
            self.wait(healthy, timeout=30)
        except RuntimeFailure:
            raise RuntimeFailure('authority_health_unavailable') from None
        # step-ca rejects JWTs whose iat precedes its initialized authority.
        # Date comes from the authenticated CA, rather than a fixed sleep or a
        # disabled issued-at check. No grant exists before this barrier.
        self.state['authority_bootstrap_time'] = ready['server_time']
        self.save()
        grants = {}
        for uid, credential in inventory.items():
            entry, key = self._bootstrap_provisioners[credential['name'] + '-' + credential['purpose']]
            grants[uid] = {'token': authority.bootstrap_token(entry, key, credential['csr'], seconds=300,
                                                           now=ready['server_time']),
                           'duration': '1h' if credential['name'].startswith('renew-') else '20m'}
        self.write_volume('certificate-state', {'bootstrap.json': json.dumps(grants)})
        self._bootstrap_provisioners.clear()
        self.compose('up', '--detach', 'certificate-controller')
        self.wait(lambda: (s := self.controller_status())['phase'] is None
                  and all(c['generation'] >= 1 for c in s['credentials'].values()), timeout=180)
        self.after_enrollment()
        self.state['authority_initialized'] = True
        self.save()

    def after_enrollment(self):
        pass

    def down(self, *, purge=False):
        result = super().down(purge=purge)
        tag = self.state['project'] + '-authority'
        if purge and command(['docker', 'image', 'ls', '--quiet', tag]).strip():
            command(['docker', 'image', 'rm', tag])
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'status', 'down'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/authority-mtls')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        runtime = AuthorityRuntime(args.directory)
        if args.mode == 'up':
            result = runtime.up()
        elif args.mode == 'status':
            runtime.load()
            result = runtime.status() | {'certificates': runtime.controller_status()}
        else:
            result = runtime.down(purge=args.purge)
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'runtime': 'unavailable'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
