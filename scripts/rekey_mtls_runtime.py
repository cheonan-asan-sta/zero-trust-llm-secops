"""Opt-in leaf private-key rotation on the persistent CA/monitoring graph."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from scripts import authority_runtime_assets as authority_assets
from scripts import rekey_runtime_assets as assets
from scripts import runtime_release as release
from scripts.authority_mtls_runtime import AuthorityRuntime
from scripts.authority_mtls_runtime import definition as authority_definition
from scripts.certificate_key_rotation import public_hash
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure
from scripts.monitored_mtls_runtime import INPUTS


def definition(project, image, nginx):
    spec = authority_definition(project, image, nginx)
    spec['services']['proxy']['entrypoint'] = ['sh', '/config/nginx-rekey.sh']
    for name in ('prometheus', 'alertmanager'):
        service = spec['services'][name]
        service['volumes'] = [v.replace(':/tls:ro', ':/service-tls:ro') for v in service['volumes']]
        original = service['entrypoint']
        child = original[original.index('--') + 1:]
        service['entrypoint'] = ['python', '-m', 'scripts.certificate_reload_runner', '--ack', '/reload/ack',
            '--resolve-tls', '--watch', '/service-tls/config.yml', '--watch', '/service-tls/web.yml', '--',
            *[v.replace('/tls/', '/service-tls/') for v in child]]
    return spec


class RekeyRuntime(AuthorityRuntime):
    def definition(self, project, image, nginx):
        return definition(project, image, nginx)

    def release_inputs(self):
        return release.capture(ROOT, definition('kmtls-000000000000', 'sha256:' + '0' * 64,
            'sha256:' + '1' * 64), (*INPUTS, *authority_assets.INPUTS, assets.INPUT))

    def build_material(self):
        return assets.material()

    def make_assets(self):
        material = super().make_assets()
        self.state['rekey_profile_identities'] = assets.profile_identities(material)
        self.state['rekey_signer_public_sha256'] = {name: public_hash(serialization.load_pem_private_key(
            material['renewal-tls']['sign-' + name + '.key'].encode(), password=None).public_key()) for name in authority_assets.SERVERS}
        self.state['authority_public_sha256']['config']['nginx-rekey.sh'] = hashlib.sha256(
            material['config']['nginx-rekey.sh'].encode()).hexdigest()
        self.save()
        return material

    def verify_monitoring_configuration(self):
        # Source templates remain immutable; only complete, journal-authorized
        # leaf pairs may change. Never re-seal a modified config on restart.
        request = {'templates': assets.templates(), 'profiles': self.state['rekey_profile_identities'],
                   'signers': self.state['rekey_signer_public_sha256'],
                   'initialized': bool(self.state.get('authority_initialized'))}
        try:
            result = json.loads(self.helper(['-m', 'scripts.rekey_runtime_control', 'verify'], json.dumps(request), readonly=True))
            if result != {'verified': True}:
                raise RuntimeFailure('rekey_configuration_drift')
        except (RuntimeFailure, ValueError, TypeError, KeyError):
            raise RuntimeFailure('rekey_configuration_drift') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('up', 'status', 'down'))
    parser.add_argument('--directory', type=Path, default=ROOT / 'runtime/c02/rekey-mtls')
    parser.add_argument('--purge', action='store_true')
    args = parser.parse_args()
    try:
        runtime = RekeyRuntime(args.directory)
        if args.mode == 'up':
            result = runtime.up()
        elif args.mode == 'status':
            runtime.load()
            result = runtime.status()
        else:
            result = runtime.down(purge=args.purge)
        print(json.dumps(result))
        return 0
    except (RuntimeFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'runtime': 'unavailable'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
