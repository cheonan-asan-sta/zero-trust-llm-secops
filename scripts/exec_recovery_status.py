"""Recheck private proposed/completed execution artifacts without private keys."""

import argparse
import json
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.exec_recovery_inventory import inspect_recovery
from scripts.f1_lab.exec_recovery_status import publish, report
from scripts.f1_lab.service_caller_identity import PinnedCallerRegistry
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('tenant','server','unit','source','registry-sha256','caller-registry-sha256'):
        parser.add_argument('--'+name,required=True)
    for name in ('root','intents','registry','caller-registry','status-output'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--caller-environment',choices=('oidc','local_oidc'),default='oidc')
    parser.add_argument('--observe-worker-security',action='store_true')
    args=parser.parse_args()
    scope=ArchiveScope(tenant_id=args.tenant,server_id=args.server,unit=args.unit,source_id=args.source)
    try:
        values=inspect_recovery(args.intents,args.root,scope,
            PinnedServiceRegistry(args.registry,args.registry_sha256),
            PinnedCallerRegistry(args.caller_registry,args.caller_registry_sha256,
                                 expected_environment=args.caller_environment))
        value=report(scope,values)
    except (ValueError,OSError,sqlite3.Error,InvalidSignature):
        value=report(scope)
    publish(args.status_output,value)
    output={'state':value['state'],'automatic_execution_allowed':False}
    if args.observe_worker_security:
        from scripts.f1_lab.collector_security import current_security_status

        output['worker_security']=current_security_status()
    print(json.dumps(output))
    return 0 if value['state'] in {'ready','pending'} else 2


if __name__=='__main__':
    raise SystemExit(main())
