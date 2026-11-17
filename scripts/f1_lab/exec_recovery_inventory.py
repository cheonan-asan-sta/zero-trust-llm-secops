"""Read-only bounded intent/seal/publication inventory, never authorization."""

import os
import re
import time
from datetime import UTC, datetime, timedelta
from itertools import islice

from scripts.f1_lab.capture_archive import MAX_BYTES, MAX_RECORDS, ArchiveScope
from scripts.f1_lab.capture_backup import private_directory, private_file
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE
from scripts.f1_lab.exec_intent import ExecutionIntent, verify_intent
from scripts.f1_lab.exec_outbox import cold_records, distinct, publication_states
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture, verify_managed
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.web_verified_context import Window


def intent_runs(directory):
    entries = []
    with os.scandir(directory) as stream:
        for ordinal,entry in enumerate(stream,1):
            require(ordinal <= MAX_RECORDS+1,'exec_recovery_inventory_bound')
            if entry.name == '.capture-store.lock':
                continue
            require(re.fullmatch('[a-f0-9]{32}',entry.name) and not entry.is_symlink()
                    and entry.is_dir(follow_symlinks=False),'exec_recovery_intent_inventory')
            entries.append(entry.name)
    require(len(entries) <= MAX_RECORDS,'exec_recovery_intent_capacity')
    return sorted(entries)


def inspect_recovery(intents,root,scope,service_pin,caller_pin,*,now=None):
    now = datetime.now(UTC) if now is None else now
    Window.aware(now)
    scope = ArchiveScope.model_validate(scope.model_dump())
    intents,root = private_directory(intents),private_directory(root)
    distinct(intents,root)
    with capture_store_lock(intents),capture_store_lock(root):
        start = time.monotonic()
        deadline = start+15
        service,caller = service_pin.current(now),caller_pin.current(now)
        cold = cold_records(root,scope)
        count=total=sealed=indeterminate=published=unpublished=0
        oldest_indeterminate=oldest_unpublished=None
        for rid in intent_runs(intents):
            require(time.monotonic() < deadline,'exec_recovery_inspection_deadline')
            run = private_directory(intents/rid)
            require({p.name for p in islice(run.iterdir(),3)} <= {'intent.json','capture.json'},
                    'exec_recovery_run_inventory')
            raw_intent = private_file(run/'intent.json',MAX_CAPTURE)
            intent = verify_intent(ExecutionIntent.model_validate(decode(raw_intent)),service_pin,caller_pin,now=now)
            require(intent.request.request_id == rid
                    and (intent.request.tenant_id,intent.request.server_id,intent.request.unit)
                    == (scope.tenant_id,scope.server_id,scope.unit),'exec_recovery_proposed_scope')
            count += 1
            total += len(raw_intent)
            target = run/'capture.json'
            if not target.exists() and not target.is_symlink():
                indeterminate += 1
                oldest_indeterminate = min(oldest_indeterminate,intent.created_at) if oldest_indeterminate else intent.created_at
            else:
                raw = private_file(target,MAX_CAPTURE)
                total += len(raw)
                capture = verify_managed(ManagedExecCapture.model_validate(decode(raw)),service_pin,caller_pin,now=now)
                require(capture.request == intent.request
                        and capture.runtime_proof.source_id == scope.source_id
                        and capture.caller_receipt.caller_ref_sha256 == intent.proposed_caller_ref_sha256
                        and capture.app_use.session_ref_sha256 == intent.session_ref_sha256
                        and (capture.app_use.resource_id,capture.app_use.action,capture.app_use.policy_sha256)
                        == (intent.resource_id,intent.action,intent.policy_sha256)
                        and intent.created_at <= capture.event.observed_at <= capture.sealed_at,
                        'exec_recovery_sealed_binding')
                sealed += 1
                done = publication_states(root,scope,[(rid,raw,capture)],cold=cold)[rid]
                published += int(done)
                unpublished += int(not done)
                if not done:
                    oldest_unpublished = min(oldest_unpublished,capture.sealed_at) if oldest_unpublished else capture.sealed_at
            require(total <= MAX_BYTES,'exec_recovery_total_bytes')
        checked_at = now+timedelta(seconds=max(0,time.monotonic()-start))
        require(time.monotonic() < deadline and service_pin.current(checked_at) == service
                and caller_pin.current(checked_at) == caller,'exec_recovery_current_pins_or_deadline')
        return {'intents':count,'raw_bytes':total,'sealed':sealed,'indeterminate':indeterminate,
                'published':published,'unpublished':unpublished,
                'oldest_indeterminate_at':oldest_indeterminate,'oldest_unpublished_at':oldest_unpublished}
