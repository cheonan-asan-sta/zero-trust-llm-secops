"""Bounded read federation over independently verified local JSONL hash chains.

Writers retain their process-owned files. A partial append may temporarily reject
a read; it never turns a corrupt/missing shard into a silently incomplete result.
Previously announced/discovered files have durable local checkpoints.
This is not a global atomic snapshot or a shared transactional writer.
"""

from pathlib import Path

from app.models import AnalysisResult
from app.services.audit import AuditStore, _summarize
from app.services.audit_manifest import AuditManifestError, AuditShardManifest
from app.services.audit_wire import analysis_core_wire, analysis_wire
from app.services.settled_io import settled_io


class AuditQueryUnavailable(RuntimeError):
    pass


class FederatedAuditStore(AuditStore):
    MAX_FILES = 128
    MAX_BYTES = 128 * 1024 * 1024
    # Cross-file merge checks identities/revisions; it is not SQLite review CAS.
    _local_review_history = False

    def __init__(self, writer_path: Path, base_path: Path):
        self._base_path = base_path
        super().__init__(writer_path)
        self._manifest = AuditShardManifest(base_path.with_name(base_path.name + ".shards.sqlite3"))

    async def save(self, record):
        try:
            # A cancelled announcement must leave a valid empty file, not a
            # permanently registered-but-missing shard that poisons later reads.
            await settled_io(self._manifest.announce, self._path, self.MAX_FILES, ensure_file=True)
        except AuditManifestError as error:
            raise AuditQueryUnavailable("audit manifest registration failed") from error
        await super().save(record)

    def _paths(self):
        base = self._base_path
        paths = list(base.parent.glob(f"{base.stem}.worker-*{base.suffix}"))
        if base.exists():
            paths.append(base)
        if len(paths) > self.MAX_FILES:
            raise AuditQueryUnavailable("audit shard capacity exceeded")
        return sorted(paths)

    def _snapshot(self):
        with self._disk_lock:
            return self._snapshot_locked()

    def _snapshot_locked(self):
        try:
            if not self._integrity_ok:
                raise AuditQueryUnavailable("local audit writer integrity failed")
            paths = self._paths()
            total, verified, legacy = 0, 0, 0
            versions = {}
            signatures = {}
            for path in paths:
                if path.is_symlink() or not path.is_file():
                    raise AuditQueryUnavailable("audit shard is not a regular file")
                total += path.stat().st_size
                if total > self.MAX_BYTES:
                    raise AuditQueryUnavailable("audit read byte capacity exceeded")
                # AuditStore's compatibility reader suppresses an OS read error;
                # federation explicitly probes first and checks stat stability.
                before = path.stat()
                with path.open("rb") as stream:
                    stream.read(1)
                shard = AuditStore(path, strict_reads=True)
                after = path.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ino,
                ):
                    raise AuditQueryUnavailable("audit shard changed during verification; retry")
                signatures[path.name] = (after.st_size, after.st_mtime_ns, after.st_ino)
                info = shard.integrity()
                if not info["ok"]:
                    raise AuditQueryUnavailable("audit shard integrity failed")
                verified += info["verified_lines"]
                legacy += info["legacy_lines"]
                for record in shard._history:
                    previous = versions.get(record.analysis_id)
                    if previous is not None:
                        if analysis_core_wire(previous) != analysis_core_wire(record):
                            raise AuditQueryUnavailable(
                                "conflicting analysis identity across shards"
                            )
                        left = previous.review_updated_at or previous.analyzed_at
                        right = record.review_updated_at or record.analyzed_at
                        if left == right and analysis_wire(previous) != analysis_wire(record):
                            raise AuditQueryUnavailable("conflicting audit revisions")
                        if left >= right:
                            continue
                    versions[record.analysis_id] = record
            if paths != self._paths():
                raise AuditQueryUnavailable("audit shard membership changed; retry")
            self._manifest.checkpoint(paths, signatures, self.MAX_FILES)
            records = sorted(versions.values(), key=lambda r: (r.analyzed_at, r.analysis_id))
            return records, {
                "backend": "federated_jsonl_hash_chains",
                "ok": True,
                "shards": len(paths),
                "verified_lines": verified,
                "legacy_lines": legacy,
            }
        except (OSError, ValueError, AuditManifestError) as error:
            raise AuditQueryUnavailable("audit shards unavailable") from error

    def get(self, event_id: str, tenant_id: str = "local") -> AnalysisResult | None:
        return next(
            (
                r
                for r in reversed(self._snapshot()[0])
                if r.event_id == event_id and r.tenant_id == tenant_id
            ),
            None,
        )

    def recent(self, limit=20, tenant_id="local"):
        records = [r for r in self._snapshot()[0] if r.tenant_id == tenant_id]
        return list(reversed(records[-limit:])) if limit > 0 else []

    def metrics(self, tenant_id="local"):
        return _summarize([r for r in self._snapshot()[0] if r.tenant_id == tenant_id])

    def integrity(self):
        try:
            return self._snapshot()[1]
        except AuditQueryUnavailable:
            return {
                "backend": "federated_jsonl_hash_chains",
                "ok": False,
                "verified_lines": 0,
                "legacy_lines": 0,
            }

    def verify_saved(self, expected):
        # Verify the announced inventory and cross-shard conflicts first, then
        # witness the exact original hashed row in this process's own writer.
        # A copy in another shard cannot substitute for a lost local append.
        self._snapshot()
        super().verify_saved(expected)
