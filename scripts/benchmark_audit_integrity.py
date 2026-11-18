"""Controlled local Python-allocation comparison; no model/API performance claim."""

import argparse
import gc
import hashlib
import json
import platform
import statistics
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import AnalysisResult, ReviewStatus
from app.scenarios import synthetic_events
from app.services.audit import _record_hash
from app.services.policy import response_preview
from app.services.sqlite_audit import SQLiteAuditStore


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(directory, *, rows=1024, padding_bytes=4096, repetitions=3, reviews_per_analysis=0):
    if not (
        type(rows) is int
        and 1 <= rows <= 10000
        and type(padding_bytes) is int
        and 0 <= padding_bytes <= 16384
        and type(repetitions) is int
        and 1 <= repetitions <= 5
        and type(reviews_per_analysis) is int
        and 0 <= reviews_per_analysis <= 4
    ):
        raise ValueError("bounded benchmark options required")
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=False)
    store = SQLiteAuditStore(directory / "synthetic-storage.sqlite3")
    event = synthetic_events()[0].model_copy(update={"ground_truth": None})
    assessment = RuleBasedAnalyzer().assess(event)
    if reviews_per_analysis:
        assessment = assessment.model_copy(update={"requires_human_review": True})
    base = AnalysisResult(
        event_id="local-storage-benchmark",
        analyzer="rule",
        assessment=assessment,
        policy_decision=response_preview(assessment, event),
        latency_ms=1,
        llm_trace={
            "meaning": "synthetic storage fixture; no LLM invocation",
            "padding": "x" * padding_bytes,
        },
    )
    # One fixture-only transaction avoids timing the runtime's per-append full
    # validation. Every constructed row is model-validated and hash chained.
    with store._transaction(write=True) as con:
        previous = "0" * 64
        for index in range(rows):
            analysis_index, revision = divmod(index, reviews_per_analysis + 1)
            record = base.model_copy(
                update={
                    "analysis_id": f"{analysis_index:032x}",
                    "event_id": f"storage-fixture-{analysis_index}",
                    "tenant_id": f"storage-tenant-{analysis_index % 8}",
                }
            )
            if revision:
                record = record.model_copy(
                    update={
                        "review_status": ReviewStatus.IN_REVIEW
                        if revision % 2
                        else ReviewStatus.RESOLVED,
                        "reviewer": "local-storage-benchmark",
                        "review_note": "Synthetic review history fixture",
                        "review_updated_at": base.analyzed_at + timedelta(seconds=revision),
                    }
                )
            record = AnalysisResult.model_validate(record.model_dump(mode="json"))
            payload = record.model_dump_json()
            digest = _record_hash(previous, payload)
            con.execute(
                "INSERT INTO audit_entries VALUES (?,?,?,?)", (index + 1, previous, digest, payload)
            )
            previous = digest
        con.execute("UPDATE audit_head SET seq=?,digest=? WHERE id=1", (rows, previous))
    original_sha = file_hash(store.path)
    distinct_analyses = (rows + reviews_per_analysis) // (reviews_per_analysis + 1)
    samples = {"materialized_compatibility_scan": [], "compact_integrity_scan": []}
    for iteration in range(repetitions):
        modes = [(True, "materialized_compatibility_scan"), (False, "compact_integrity_scan")]
        if iteration % 2:
            modes.reverse()
        for retained, name in modes:
            gc.collect()
            tracemalloc.start()
            started = perf_counter()
            try:
                with store._transaction() as con:
                    entries, seq, digest, size = store._read(con, retain_records=retained)
                    assert len(entries) == distinct_analyses and seq == rows and digest == previous
                    del entries
                elapsed = perf_counter() - started
                current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            samples[name].append(
                {
                    "seconds": elapsed,
                    "python_peak_bytes": peak,
                    "python_current_bytes": current,
                    "verified_rows": seq,
                    "verified_payload_bytes": size,
                    "verified_head": digest,
                }
            )
    assert store.integrity()["ok"] and file_hash(store.path) == original_sha
    summary = {
        name: {
            "median_seconds": statistics.median(v["seconds"] for v in values),
            "median_python_peak_bytes": statistics.median(v["python_peak_bytes"] for v in values),
            "samples": values,
        }
        for name, values in samples.items()
    }
    before = summary["materialized_compatibility_scan"]["median_python_peak_bytes"]
    after = summary["compact_integrity_scan"]["median_python_peak_bytes"]
    report = {
        "completed": True,
        "timestamp": datetime.now(UTC).isoformat(),
        "rows": rows,
        "padding_bytes_per_row": padding_bytes,
        "repetitions": repetitions,
        "reviews_per_analysis": reviews_per_analysis,
        "distinct_analyses": distinct_analyses,
        "synthetic_storage_fixture_only": True,
        "comparison": "same current verifier and fixed SQLite snapshot, two retention modes",
        "source_database_unchanged": True,
        "source_database_sha256": original_sha,
        "python_version": platform.python_version(),
        "system": platform.system(),
        "python_peak_reduction_percent": (1 - after / before) * 100,
        "measurements": summary,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "not_process_rss_or_service_sla": True,
        "model_quality_measured": False,
        "source_sha256": {
            "sqlite_audit.py": file_hash(
                Path(__file__).parents[1] / "app/services/sqlite_audit.py"
            ),
            "benchmark_audit_integrity.py": file_hash(__file__),
        },
    }
    (directory / "result.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", type=Path, required=True, help="fresh private output directory"
    )
    parser.add_argument("--rows", type=int, default=1024)
    parser.add_argument("--padding-bytes", type=int, default=4096)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--reviews-per-analysis", type=int, default=0)
    args = parser.parse_args()
    result = run(
        args.directory,
        rows=args.rows,
        padding_bytes=args.padding_bytes,
        repetitions=args.repetitions,
        reviews_per_analysis=args.reviews_per_analysis,
    )
    print(
        json.dumps(
            {
                "completed": result["completed"],
                "rows": result["rows"],
                "python_peak_reduction_percent": result["python_peak_reduction_percent"],
            }
        )
    )


if __name__ == "__main__":
    main()
