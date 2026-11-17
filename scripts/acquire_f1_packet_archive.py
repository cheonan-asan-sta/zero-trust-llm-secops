"""Fetch one explicitly pinned training packet archive; never extract or run it.

This separate recipe permits only the declared RussellMitchell full archive.
The existing general public-source reader's 2 GiB limit is unchanged.
"""

import argparse
import hashlib
import http.client
import json
import shutil
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.public_sources import metadata, require

CHUNK = 1024**2
RANGE = 16 * CHUNK
MAXIMUM = 8 * 1024**3
DEADLINE_SECONDS = 3 * 3600


@dataclass(frozen=True)
class PinnedArchive:
    record_id: int = 19483937
    record_version: str = 'v2_1'
    filename: str = 'russellmitchell.zip'
    bytes: int = 7132670599
    publisher_md5: str = '78e9b7d169b438f03816019b52ab3ff7'
    license_id: str = 'cc-by-nc-sa-4.0'
    metadata_url: str = 'https://zenodo.org/api/records/19483937'
    url: str = 'https://zenodo.org/api/records/19483937/files/russellmitchell.zip/content'


ASSET = PinnedArchive()


def transport(start, end):
    require(type(start) is int and type(end) is int and 0 <= start <= end < ASSET.bytes <= MAXIMUM
            and end - start < RANGE, 'packet_range_bound')
    request = urllib.request.Request(ASSET.url, headers={
        'Range': f'bytes={start}-{end}', 'Accept-Encoding': 'identity',
        'User-Agent': 'ZeroTrustSecOps-public-packet-training/1.0'})
    response = urllib.request.urlopen(request, timeout=45)
    if (response.geturl() != ASSET.url or response.status != 206
            or response.headers.get('Content-Encoding', 'identity') != 'identity'
            or response.headers.get('Content-Range') != f'bytes {start}-{end}/{ASSET.bytes}'
            or response.headers.get('Content-Length') not in {None, str(end - start + 1)}):
        response.close()
        require(False, 'packet_range_response')
    return response


def digest_file(path):
    require(path.is_file() and not path.is_symlink(), 'packet_regular_file')
    result = hashlib.sha256()
    with path.open('rb') as stream:
        while body := stream.read(CHUNK):
            result.update(body)
    return result.hexdigest()


def span(directory, number, start, end, deadline, stopped):
    destination = directory / f'chunk-{number:04}.source'
    partial = destination.with_suffix('.part')
    receipt = destination.with_suffix('.json')
    require(not destination.is_symlink() and not partial.is_symlink() and not receipt.is_symlink(),
            'packet_chunk_symlink')
    # A completed chunk can be reused only after checking its exact receipt.
    if destination.exists():
        require(receipt.is_file() and receipt.stat().st_size <= 4096, 'packet_chunk_receipt')
        old = json.loads(receipt.read_bytes())
        require(old == {'number': number, 'start': start, 'end': end,
                        'sha256': digest_file(destination), 'bytes': end - start + 1}
                and destination.stat().st_size == end - start + 1, 'packet_chunk_reuse_pin')
        return old
    for attempt in range(6):
        require(not stopped.is_set() and time.monotonic() < deadline, 'packet_transfer_deadline')
        try:
            result = hashlib.sha256()
            count = 0
            with transport(start, end) as source, partial.open('wb') as target:
                while count < end - start + 1:
                    require(not stopped.is_set() and time.monotonic() < deadline, 'packet_transfer_deadline')
                    body = source.read(min(CHUNK, end - start + 1 - count))
                    if not body:
                        raise EOFError('short public packet range')
                    require(len(body) <= end - start + 1 - count, 'packet_range_body')
                    target.write(body)
                    result.update(body)
                    count += len(body)
                require(source.read(1) == b'', 'packet_range_extra_body')
            partial.rename(destination)
            row = {'number': number, 'start': start, 'end': end, 'bytes': count, 'sha256': result.hexdigest()}
            receipt.write_bytes(canonical(row) + b'\n')
            return row
        except (OSError, http.client.HTTPException, EOFError) as error:
            code = getattr(error, 'code', None)
            if code is not None and code not in {408, 429, 500, 502, 503, 504}:
                raise
            if attempt == 5:
                raise
            time.sleep(min(2 ** (attempt + 1), 16))
    raise RuntimeError('packet range retry accounting')


def assemble(directory, rows, destination):
    require(not destination.exists() and not destination.is_symlink(), 'packet_fresh_archive')
    partial = destination.with_suffix('.assembly.part')
    require(not partial.exists() and not partial.is_symlink(), 'packet_fresh_assembly')
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    count = 0
    with partial.open('xb') as target:
        for number, row in enumerate(rows):
            require(row['number'] == number and row['start'] == count, 'packet_complete_ranges')
            path = directory / f'chunk-{number:04}.source'
            require(path.stat().st_size == row['bytes'] == row['end'] - row['start'] + 1
                    and digest_file(path) == row['sha256'], 'packet_assembly_chunk_pin')
            with path.open('rb') as source:
                while body := source.read(CHUNK):
                    count += len(body)
                    require(count <= ASSET.bytes, 'packet_assembly_bound')
                    sha.update(body)
                    md5.update(body)
                    target.write(body)
    require(count == ASSET.bytes and md5.hexdigest() == ASSET.publisher_md5, 'packet_full_publisher_checksum')
    partial.rename(destination)
    return {'bytes_received': count, 'local_sha256': sha.hexdigest(), 'publisher_md5_verified': True}


def acquire(directory, *, resume=False, workers=4):
    require(get_settings().app_environment in {'local', 'test'}, 'packet_local_test_only')
    require(type(workers) is int and 1 <= workers <= 4 and type(resume) is bool, 'packet_execution_options')
    directory = Path(directory)
    require(not directory.is_symlink(), 'packet_output_symlink')
    directory = directory.resolve()
    require(directory.exists() is resume, 'packet_fresh_or_resume_directory')
    directory.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(directory.parent).free > 2 * ASSET.bytes + CHUNK * 1024,
            'packet_disk_headroom')
    recipe = {'schema': 'pinned-packet-training-acquisition-1', 'asset': asdict(ASSET),
              'purpose': 'noncommercial_research', 'range_bytes': RANGE, 'role': 'training',
              'goal_qualified': False, 'source_code_sha256': digest_file(Path(__file__))}
    if resume:
        require((directory / 'recipe.json').is_file()
                and json.loads((directory / 'recipe.json').read_bytes()) == recipe, 'packet_resume_recipe')
        require(not (directory / ASSET.filename).exists(), 'packet_already_completed')
    else:
        directory.mkdir()
        (directory / 'recipe.json').write_bytes(canonical(recipe) + b'\n')
    chunks = directory / 'chunks'
    chunks.mkdir(exist_ok=resume)
    require(not chunks.is_symlink(), 'packet_chunk_directory')
    started = time.monotonic()
    report = {'schema': 'pinned-packet-training-acquisition-1', 'completed': False,
              'asset': asdict(ASSET), 'purpose': 'noncommercial_research', 'role': 'training',
              'publisher_checksum_kind': 'MD5; not a publisher digital signature',
              'local_sha256_kind': 'local immutable follow-up anchor; not a publisher signature',
              'archive_extracted': False, 'code_executed_from_asset': False,
              'started_at': datetime.now(UTC).isoformat(), 'workers': workers, 'bytes_received': 0,
              'paid_api_calls': 0, 'aws_calls': 0, 'new_independent_evaluation': False, 'goal_qualified': False}
    lock = threading.Lock()
    try:
        raw = metadata(ASSET)
        (directory / 'publisher-metadata.json').write_bytes(raw)
        report['publisher_metadata_sha256'] = hashlib.sha256(raw).hexdigest()
        rows = {}
        stopped = threading.Event()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {pool.submit(span, chunks, n, start, min(start + RANGE, ASSET.bytes) - 1,
                                   started + DEADLINE_SECONDS, stopped): n
                       for n, start in enumerate(range(0, ASSET.bytes, RANGE))}
            try:
                for completed in as_completed(pending):
                    row = completed.result()
                    rows[row['number']] = row
                    report['bytes_received'] = sum(r['bytes'] for r in rows.values())
                    progress = {'bytes_received': report['bytes_received'], 'expected_bytes': ASSET.bytes,
                                'completed_ranges': len(rows), 'total_ranges': len(pending),
                                'elapsed_seconds': round(time.monotonic() - started, 2)}
                    with lock:
                        (directory / 'progress.json').write_bytes(canonical(progress) + b'\n')
                        print(json.dumps(progress), flush=True)
            except BaseException:
                stopped.set()
                for future in pending:
                    future.cancel()
                raise
        ordered = [rows[n] for n in range(len(rows))]
        (directory / 'ranges.json').write_bytes(canonical(ordered) + b'\n')
        report.update(assemble(chunks, ordered, directory / ASSET.filename))
        report['completed'] = True
    except (ValueError, TypeError, KeyError, OSError, EOFError, http.client.HTTPException) as error:
        report['failure_type'] = type(error).__name__
        report['failure_code'] = str(error) if str(error).startswith('public_asset_') else 'packet_acquisition_failed'
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['ended_at'] = datetime.now(UTC).isoformat()
        (directory / 'acquisition.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    result = acquire(args.output, resume=args.resume, workers=args.workers)
    print(json.dumps({k: result.get(k) for k in ('completed', 'bytes_received', 'local_sha256', 'failure_type')}))
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
