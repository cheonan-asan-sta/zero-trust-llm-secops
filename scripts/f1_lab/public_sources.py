"""Bounded acquisition of pinned public research assets; no archive execution/extraction."""

import argparse
import hashlib
import http.client
import json
import re
import shutil
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

from app.config import get_settings
from app.models import StrictModel

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT/'infra/f1-lab/public-assets.json'
CHUNK = 1024**2
RANGE_BYTES = 4*CHUNK
MAX_RETRIES = 8
MAX_ASSET = 2*1024**3


def require(condition, code):
    if not condition:
        raise ValueError('public_asset_'+code)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _value: require(False, 'nonfinite_json'))


class Asset(StrictModel):
    asset_id: str = Field(pattern=r'^[a-z0-9-]{1,80}$')
    record_id: int = Field(strict=True, ge=1)
    record_version: str = Field(min_length=1, max_length=64)
    filename: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,100}$')
    bytes: int = Field(strict=True, ge=1, le=MAX_ASSET)
    publisher_md5: str = Field(pattern=r'^[a-f0-9]{32}$')
    license_id: Literal['cc-by-4.0', 'cc-by-nc-sa-4.0']
    data_role: str = Field(min_length=1, max_length=128)
    reference: str

    @field_validator('filename')
    @classmethod
    def basename(cls, value):
        require(value not in {'.', '..'}, 'filename')
        return value

    @model_validator(mode='after')
    def record_reference(self):
        require(self.reference == 'https://zenodo.org/records/'+str(self.record_id), 'record_reference')
        return self

    @property
    def metadata_url(self):
        return 'https://zenodo.org/api/records/'+str(self.record_id)

    @property
    def url(self):
        return self.metadata_url+'/files/'+self.filename+'/content'


class Contract(StrictModel):
    schema_version: Literal['f1-public-assets-1']
    assets: list[Asset] = Field(min_length=1, max_length=16)

    @model_validator(mode='after')
    def unique(self):
        require(len({a.asset_id for a in self.assets}) == len(self.assets), 'duplicate_asset')
        require(len({(a.record_id, a.filename) for a in self.assets}) == len(self.assets), 'duplicate_record_file')
        return self


def load(path, expected_sha256):
    path = Path(path)
    require(re.fullmatch(r'[a-f0-9]{64}', expected_sha256) is not None, 'external_contract_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536, 'contract_file')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, 'contract_size')
    require(digest(raw) == expected_sha256, 'contract_hash')
    return Contract.model_validate(decode(raw))


def response(url, *, byte_range=None):
    headers = {'User-Agent': 'ZeroTrustSecOps-public-evaluation/1.0', 'Accept-Encoding': 'identity'}
    if byte_range is not None:
        start, end, total = byte_range
        require(all(type(value) is int for value in byte_range) and 0 <= start <= end < total <= MAX_ASSET, 'range_request')
        headers['Range'] = f'bytes={start}-{end}'
    request = urllib.request.Request(url, headers=headers)
    result = urllib.request.urlopen(request, timeout=45)
    parsed = urlparse(result.geturl())
    if parsed.scheme != 'https' or parsed.hostname != 'zenodo.org' or parsed.username or parsed.password or parsed.query or parsed.fragment:
        result.close()
        require(False, 'redirect_origin')
    if result.geturl() != url or result.status != (206 if byte_range is not None else 200) or result.headers.get('Content-Encoding', 'identity') != 'identity':
        result.close()
        require(False, 'response_contract')
    if byte_range is not None:
        start, end, total = byte_range
        if result.headers.get('Content-Range') != f'bytes {start}-{end}/{total}' or (
                result.headers.get('Content-Length') is not None and result.headers['Content-Length'] != str(end-start+1)):
            result.close()
            require(False, 'range_response')
    return result


def metadata(asset):
    with response(asset.metadata_url) as stream:
        raw = stream.read(2*CHUNK+1)
    require(len(raw) <= 2*CHUNK, 'metadata_size')
    data = decode(raw)
    require(data['id'] == asset.record_id and data['metadata']['version'] == asset.record_version
            and data['metadata']['license']['id'] == asset.license_id, 'publisher_record_changed')
    matches = [row for row in data['files'] if row['key'] == asset.filename]
    require(len(matches) == 1 and matches[0]['size'] == asset.bytes
            and matches[0]['checksum'] == 'md5:'+asset.publisher_md5, 'publisher_file_changed')
    return raw


def resume_prefix(asset, prior, purpose, target, sha, md5):
    prior = Path(prior)
    require(prior.is_dir() and not prior.is_symlink(), 'resume_directory')
    receipt = prior/'acquisition.json'
    require(receipt.is_file() and not receipt.is_symlink(), 'resume_receipt')
    with receipt.open('rb') as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, 'resume_receipt_size')
    report = decode(raw)
    require(report.get('schema') == 'f1-public-asset-acquisition-1' and report.get('completed') is False
            and report.get('asset') == asset.model_dump() and report.get('purpose') == purpose, 'resume_contract')
    prefix = prior/(asset.filename+'.part')
    require(prefix.is_file() and not prefix.is_symlink() and 0 <= prefix.stat().st_size == report.get('bytes_received') < asset.bytes,
            'resume_prefix_size')
    total, prefix_sha = 0, hashlib.sha256()
    with prefix.open('rb') as stream:
        while body := stream.read(CHUNK):
            total += len(body)
            require(total < asset.bytes, 'resume_prefix_bound')
            target.write(body)
            sha.update(body)
            md5.update(body)
            prefix_sha.update(body)
    require(total == report['bytes_received'], 'resume_prefix_changed')
    return {'resumed_prefix_bytes': total, 'resumed_prefix_sha256': prefix_sha.hexdigest(),
        'prior_acquisition_sha256': digest(raw), 'prefix_publisher_verified': False}


def ranged_transfer(asset, directory, target, report, sha, md5, started):
    retries = 0
    report['range_retries'] = 0
    while report['bytes_received'] < asset.bytes:
        require(time.monotonic()-started <= 3600, 'transfer_bound')
        start = report['bytes_received']
        end = min(start+RANGE_BYTES, asset.bytes)-1
        event = {'start': start, 'end': end, 'total': asset.bytes, 'completed': False}
        try:
            with response(asset.url, byte_range=(start, end, asset.bytes)) as stream:
                while report['bytes_received'] <= end:
                    body = stream.read(min(CHUNK, end+1-report['bytes_received']))
                    if not body:
                        raise EOFError('range ended before advertised boundary')
                    require(len(body) <= end+1-report['bytes_received'], 'range_body_bound')
                    target.write(body)
                    sha.update(body)
                    md5.update(body)
                    report['bytes_received'] += len(body)
                    (directory/'progress.json').write_bytes(canonical({'bytes_received': report['bytes_received'],
                        'expected_bytes': asset.bytes, 'retry_count': retries, 'elapsed_seconds': round(time.monotonic()-started, 2)}))
            event['completed'] = True
        except (OSError, http.client.HTTPException, EOFError) as error:
            event.update(completed=False, failure_type=type(error).__name__)
            if getattr(error, 'code', None) is not None and error.code not in {408, 429, 500, 502, 503, 504}:
                raise
            retries += 1
            require(retries <= MAX_RETRIES, 'range_retry_bound')
            report['range_retries'] = retries
            time.sleep(min(2**retries, 8))
        finally:
            event['next_offset'] = report['bytes_received']
            with (directory/'range-events.jsonl').open('ab') as log:
                log.write(canonical(event)+b'\n')
    report['range_retries'] = retries


def acquire(asset, directory, *, purpose, ranged=False, resume_from=None):
    require(get_settings().app_environment in {'local', 'test'}, 'local_test_only')
    require(isinstance(asset, Asset) and purpose in {'noncommercial_research', 'research'}, 'purpose')
    require(asset.license_id != 'cc-by-nc-sa-4.0' or purpose == 'noncommercial_research', 'noncommercial_purpose_required')
    require(type(ranged) is bool and (resume_from is None or ranged), 'resume_requires_ranges')
    directory = Path(directory)
    require(not directory.exists() and not directory.is_symlink(), 'fresh_directory_required')
    directory.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(directory.parent).free > asset.bytes*2+256*CHUNK, 'disk_headroom')
    directory.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'schema': 'f1-public-asset-acquisition-1', 'asset': asset.model_dump(), 'purpose': purpose,
        'started_at': datetime.now(UTC).isoformat(), 'completed': False, 'bytes_received': 0,
        'paid_api_calls': 0, 'aws_sdk_calls': 0, 'archive_extracted': False, 'code_executed_from_asset': False,
        'goal_qualified': False, 'publisher_checksum_kind': 'MD5; not a publisher digital signature',
        'local_sha256_kind': 'local immutable follow-up anchor; not a publisher signature',
        'ranged_transfer': ranged, 'resumed_prefix_bytes': 0}
    try:
        raw = metadata(asset)
        (directory/'publisher-metadata.json').write_bytes(raw)
        report['publisher_metadata_sha256'] = digest(raw)
        sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
        with (directory/(asset.filename+'.part')).open('xb') as target:
            if resume_from is not None:
                report.update(resume_prefix(asset, resume_from, purpose, target, sha, md5))
                report['bytes_received'] = report['resumed_prefix_bytes']
            if ranged:
                ranged_transfer(asset, directory, target, report, sha, md5, started)
            else:
                with response(asset.url) as stream:
                    length = stream.headers.get('Content-Length')
                    require(length is None or length.isdecimal() and int(length) == asset.bytes, 'content_length')
                    while chunk := stream.read(CHUNK):
                        require(report['bytes_received']+len(chunk) <= asset.bytes and time.monotonic()-started <= 1800, 'transfer_bound')
                        target.write(chunk)
                        sha.update(chunk)
                        md5.update(chunk)
                        report['bytes_received'] += len(chunk)
                        (directory/'progress.json').write_bytes(canonical({'bytes_received': report['bytes_received'],
                            'expected_bytes': asset.bytes, 'elapsed_seconds': round(time.monotonic()-started, 2)}))
        require(report['bytes_received'] == asset.bytes and md5.hexdigest() == asset.publisher_md5, 'size_or_checksum')
        report['local_sha256'] = sha.hexdigest()
        report['publisher_md5_verified'] = True
        (directory/(asset.filename+'.part')).rename(directory/asset.filename)
        report['completed'] = True
    except (ValueError, TypeError, KeyError, OSError, RecursionError, http.client.HTTPException) as error:
        report['failure_type'] = type(error).__name__
        report['failure_code'] = str(error) if type(error) is ValueError and str(error).startswith('public_asset_') else 'public_asset_acquisition_failed'
    finally:
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        report['ended_at'] = datetime.now(UTC).isoformat()
        (directory/'acquisition.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n', encoding='utf8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--asset', required=True)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--contract', type=Path, default=CONTRACT)
    parser.add_argument('--expected-contract-sha256', required=True)
    parser.add_argument('--purpose', choices=('noncommercial_research', 'research'), required=True)
    parser.add_argument('--ranges', action='store_true')
    parser.add_argument('--resume-from', type=Path)
    args = parser.parse_args()
    contract = load(args.contract, args.expected_contract_sha256)
    matches = [row for row in contract.assets if row.asset_id == args.asset]
    require(len(matches) == 1, 'unknown_asset')
    result = acquire(matches[0], args.directory, purpose=args.purpose, ranged=args.ranges, resume_from=args.resume_from)
    print(json.dumps({key: result.get(key) for key in ('completed', 'bytes_received', 'local_sha256', 'failure_type', 'failure_code', 'goal_qualified')}))
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
