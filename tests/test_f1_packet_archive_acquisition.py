import hashlib
import io
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts import acquire_f1_packet_archive as source


class Response(io.BytesIO):
    def __init__(self, body, url, *, status=206, headers=None):
        super().__init__(body)
        self.url, self.status, self.headers = url, status, headers or {}

    def geturl(self):
        return self.url


@pytest.fixture
def lab(monkeypatch):
    body = b'abcdefghij'
    asset = replace(source.ASSET, bytes=len(body), publisher_md5=hashlib.md5(body, usedforsecurity=False).hexdigest())
    monkeypatch.setattr(source, 'ASSET', asset)
    monkeypatch.setattr(source, 'RANGE', 4)
    monkeypatch.setattr(source, 'get_settings', lambda: SimpleNamespace(app_environment='test'))
    monkeypatch.setattr(source.shutil, 'disk_usage', lambda _: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(source.time, 'sleep', lambda _: None)
    metadata = {'id': asset.record_id, 'metadata': {'version': asset.record_version,
                'license': {'id': asset.license_id}}, 'files': [{'key': asset.filename,
                'size': len(body), 'checksum': 'md5:' + asset.publisher_md5}]}
    calls = []

    def request(req, timeout):
        url = req.full_url
        calls.append(url)
        if url == asset.metadata_url:
            return Response(json.dumps(metadata).encode(), url, status=200)
        assert url == asset.url and timeout == 45
        first, last = map(int, req.headers['Range'].removeprefix('bytes=').split('-'))
        return Response(body[first:last + 1], url, headers={
            'Content-Range': f'bytes {first}-{last}/{len(body)}', 'Content-Length': str(last - first + 1)})

    monkeypatch.setattr(source.urllib.request, 'urlopen', request)
    return SimpleNamespace(body=body, asset=asset, metadata=metadata, calls=calls)


def test_complete_exact_ranges_verify_full_checksum_and_do_not_extract_or_execute(lab, tmp_path):
    out = tmp_path / 'download'
    result = source.acquire(out, workers=2)
    assert result['completed'] and result['publisher_md5_verified']
    assert result['local_sha256'] == hashlib.sha256(lab.body).hexdigest()
    assert (out / lab.asset.filename).read_bytes() == lab.body
    assert not result['archive_extracted'] and not result['code_executed_from_asset']
    assert result['paid_api_calls'] == result['aws_calls'] == 0
    assert result['role'] == 'training' and result['new_independent_evaluation'] is False
    rows = json.loads((out / 'ranges.json').read_bytes())
    assert [(r['start'], r['end']) for r in rows] == [(0, 3), (4, 7), (8, 9)]


@pytest.mark.parametrize('fault', ['license', 'version', 'size', 'checksum'])
def test_metadata_change_prevents_all_archive_requests(lab, tmp_path, fault):
    if fault == 'license': lab.metadata['metadata']['license']['id'] = 'other'
    if fault == 'version': lab.metadata['metadata']['version'] = 'other'
    if fault == 'size': lab.metadata['files'][0]['size'] += 1
    if fault == 'checksum': lab.metadata['files'][0]['checksum'] = 'md5:' + '0' * 32
    result = source.acquire(tmp_path / 'rejected')
    assert not result['completed'] and lab.calls == [lab.asset.metadata_url]
    assert not (tmp_path / 'rejected' / lab.asset.filename).exists()


@pytest.mark.parametrize('fault', ['origin', 'status', 'encoding', 'range', 'length'])
def test_wrong_transport_origin_status_or_range_is_rejected_and_closed(lab, monkeypatch, fault):
    response = Response(b'abcd', lab.asset.url, headers={'Content-Range': 'bytes 0-3/10', 'Content-Length': '4'})
    if fault == 'origin': response.url = 'https://example.org/data'
    if fault == 'status': response.status = 200
    if fault == 'encoding': response.headers['Content-Encoding'] = 'gzip'
    if fault == 'range': response.headers['Content-Range'] = 'bytes 1-4/10'
    if fault == 'length': response.headers['Content-Length'] = '5'
    monkeypatch.setattr(source.urllib.request, 'urlopen', lambda *_a, **_k: response)
    with pytest.raises(ValueError):
        source.transport(0, 3)
    assert response.closed


@pytest.mark.parametrize('start,end', [(-1, 2), (0, 4), (8, 10), (True, 2), (2, 1)])
def test_invalid_range_never_opens_network(lab, start, end):
    with pytest.raises(ValueError):
        source.transport(start, end)
    assert lab.calls == []


def test_full_checksum_failure_never_publishes_archive_and_keeps_evidence(lab, monkeypatch, tmp_path):
    original = source.transport

    def corrupt(start, end):
        response = original(start, end)
        return Response(b'X' * (end - start + 1), response.geturl(), headers=response.headers)

    monkeypatch.setattr(source, 'transport', corrupt)
    out = tmp_path / 'corrupt'
    result = source.acquire(out)
    assert not result['completed'] and 'checksum' in result['failure_code']
    assert not (out / lab.asset.filename).exists()
    assert (out / 'russellmitchell.assembly.part').exists()


def test_resume_revalidates_recipe_and_each_completed_chunk(lab, tmp_path):
    out = tmp_path / 'complete'
    source.acquire(out)
    # Move the completed output to a separate artifact before simulating an interrupted transfer.
    (out / lab.asset.filename).rename(tmp_path / 'previous-archive.source')
    first = out / 'chunks/chunk-0000.source'
    first.write_bytes(b'tampered')
    result = source.acquire(out, resume=True)
    assert not result['completed'] and not (out / lab.asset.filename).exists()
    assert 'reuse_pin' in result['failure_code']


@pytest.mark.parametrize('fault', ['environment', 'workers', 'disk', 'fresh', 'resume'])
def test_execution_preconditions_prevent_network(lab, monkeypatch, tmp_path, fault):
    out = tmp_path / 'new'
    kwargs = {}
    if fault == 'environment': monkeypatch.setattr(source, 'get_settings', lambda: SimpleNamespace(app_environment='production'))
    if fault == 'workers': kwargs['workers'] = 5
    if fault == 'disk': monkeypatch.setattr(source.shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    if fault == 'fresh': out.mkdir()
    if fault == 'resume': kwargs['resume'] = True
    with pytest.raises(ValueError):
        source.acquire(out, **kwargs)
    assert lab.calls == []
