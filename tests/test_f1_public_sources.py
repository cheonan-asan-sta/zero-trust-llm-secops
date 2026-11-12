import hashlib
import io
import json
import re
from types import SimpleNamespace

import pytest

from scripts.f1_lab import public_sources as source

TRANSPORT = source.response


class Response(io.BytesIO):
    def __init__(self, body, url, *, status=200, headers=None):
        super().__init__(body)
        self.url, self.status, self.headers = url, status, headers or {}

    def geturl(self):
        return self.url


@pytest.fixture
def lab(monkeypatch):
    body = b'public fixture data; never executed\n'
    asset = source.Asset(asset_id='fixture', record_id=123, record_version='v1', filename='fixture.zip',
        bytes=len(body), publisher_md5=hashlib.md5(body, usedforsecurity=False).hexdigest(), license_id='cc-by-4.0',
        data_role='fixture', reference='https://zenodo.org/records/123')
    metadata = {'id': 123, 'metadata': {'version': 'v1', 'license': {'id': asset.license_id}},
        'files': [{'key': asset.filename, 'size': len(body), 'checksum': 'md5:'+asset.publisher_md5}]}
    calls, payload = [], [body]
    def respond(url):
        calls.append(url)
        raw = source.canonical(metadata) if url == asset.metadata_url else payload[0]
        return Response(raw, url, headers={'Content-Length': str(len(raw))})
    monkeypatch.setattr(source, 'response', respond)
    monkeypatch.setattr(source, 'get_settings', lambda: SimpleNamespace(app_environment='test'))
    return SimpleNamespace(asset=asset, metadata=metadata, calls=calls, payload=payload, body=body)


def test_fixed_public_record_and_full_hash_are_verified_without_extracting_or_executing(lab, tmp_path):
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research')
    assert result['completed'] and result['publisher_md5_verified']
    assert result['local_sha256'] == hashlib.sha256(lab.body).hexdigest()
    assert (tmp_path/'result'/lab.asset.filename).read_bytes() == lab.body
    assert lab.calls == [lab.asset.metadata_url, lab.asset.url]
    assert not (tmp_path/'result'/(lab.asset.filename+'.part')).exists()
    assert not result['archive_extracted'] and not result['code_executed_from_asset'] and not result['goal_qualified']
    assert result['paid_api_calls'] == result['aws_sdk_calls'] == 0
    assert json.loads((tmp_path/'result/acquisition.json').read_bytes()) == result


@pytest.mark.parametrize('field,value', [('license', 'other-license'), ('version', 'v2'), ('id', 124), ('size', 1), ('checksum', 'md5:'+'0'*32)])
def test_changed_publisher_license_version_or_file_never_starts_archive_download(lab, tmp_path, field, value):
    if field == 'license':
        lab.metadata['metadata']['license']['id'] = value
    elif field == 'version':
        lab.metadata['metadata']['version'] = value
    elif field == 'id':
        lab.metadata['id'] = value
    else:
        lab.metadata['files'][0][field] = value
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research')
    assert not result['completed'] and lab.calls == [lab.asset.metadata_url]
    assert result['bytes_received'] == 0 and not (tmp_path/'result'/lab.asset.filename).exists()


@pytest.mark.parametrize('change', ['short', 'long', 'corrupt'])
def test_bad_size_or_checksum_keeps_failure_record_and_never_publishes_the_final_asset(lab, tmp_path, change):
    lab.payload[0] = lab.body[:-1] if change == 'short' else lab.body+b'x' if change == 'long' else b'x'+lab.body[1:]
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research')
    assert not result['completed'] and not (tmp_path/'result'/lab.asset.filename).exists()
    assert not result.get('publisher_md5_verified', False)
    assert (tmp_path/'result/acquisition.json').exists()


def test_noncommercial_license_requires_explicit_research_purpose_before_io(lab, tmp_path):
    asset = lab.asset.model_copy(update={'license_id': 'cc-by-nc-sa-4.0'})
    with pytest.raises(ValueError, match='noncommercial_purpose_required'):
        source.acquire(asset, tmp_path/'result', purpose='research')
    assert not lab.calls and not (tmp_path/'result').exists()
    lab.metadata['metadata']['license']['id'] = asset.license_id
    assert source.acquire(asset, tmp_path/'result', purpose='noncommercial_research')['completed']


def test_production_and_existing_output_are_rejected_without_requests_or_overwrite(lab, tmp_path, monkeypatch):
    (tmp_path/'existing').mkdir()
    (tmp_path/'existing/user-file').write_bytes(b'preserve')
    with pytest.raises(ValueError, match='fresh_directory'):
        source.acquire(lab.asset, tmp_path/'existing', purpose='research')
    assert (tmp_path/'existing/user-file').read_bytes() == b'preserve' and not lab.calls
    monkeypatch.setattr(source, 'get_settings', lambda: SimpleNamespace(app_environment='production'))
    with pytest.raises(ValueError, match='local_test_only'):
        source.acquire(lab.asset, tmp_path/'production', purpose='research')
    assert not (tmp_path/'production').exists() and not lab.calls


@pytest.mark.parametrize('url,status,headers', [
    ('http://zenodo.org/api/records/123', 200, {}), ('https://other.example/api/records/123', 200, {}),
    ('https://zenodo.org/api/records/123?token=private', 200, {}),
    ('https://zenodo.org/api/records/124', 200, {}), ('https://zenodo.org/api/records/123', 206, {}),
    ('https://zenodo.org/api/records/123', 200, {'Content-Encoding': 'gzip'})])
def test_transport_does_not_follow_unexpected_origins_records_partial_content_or_encoding(monkeypatch, url, status, headers):
    response = Response(b'body', url, status=status, headers=headers)
    monkeypatch.setattr(source.urllib.request, 'urlopen', lambda *_a, **_kw: response)
    with pytest.raises(ValueError):
        source.response('https://zenodo.org/api/records/123')
    assert response.closed


def test_asset_contract_has_external_anchor_and_strict_unique_population(lab, tmp_path):
    payload = {'schema_version': 'f1-public-assets-1', 'assets': [lab.asset.model_dump()]}
    path = tmp_path/'contract.json'
    raw = source.canonical(payload)
    path.write_bytes(raw)
    assert source.load(path, source.digest(raw)).assets == [lab.asset]
    with pytest.raises(ValueError, match='contract_hash'):
        source.load(path, '0'*64)
    payload['assets'] *= 2
    path.write_bytes(source.canonical(payload))
    with pytest.raises(ValueError, match='duplicate_asset'):
        source.load(path, source.digest(path.read_bytes()))
    with pytest.raises(ValueError, match='duplicate_json_key'):
        source.decode(b'{"x":1,"x":2}')


@pytest.mark.parametrize('filename', ['..', '.', '../file.zip', r'..\file.zip', 'file.zip?token=x'])
def test_record_asset_name_is_a_basename_not_a_path_or_query(lab, filename):
    with pytest.raises(ValueError):
        source.Asset.model_validate({**lab.asset.model_dump(), 'filename': filename})


def test_content_transfer_failure_has_a_bounded_reason_and_no_success_receipt(lab, tmp_path, monkeypatch):
    original = source.response
    def fail(url):
        if url == lab.asset.url:
            raise OSError('private-transport-marker')
        return original(url)
    monkeypatch.setattr(source, 'response', fail)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research')
    assert not result['completed'] and 'private-transport-marker' not in json.dumps(result)
    assert result['failure_code'] == 'public_asset_acquisition_failed'


def range_server(lab, monkeypatch, *, interrupt=False, wrong_range=False, ignore_range=False, truncate_always=False):
    calls = []
    class Interrupted(Response):
        def read(self, size=-1):
            if self.tell() == 0:
                return super().read(min(size, 5))
            raise TimeoutError('transport-details-not-exported')
    def serve(request, **_kwargs):
        if request.full_url == lab.asset.metadata_url:
            return Response(source.canonical(lab.metadata), request.full_url)
        header = request.get_header('Range')
        match = re.fullmatch(r'bytes=(\d+)-(\d+)', header)
        assert match
        start, end = map(int, match.groups())
        calls.append((start, end))
        body = lab.body[start:end+1]
        if truncate_always:
            body = b''
        kind = Interrupted if interrupt and len(calls) == 1 else Response
        return kind(body, request.full_url, status=200 if ignore_range else 206,
            headers={'Content-Range': f'bytes {0 if wrong_range else start}-{end}/{lab.asset.bytes}',
                     'Content-Length': str(end-start+1)})
    monkeypatch.setattr(source, 'response', TRANSPORT)
    monkeypatch.setattr(source.urllib.request, 'urlopen', serve)
    monkeypatch.setattr(source.time, 'sleep', lambda _seconds: None)
    return calls


def test_interrupted_range_retries_from_committed_offset_without_duplicate_or_missing_bytes(lab, tmp_path, monkeypatch):
    calls = range_server(lab, monkeypatch, interrupt=True)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True)
    assert result['completed'] and result['range_retries'] == 1
    assert calls == [(0, len(lab.body)-1), (5, len(lab.body)-1)]
    assert (tmp_path/'result'/lab.asset.filename).read_bytes() == lab.body
    events = [json.loads(line) for line in (tmp_path/'result/range-events.jsonl').read_bytes().splitlines()]
    assert [row['completed'] for row in events] == [False, True] and events[0]['next_offset'] == 5


def prior_prefix(lab, tmp_path, *, body=None, asset=None, purpose='research'):
    prior = tmp_path/'prior'
    prior.mkdir()
    prefix = lab.body[:7] if body is None else body
    (prior/(lab.asset.filename+'.part')).write_bytes(prefix)
    receipt = {'schema': 'f1-public-asset-acquisition-1', 'completed': False, 'asset': asset or lab.asset.model_dump(),
               'purpose': purpose, 'bytes_received': len(prefix)}
    (prior/'acquisition.json').write_bytes(source.canonical(receipt))
    return prior, receipt


def test_resume_preserves_failed_attempt_and_rechecks_the_whole_publisher_checksum(lab, tmp_path, monkeypatch):
    prior, receipt = prior_prefix(lab, tmp_path)
    calls = range_server(lab, monkeypatch)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True, resume_from=prior)
    assert result['completed'] and result['resumed_prefix_bytes'] == 7
    assert calls == [(7, len(lab.body)-1)]
    assert (tmp_path/'result'/lab.asset.filename).read_bytes() == lab.body
    assert (prior/(lab.asset.filename+'.part')).read_bytes() == lab.body[:7]
    assert json.loads((prior/'acquisition.json').read_bytes()) == receipt
    assert not result['prefix_publisher_verified'] and result['publisher_md5_verified']


def test_changed_prefix_cannot_be_promoted_even_when_remaining_ranges_are_valid(lab, tmp_path, monkeypatch):
    prior, _receipt = prior_prefix(lab, tmp_path, body=b'xxxxxxx')
    range_server(lab, monkeypatch)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True, resume_from=prior)
    assert not result['completed'] and result['failure_code'] == 'public_asset_size_or_checksum'
    assert not (tmp_path/'result'/lab.asset.filename).exists()


@pytest.mark.parametrize('change', ['asset', 'purpose', 'size', 'completed'])
def test_resume_receipt_cannot_cross_asset_purpose_or_prefix_population(lab, tmp_path, monkeypatch, change):
    prior, receipt = prior_prefix(lab, tmp_path)
    if change == 'asset':
        receipt['asset'] = {**receipt['asset'], 'record_id': 999}
    elif change == 'purpose':
        receipt['purpose'] = 'other'
    elif change == 'size':
        receipt['bytes_received'] = 1
    else:
        receipt['completed'] = True
    (prior/'acquisition.json').write_bytes(source.canonical(receipt))
    calls = range_server(lab, monkeypatch)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True, resume_from=prior)
    assert not result['completed'] and not calls and not (tmp_path/'result'/lab.asset.filename).exists()


@pytest.mark.parametrize('change', ['wrong_offset', 'ignored_range'])
def test_server_cannot_append_a_different_range_or_a_full_response_to_a_prefix(lab, tmp_path, monkeypatch, change):
    prior, _receipt = prior_prefix(lab, tmp_path)
    calls = range_server(lab, monkeypatch, wrong_range=change == 'wrong_offset', ignore_range=change == 'ignored_range')
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True, resume_from=prior)
    assert not result['completed'] and len(calls) == 1 and result['bytes_received'] == 7
    assert not (tmp_path/'result'/lab.asset.filename).exists()


def test_repeated_short_responses_stop_at_bounded_retry_budget(lab, tmp_path, monkeypatch):
    calls = range_server(lab, monkeypatch, truncate_always=True)
    result = source.acquire(lab.asset, tmp_path/'result', purpose='research', ranged=True)
    assert not result['completed'] and result['failure_code'] == 'public_asset_range_retry_bound'
    assert len(calls) == source.MAX_RETRIES+1 and result['range_retries'] == source.MAX_RETRIES
    assert result['bytes_received'] == 0 and not (tmp_path/'result'/lab.asset.filename).exists()


def test_resume_cannot_accidentally_use_an_unranged_full_body_transfer(lab, tmp_path):
    with pytest.raises(ValueError, match='resume_requires_ranges'):
        source.acquire(lab.asset, tmp_path/'result', purpose='research', resume_from=tmp_path/'prior')
    assert not (tmp_path/'result').exists() and not lab.calls
