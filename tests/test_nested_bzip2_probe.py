import bz2
import hashlib
import io

import pytest

from scripts.f1_lab.nested_bzip2_probe import CHUNK, chunks, probe


def test_prefix_stays_fixed_and_all_later_bytes_are_integrity_checked():
    body = b'{"message":"native","process":{"pid":9}}\n' * 130
    result, prefix = probe(io.BytesIO(bz2.compress(body)))
    assert prefix == body[:len(body) // 130 * 128]
    assert result['probe_lines'] == 128 and result['parse_errors'] == 0
    assert result['decoded_sha256'] == hashlib.sha256(body).hexdigest()
    assert result['decoded_bytes'] == len(body)
    assert result['top_level_keys'] == {'message': 128, 'process': 128}
    assert result['field_paths_and_types']['process.pid:int'] == 128
    assert result['automatic_enforcement_allowed'] is False
    assert result['labels_inferred'] == result['trained_or_predicted_rows'] == 0
    assert result['new_independent_cases'] == 0


@pytest.mark.parametrize('suffix', [b'x', b'\0', bz2.compress(b'{"future":true}\n')])
def test_trailing_bytes_and_concatenated_streams_are_rejected(suffix):
    with pytest.raises(ValueError, match='bz2_trailing_bytes'):
        probe(io.BytesIO(bz2.compress(b'{}\n') + suffix))


@pytest.mark.parametrize('missing', [1, 5, 10, 20])
def test_truncation_after_valid_prefix_is_not_success(missing):
    data = bz2.compress(b'{"valid":true}\n' * 150)
    with pytest.raises(ValueError, match='bz2_incomplete'):
        probe(io.BytesIO(data[:-missing]))


def test_corrupt_checksum_cannot_publish_a_successful_prefix():
    data = bytearray(bz2.compress(b'{}\n' * 150))
    data[-5] ^= 1
    with pytest.raises(ValueError, match='bz2_'):
        probe(io.BytesIO(data))


@pytest.mark.parametrize('body', [b'not-json\n', b'\xff\n', b'\n', b'[]\n',
                                b'{"x":1,"x":2}\n', b'{"x":NaN}\n'])
def test_malformed_non_object_duplicate_nonfinite_rows_stay_in_prefix(body):
    data = body + b'{"ok":true}\n'
    result, prefix = probe(io.BytesIO(bz2.compress(data)))
    assert prefix == data and result['probe_lines'] == 2
    assert result['parse_errors'] == 1
    assert result['rows'][0]['error'] is not None
    assert result['rows'][1]['ordinal'] == 2
    assert result['top_level_keys'] == {'ok': 1}


def test_final_line_without_newline_is_preserved():
    result, prefix = probe(io.BytesIO(bz2.compress(b'{}\n{"last":1}')))
    assert result['probe_lines'] == 2 and result['parse_errors'] == 0
    assert prefix == b'{}\n{"last":1}'


def test_decoded_size_limit_applies_after_observed_prefix():
    data = b'{}\n' * 128 + b' ' * CHUNK
    with pytest.raises(ValueError, match='bz2_decoded_size'):
        probe(io.BytesIO(bz2.compress(data)), maximum_decoded_bytes=1000)


def test_compression_expansion_drains_internal_output_until_eof():
    body = b'{}\n' * 100000
    result, prefix = probe(io.BytesIO(bz2.compress(body)))
    assert result['decoded_bytes'] == len(body)
    assert result['decoded_sha256'] == hashlib.sha256(body).hexdigest()
    assert prefix == b'{}\n' * 128


def test_oversized_prefix_row_is_not_silently_dropped():
    with pytest.raises(ValueError, match='probe_oversized_row'):
        probe(io.BytesIO(bz2.compress(b'{"a":"' + b'x' * 100 + b'"}\n')), maximum_row_bytes=20)


@pytest.mark.parametrize('options', [{'maximum_lines': 0}, {'maximum_lines': True},
                                   {'maximum_lines': 129}, {'maximum_row_bytes': 0},
                                   {'maximum_decoded_bytes': 0}])
def test_bounds_cannot_be_disabled(options):
    with pytest.raises(ValueError):
        probe(io.BytesIO(bz2.compress(b'{}\n')), **options)


def test_invalid_non_bzip2_input_is_rejected():
    with pytest.raises(ValueError, match='bz2_'):
        list(chunks(io.BytesIO(b'{}\n')))
