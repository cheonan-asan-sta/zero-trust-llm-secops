"""Bounded native schema inspection; no labels, classifier or trust assertions."""

import bz2
import hashlib
import io
from collections import Counter

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require

MAX_DECODED = 512 * 1024**2
CHUNK = 64 * 1024


def chunks(stream, *, maximum_bytes=MAX_DECODED):
    """Require one complete bzip2 stream, including EOF and all trailing bytes."""
    require(type(maximum_bytes) is int and 0 < maximum_bytes <= MAX_DECODED, 'bz2_bound')
    decoder, total = bz2.BZ2Decompressor(), 0
    while block := stream.read(CHUNK):
        require(not decoder.eof, 'bz2_trailing_bytes')
        while True:
            try:
                value = decoder.decompress(block, max_length=CHUNK)
            except (OSError, EOFError, ValueError) as error:
                raise ValueError('native_source_bz2_decode') from error
            block = b''
            total += len(value)
            require(total <= maximum_bytes, 'bz2_decoded_size')
            if value:
                yield value
            if decoder.eof:
                require(not decoder.unused_data, 'bz2_trailing_bytes')
                break
            if decoder.needs_input:
                break
            require(bool(value), 'bz2_no_progress')
    require(decoder.eof, 'bz2_incomplete')


def shape(value, counts, prefix='', depth=0):
    require(depth <= 32, 'probe_json_depth')
    if isinstance(value, dict):
        require(len(value) <= 10000, 'probe_key_count')
        for key, item in value.items():
            require(type(key) is str and len(key) <= 512, 'probe_key_size')
            name = prefix + '.' + key if prefix else key
            counts[name + ':' + type(item).__name__] += 1
            shape(item, counts, name, depth + 1)
    elif isinstance(value, list):
        require(len(value) <= 10000, 'probe_list_count')
        for item in value:
            shape(item, counts, prefix + '[]', depth + 1)


def probe(stream, *, maximum_lines=128, maximum_row_bytes=MAX_ROW,
          maximum_decoded_bytes=MAX_DECODED):
    """Inspect a fixed prefix, hash the rest, and retain every prefix parse error."""
    require(type(maximum_lines) is int and 0 < maximum_lines <= 128, 'probe_line_bound')
    require(type(maximum_row_bytes) is int and 0 < maximum_row_bytes <= MAX_ROW, 'probe_row_bound')
    digest, total, pending = hashlib.sha256(), 0, b''
    output, rows, paths, roots, types = io.BytesIO(), [], Counter(), Counter(), Counter()

    def observe(raw):
        require(len(raw) <= maximum_row_bytes, 'probe_oversized_row')
        output.write(raw)
        row = {'ordinal': len(rows) + 1, 'bytes': len(raw),
               'sha256': hashlib.sha256(raw).hexdigest(), 'error': None}
        try:
            value = decode(raw)
            require(type(value) is dict, 'probe_object_required')
            local = Counter()
            shape(value, local)
            paths.update(local)
            roots.update(value.keys())
            types[type(value).__name__] += 1
        except (UnicodeError, ValueError, RecursionError) as error:
            row['error'] = type(error).__name__
        rows.append(row)

    for value in chunks(stream, maximum_bytes=maximum_decoded_bytes):
        digest.update(value)
        total += len(value)
        if len(rows) >= maximum_lines:
            continue
        pending += value
        while len(rows) < maximum_lines and b'\n' in pending:
            raw, pending = pending.split(b'\n', 1)
            observe(raw + b'\n')
        if len(rows) >= maximum_lines:
            pending = b''
        else:
            require(len(pending) <= maximum_row_bytes, 'probe_oversized_row')
    if pending and len(rows) < maximum_lines:
        observe(pending)
    prefix = output.getvalue()
    return {'schema': 'bounded-native-bzip2-schema-probe-1', 'complete': True,
            'decoded_bytes': total, 'decoded_sha256': digest.hexdigest(),
            'probe_lines': len(rows), 'probe_sha256': hashlib.sha256(prefix).hexdigest(),
            'rows': rows, 'parse_errors': sum(r['error'] is not None for r in rows),
            'top_level_keys': dict(roots), 'types': dict(types),
            'field_paths_and_types': dict(sorted(paths.items())),
            'labels_inferred': 0, 'trained_or_predicted_rows': 0,
            'new_independent_cases': 0, 'automatic_enforcement_allowed': False}, prefix
