"""Metadata-only linkage diagnostics. Never classifier features or trust authorities."""

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from scripts.f1_lab.native_jsonl import require

PLACEHOLDERS = {'', 'anonymous', 'unknown', 'none', 'null', '-', 'n/a', '00000000-0000-0000-0000-000000000000'}
PROFILE_FIELDS = ('ua', 'platform', 'deviceType', 'screen', 'colorDepth', 'canvas', 'cores', 'memory')
VOLATILE = {'ts', 'timestamp', 'nonce', 'traceid', 'sessionid', 'token', 'access_token'}
UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
ISO = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$')


def useful(value):
    return isinstance(value, str) and len(value) <= 8192 and value.strip().casefold() not in PLACEHOLDERS


def digest(kind, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    return kind+':'+hashlib.sha256(raw).hexdigest()


def truth(value):
    fields = [value[name] for name in ('Suspicious', 'suspicious') if name in value]
    if not fields or any(type(v) is not bool for v in fields) or len(set(fields)) != 1:
        return None
    return fields[0]


def normalize_payload(value, depth=0):
    require(depth <= 16, 'context_payload_depth')
    if isinstance(value, dict):
        require(len(value) <= 256, 'context_payload_keys')
        return {key: '<volatile>' if key.casefold() in VOLATILE else normalize_payload(child, depth+1)
                for key, child in sorted(value.items())}
    if isinstance(value, list):
        require(len(value) <= 1024, 'context_payload_array')
        return [normalize_payload(child, depth+1) for child in value]
    if isinstance(value, str):
        return '<uuid>' if UUID.fullmatch(value) else '<time>' if ISO.fullmatch(value) else value
    return value


def links(value):
    require(isinstance(value, dict), 'context_json_object')
    context = value.get('UserContext')
    context = context if isinstance(context, dict) else {}
    claims = context.get('claims')
    claims = claims if isinstance(claims, dict) else {}
    identity = set()
    for kind, item in [('user', value.get('User')), ('user', claims.get('name')),
                       ('session', value.get('SessionId')), ('session', claims.get('SessionId'))]:
        if useful(item):
            identity.add(digest(kind, item.strip()))
    profile = None
    fingerprint = value.get('Fingerprint')
    if isinstance(fingerprint, dict):
        fields = {name: fingerprint[name] for name in PROFILE_FIELDS if useful(fingerprint.get(name))}
        if len(fields) >= 3:
            profile = digest('browser-profile', fields)
    template = None
    template_error = False
    metadata = value.get('RequestMetadata')
    if isinstance(metadata, dict) and useful(metadata.get('method')) and useful(metadata.get('url')):
        try:
            parsed = urlsplit(metadata['url'])
            path = '/'.join('<uuid>' if UUID.fullmatch(part) else '<number>' if part.isdecimal() else part for part in parsed.path.split('/'))
            query = [(key, '<volatile>' if key.casefold() in VOLATILE else '<uuid>' if UUID.fullmatch(item) else item)
                     for key, item in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256)]
            template = digest('request-template', {'method': metadata['method'], 'path': path,
                              'query': urlencode(sorted(query)), 'body': normalize_payload(value.get('JSON'))})
        except (ValueError, RecursionError):
            template_error = True
    return {'identity': sorted(identity), 'profile': profile, 'request_template': template, 'template_error': template_error}


class Components:
    def __init__(self):
        self.parent, self.size, self.tainted, self.linked, self.seen = [], [], [], [], {}

    def root(self, row):
        while self.parent[row] != row:
            self.parent[row] = self.parent[self.parent[row]]
            row = self.parent[row]
        return row

    def add(self, keys, *, development_probe):
        row = len(self.parent)
        self.parent.append(row)
        self.size.append(1)
        self.tainted.append(bool(development_probe))
        self.linked.append(bool(keys))
        for key in keys:
            if key in self.seen:
                a, b = self.root(row), self.root(self.seen[key])
                if a != b:
                    if self.size[a] < self.size[b]:
                        a, b = b, a
                    self.parent[b] = a
                    self.size[a] += self.size[b]
                    self.tainted[a] |= self.tainted[b]
            else:
                self.seen[key] = row

    def summary(self):
        roots = [i for i, parent in enumerate(self.parent) if i == parent]
        return {'rows': len(self.parent), 'components': len(roots),
                'largest_component_rows': max((self.size[i] for i in roots), default=0),
                'probe_tainted_components': sum(self.tainted[i] for i in roots),
                'probe_tainted_rows': sum(self.size[i] for i in roots if self.tainted[i]),
                'unlinked_rows': sum(not v for v in self.linked),
                'remaining_linked_untouched_rows': sum(self.size[i] for i in roots if not self.tainted[i] and self.linked[i]),
                'final_partition_certified': False}
