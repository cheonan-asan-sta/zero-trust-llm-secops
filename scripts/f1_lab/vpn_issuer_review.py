"""Advisory server-reported issuer relations; never an identity or permission.

Only equality with preceding issuer subjects is represented. Subject text and
join hashes, source age, client claims and future leaf verification are not
model features. Even a lowered alert remains a review, never an access grant.
"""

import hashlib
import itertools
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_context import PREFIX, endpoint
from scripts.f1_lab.vpn_protocol_review import ProtocolObservation

PROFILE = 'causal-vpn-reported-issuer-relations-1'
SCHEMA = 'vpn-reported-issuer-advisory-head-1'
REASONS = {'vpn_history_risk_review', 'vpn_strict_past_risk_retained'}
FIELDS = ('reported_issuer_present', 'reported_issuer_subject_seen_before',
          'other_issuer_subject_previously_observed')
VERIFY = re.compile(r'VERIFY OK: depth=(0|[1-9]\d?), ([^\r\n]{1,1024})')
SUBJECT_FIELD = re.compile(r'(C|ST|L|O|OU|CN|emailAddress)=([^,=\r\n]{1,256})')


def verified_subject(body):
    """Parse a reported subject for a local equality join, not trusted identity."""
    match = VERIFY.fullmatch(body)
    if match is None:
        return None
    fields = [SUBJECT_FIELD.fullmatch(value) for value in match[2].split(', ')]
    if (not 1 <= len(fields) <= 8 or not all(fields)
            or len({field[1] for field in fields}) != len(fields) or not any(field[1] == 'CN' for field in fields)):
        return None
    return int(match[1]), tuple((field[1], field[2]) for field in fields)


def server_verification_stage(body):
    if verified_subject(body) is not None:
        return True
    if body in {'VERIFY KU OK', 'VERIFY EKU OK', 'Validating certificate extended key usage'}:
        return True
    return re.fullmatch(r'\+\+ Certificate has EKU \(str\) TLS Web (Client|Server) Authentication, '
                        r'expects TLS Web (Client|Server) Authentication', body) is not None


def feature_pin(features):
    require(type(features) is dict and set(features) == set(FIELDS)
            and all(type(features[k]) is bool for k in FIELDS)
            and features['reported_issuer_present'] is True, 'issuer_feature_fields')
    return hashlib.sha256(canonical({'profile': PROFILE, **features})).hexdigest()


@dataclass(frozen=True)
class IssuerObservation:
    source_sha256: str
    ordinal: int
    line_sha256: str
    projection_sha256: str
    protected: bool
    human_or_device_identity_verified: bool = False
    authority_verified: bool = False


class IssuerRelationReview:
    def __init__(self, source_sha256):
        require(type(source_sha256) is str and re.fullmatch('[a-f0-9]{64}', source_sha256), 'issuer_source')
        self.source, self.ordinal, self.time, self.disabled = source_sha256, 0, None, False
        self.known, self.active = {}, {}

    def observe(self, ordinal, line, moment, protocol_observation, *, source_sha256):
        require(type(ordinal) is int and ordinal > 0 and type(line) is str and len(line.encode()) <= MAX_ROW,
                'issuer_current_row')
        require(isinstance(protocol_observation, ProtocolObservation)
                and protocol_observation.source_sha256 == source_sha256 and protocol_observation.ordinal == ordinal
                and protocol_observation.line_sha256 == hashlib.sha256(line.encode()).hexdigest()
                and type(protocol_observation.available) is bool and type(protocol_observation.protected) is bool,
                'issuer_protocol_binding')
        if self.disabled:
            return None
        try:
            reported = datetime.fromisoformat(line[:19]).replace(tzinfo=UTC).timestamp()
        except (ValueError, OverflowError, OSError):
            reported = None
        if (source_sha256 != self.source or ordinal != self.ordinal + 1 or type(moment) not in {int, float}
                or not math.isfinite(moment) or reported is None or moment != reported
                or self.time is not None and moment < self.time):
            self.disabled = True
            return None
        self.ordinal, self.time = ordinal, moment
        self.known = {key: at for key, at in self.known.items() if moment - at <= 86400}
        self.active = {key: value for key, value in self.active.items() if moment - value[1] <= 300}
        match, ep = PREFIX.match(line), endpoint(line)
        if ep is None and re.match(r'(?:OpenVPN \d|SIG(?:TERM|USR1|HUP)\[)', line[20:]):
            self.known.clear()
            self.active.clear()
        if not protocol_observation.available:
            return None
        if match is None or ep is None:
            return None
        _peer, connection, _named, initial = ep
        if initial:
            self.active.pop(connection, None)
        body = line[match.end():].rstrip('\r\n')
        subject = verified_subject(body)
        current = self.active.get(connection)
        if subject is not None and subject[0] == 1:
            # Only a source-local equality join. This is a subject, NOT a
            # certificate fingerprint, current trust-store check or attestation.
            key = hashlib.sha256(canonical({'source': self.source, 'subject': subject[1]})).digest()
            features = {'reported_issuer_present': True,
                'reported_issuer_subject_seen_before': key in self.known,
                'other_issuer_subject_previously_observed': any(prior != key for prior in self.known)}
            current = features, moment
            self.active[connection] = current
            self.known[key] = moment
        require(len(self.known) <= 10000 and len(self.active) <= 10000, 'issuer_capacity')
        if current is None or not server_verification_stage(body):
            return None
        return IssuerObservation(self.source, ordinal, hashlib.sha256(line.encode()).hexdigest(),
                                 feature_pin(current[0]), protocol_observation.protected)


class IssuerHead:
    def __init__(self, dependencies):
        require(type(dependencies) is dict and set(dependencies) ==
                {'legacy_identity_sha256', 'protocol_model_sha256', 'control_model_sha256'}
                and all(type(p) is str and re.fullmatch('[a-f0-9]{64}', p) for p in dependencies.values()),
                'issuer_dependencies')
        self.dependencies, self.rows, self.frozen = dependencies.copy(), {}, False

    def add(self, observation, malicious):
        require(not self.frozen and type(malicious) is bool, 'issuer_training_state')
        if observation is None:
            return
        require(isinstance(observation, IssuerObservation), 'issuer_observation_type')
        counts = self.rows.setdefault(observation.projection_sha256, [0, 0])
        counts[int(malicious)] += 1

    def save(self, path):
        require(not self.frozen and self.rows, 'issuer_empty_model')
        self.frozen = True
        value = {'schema': SCHEMA, 'profile': PROFILE, 'minimum_support': 5, 'rows': self.rows,
            'dependencies': self.dependencies, 'automatic_enforcement_allowed': False,
            'review_retained': True, 'identity_or_authority_verified': False}
        Path(path).write_bytes(canonical(value) + b'\n')
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @classmethod
    def load(cls, path, pin, dependencies):
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), 'issuer_model_file')
        with path.open('rb') as stream:
            body = stream.read(65537)
        require(len(body) <= 65536 and hashlib.sha256(body).hexdigest() == pin, 'issuer_model_pin')
        value = decode(body)
        valid = {feature_pin(dict(zip(FIELDS, (True, *bits), strict=True)))
                 for bits in itertools.product((False, True), repeat=2)}
        require(type(value) is dict and set(value) == {'schema', 'profile', 'minimum_support', 'rows',
                'dependencies', 'automatic_enforcement_allowed', 'review_retained', 'identity_or_authority_verified'}
                and value['schema'] == SCHEMA and value['profile'] == PROFILE
                and type(value['minimum_support']) is int and value['minimum_support'] == 5
                and value['dependencies'] == dependencies and value['automatic_enforcement_allowed'] is False
                and value['review_retained'] is True and value['identity_or_authority_verified'] is False
                and type(value['rows']) is dict and 0 < len(value['rows']) <= 4
                and set(value['rows']) <= valid, 'issuer_model_scope')
        for counts in value['rows'].values():
            require(type(counts) is list and len(counts) == 2
                    and all(type(n) is int and 0 <= n <= 1000000 for n in counts), 'issuer_model_counts')
        head = cls(dependencies)
        head.rows, head.frozen = value['rows'], True
        return head

    def refine(self, previous, observation, *, source_sha256, ordinal, raw):
        require(self.frozen and isinstance(previous, OperationDecision) and previous.automatic_enforcement_allowed is False,
                'issuer_previous')
        require(type(previous.alert) is bool and type(previous.review) is bool
                and all(type(v) in {int, float} and math.isfinite(v) and 0 <= v <= 1
                        for v in (previous.baseline_score, previous.score)), 'issuer_previous_values')
        if observation is None:
            return previous
        require(isinstance(observation, IssuerObservation) and observation.source_sha256 == source_sha256
                and observation.ordinal == ordinal and observation.line_sha256 == hashlib.sha256(raw.encode()).hexdigest()
                and observation.human_or_device_identity_verified is False and observation.authority_verified is False,
                'issuer_current_binding')
        if (observation.protected or previous.baseline_score >= .95 or previous.reason not in REASONS
                or not previous.alert):
            return previous
        counts = self.rows.get(observation.projection_sha256)
        if counts is None or counts[0] < 5 or counts[1]:
            return previous
        return OperationDecision(previous.baseline_score, previous.baseline_score, False, True,
                                 'learned_vpn_issuer_relation_review')
