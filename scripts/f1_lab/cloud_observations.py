"""Partial historical CloudTrail facts. No invented posture, active state or approval."""

import hashlib
import json
from datetime import datetime

from scripts.f1_lab.native_jsonl import require

LABEL_FIELDS = {'should_sample', 'attack_name', 'ground_truth', 'Suspicious'}
KINDS = {'IAMUser', 'AssumedRole', 'Root', 'FederatedUser', 'AWSService', 'AWSAccount', 'IdentityCenterUser', 'Unknown'}
ALLOWED = {'eventID', 'eventTime', 'eventSource', 'eventName', 'userIdentity', 'readOnly', 'managementEvent',
           'eventType', 'eventCategory', 'resources', 'errorCode', 'sourceIPAddress'}


def text(value, maximum=512):
    require(isinstance(value, str) and 0 < len(value) <= maximum and '\x00' not in value, 'cloud_text')
    return value


def reference(kind, value):
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256((kind+':'+value).encode()).hexdigest()


def moment(value):
    if value is None:
        return None
    instant = datetime.fromisoformat(text(value, 64))
    require(instant.tzinfo is not None, 'cloud_timezone')
    return instant.timestamp()


def label(raw):
    value, attack = raw.get('should_sample'), raw.get('attack_name')
    if type(value) is not bool:
        return {'truth': None, 'reason': 'missing_or_nonboolean_should_sample', 'attack_name': None}
    if value and (not isinstance(attack, str) or not attack.strip()):
        return {'truth': None, 'reason': 'attack_name_missing', 'attack_name': None}
    if not value and attack not in (None, ''):
        return {'truth': None, 'reason': 'conflicting_attack_name', 'attack_name': None}
    return {'truth': value, 'reason': 'explicit_publisher_annotation', 'attack_name': attack if value else None}


def observation(raw):
    require(isinstance(raw, dict) and not LABEL_FIELDS & raw.keys(), 'cloud_truth_in_inference')
    require(set(raw) <= ALLOWED, 'cloud_observation_field_population')
    name, source = text(raw.get('eventName'), 128), text(raw.get('eventSource'), 128)
    identity = raw.get('userIdentity')
    identity = identity if isinstance(identity, dict) else {}
    context = identity.get('sessionContext')
    context = context if isinstance(context, dict) else {}
    attributes = context.get('attributes')
    attributes = attributes if isinstance(attributes, dict) else {}
    issuer = context.get('sessionIssuer')
    issuer = issuer if isinstance(issuer, dict) else {}
    mfa = attributes.get('mfaAuthenticated')
    if type(mfa) is bool:
        mfa_used = mfa
    elif isinstance(mfa, str) and mfa in {'true', 'false'}:
        mfa_used = mfa == 'true'
    else:
        mfa_used = None
    for field in ('readOnly', 'managementEvent'):
        require(raw.get(field) is None or type(raw[field]) is bool, 'cloud_boolean_observation')
    resources = raw.get('resources')
    require(resources is None or isinstance(resources, list) and len(resources) <= 1024, 'cloud_resources')
    resource_refs, resource_types = [], set()
    if resources is not None:
        for resource in resources:
            require(isinstance(resource, dict), 'cloud_resource_object')
            if isinstance(resource.get('type'), str):
                resource_types.add(text(resource['type'], 128))
            resource_ref = reference('resource', resource.get('ARN', resource.get('arn')))
            if resource_ref:
                resource_refs.append(resource_ref)
    kind = identity.get('type')
    kind = kind if isinstance(kind, str) and kind in KINDS else 'Unknown'
    event_time = moment(raw.get('eventTime'))
    creation_time = moment(attributes.get('creationDate'))
    age = event_time-creation_time if event_time is not None and creation_time is not None and event_time >= creation_time else None
    features = {'api_name': name, 'event_source': source, 'principal_kind': kind,
                'session_mfa_used': mfa_used, 'session_issuer_present': bool(issuer),
                'read_only': raw.get('readOnly'), 'management_event': raw.get('managementEvent'),
                'api_error_present': isinstance(raw.get('errorCode'), str) and bool(raw['errorCode']),
                'resource_count': len(resources) if resources is not None else None,
                'resource_types': sorted(resource_types), 'historical_session_age_seconds': age}
    # These remain unavailable; an IAM role or a completed API call is not an
    # independently verified owner policy, active identity, or device verdict.
    missing = dict.fromkeys(('identity_active', 'device_managed', 'device_healthy', 'resource_required_role',
                             'business_approval', 'mfa_failure', 'download_volume_mb'))
    return {'features': features, 'unavailable_claims': missing,
            'provenance': {'event_time': event_time, 'event_reference': reference('event', raw.get('eventID')),
                           'principal_reference': reference('principal', identity.get('principalId')),
                           'issuer_reference': reference('issuer', issuer.get('arn')),
                           'source_ip_reference': reference('ip', raw.get('sourceIPAddress')),
                           'resource_references': resource_refs},
            'authority': 'historical public-source assertion; no live cryptographic authority verified',
            'access_grants': 0, 'session_changes': 0}


def partition(raw):
    require(isinstance(raw, dict), 'cloud_record_object')
    gold = label(raw)
    # An allowlist prevents nested request bodies, response credentials and
    # unknown annotation fields from being copied into this observation view.
    view = {key: raw[key] for key in ALLOWED if key in raw}
    return observation(view), gold


def case_id(raw, ordinal):
    payload = {'event': raw.get('eventID'), 'ordinal': ordinal}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
