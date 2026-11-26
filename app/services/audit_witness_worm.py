"""Store and retrieve exact witness evidence versions in a provisioned WORM bucket."""

import base64
import re
from contextlib import closing
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError

from app.services import audit_witness_archive as archive
from app.services.audit_transfer import AuditTransferError, require


class WormReadbackError(AuditTransferError):
    def __init__(self, version_id):
        super().__init__("WORM write returned a version but verification did not complete")
        self.version_id = version_id


def _location(bucket, owner, archive_pin):
    require(re.fullmatch(r"[0-9]{12}", owner) and 3 <= len(bucket) <= 63
            and re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", bucket)
            and re.fullmatch(r"[a-f0-9]{64}", archive_pin), "WORM destination or archive pin rejected")
    return {"Bucket": bucket, "ExpectedBucketOwner": owner,
            "Key": f"audit-witness/v1/sha256/{archive_pin}.json"}


def _version(value):
    require(isinstance(value, str) and 0 < len(value) <= 1024 and value != "null",
            "WORM object version ID required")
    return value


def _retention(value):
    require(isinstance(value, datetime) and value.utcoffset() is not None,
            "WORM retention timestamp required")
    return value.astimezone(UTC)


def fetch(client, bucket, owner, version, retain_until, *, archive_pin, key_pin, terminal_pin):
    location = _location(bucket, owner, archive_pin)
    version = _version(version)
    minimum_retention = _retention(retain_until)
    response = client.get_object(**location, VersionId=version)
    with closing(response["Body"]) as body:
        require(response.get("VersionId") == version
                and response.get("ObjectLockMode") == "COMPLIANCE",
                "WORM object version or compliance lock rejected")
        actual_retention = _retention(response.get("ObjectLockRetainUntilDate"))
        require(actual_retention >= minimum_retention, "WORM retention below external minimum")
        size = response.get("ContentLength")
        require(type(size) is int and 0 < size <= archive.MAX_ARCHIVE_BYTES,
                "WORM object size rejected")
        buffer = bytearray()
        while len(buffer) <= size:
            chunk = body.read(min(65536, size + 1 - len(buffer)))
            if not chunk:
                break
            buffer.extend(chunk)
        require(len(buffer) == size, "WORM object length mismatch")
        raw = bytes(buffer)
    result = archive.inspect(raw, archive_pin, key_pin, terminal_pin)
    result.update(bucket=bucket, bucket_owner=owner, object_key=location["Key"],
                  version_id=version, retention_mode="COMPLIANCE",
                  retain_until=actual_retention.isoformat(),
                  retention_active=actual_retention > datetime.now(UTC))
    return raw, result


def upload(client, bucket, owner, retain_until, raw, *, archive_pin, key_pin, terminal_pin):
    archive.inspect(raw, archive_pin, key_pin, terminal_pin)
    location = _location(bucket, owner, archive_pin)
    retain_until = _retention(retain_until)
    require(retain_until > datetime.now(UTC), "WORM upload needs a future retention deadline")
    response = client.put_object(
        **location, Body=raw, IfNoneMatch="*", ContentType="application/json",
        ChecksumAlgorithm="SHA256", ChecksumSHA256=base64.b64encode(bytes.fromhex(archive_pin)).decode(),
        ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=retain_until,
    )
    version = _version(response.get("VersionId"))
    try:
        _, result = fetch(client, bucket, owner, version, retain_until, archive_pin=archive_pin,
                          key_pin=key_pin, terminal_pin=terminal_pin)
        require(result["retention_active"], "WORM retention expired before verification")
    except (AuditTransferError, BotoCoreError, ClientError, OSError, ValueError, TypeError,
            KeyError, RecursionError) as error:
        raise WormReadbackError(version) from error
    return result
