"""Opt-in CA connection failover. Never replay a POST after sending credentials."""

import http.client
import json
import re
import ssl

from scripts.certificate_controller import LifecycleError


def endpoints(directory):
    path = directory / "ca-endpoints.json"
    if not path.exists():
        return ["ca"], 3
    value = json.loads(path.read_bytes())
    hosts = value.get("hosts")
    timeout = value.get("connect_timeout_seconds", 1)
    if (set(value) - {"schema", "hosts", "connect_timeout_seconds"}
            or value.get("schema") != "ca-endpoints-1" or not isinstance(hosts, list)
            or not 2 <= len(hosts) <= 4 or any(not isinstance(h, str)
                or not re.fullmatch(r"ca-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", h) for h in hosts)
            or len(set(hosts)) != len(hosts) or type(timeout) not in {int, float} or not .2 <= timeout <= 3):
        raise LifecycleError("ca_endpoint_configuration")
    return hosts, timeout


def connect(directory, context, *, endpoint=None):
    hosts, timeout = endpoints(directory)
    if endpoint is not None:
        if endpoint not in hosts:
            raise LifecycleError("ca_endpoint_not_registered")
        hosts = [endpoint]
    for host in hosts:
        connection = http.client.HTTPSConnection(host, 9000, context=context, timeout=timeout)
        try:
            connection.connect()  # Chain, hostname, time and EKU before HTTP credentials.
            return connection, host
        except ssl.SSLError:
            connection.close()
            raise  # Authentication failures are never hidden by another endpoint.
        except OSError:
            connection.close()
            if host == hosts[-1]:
                raise LifecycleError("ca_endpoints_unavailable") from None
    raise LifecycleError("ca_endpoints_unavailable")
