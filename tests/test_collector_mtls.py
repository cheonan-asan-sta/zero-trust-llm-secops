import json
import ssl

import pytest

from scripts import local_signal_collector as collector
from scripts import mtls_transport


@pytest.fixture
def profile_path(tmp_path):
    path = tmp_path / "client.json"
    path.write_text(json.dumps({"host": "gateway", "port": 8443}))
    return path


@pytest.mark.parametrize("url", [
    "http://gateway:8443", "https://other:8443", "https://gateway:443",
    "https://user:secret@gateway:8443", "https://gateway:8443/path",
    "https://gateway:8443/?q=1", "https://gateway:8443/#part",
])
def test_tls_collector_rejects_destination_mismatch_before_sending(monkeypatch, profile_path, url):
    monkeypatch.setattr(mtls_transport, "request", lambda *a, **k: pytest.fail("sent to wrong destination"))
    with pytest.raises(ValueError):
        collector._post(url, "/zero-trust/signals/inbox", {}, tls_profile=profile_path)


def test_collector_tls_failure_never_uses_http(monkeypatch, profile_path):
    def fail(*args, **kwargs):
        raise ssl.SSLError("server_pin_rejected")
    monkeypatch.setattr(mtls_transport, "request", fail)
    monkeypatch.setattr(collector, "build_opener", lambda *a: pytest.fail("HTTP fallback"))
    with pytest.raises(ssl.SSLError):
        collector._post("https://gateway:8443", "/zero-trust/signals/inbox", {}, tls_profile=profile_path)


def test_collector_decodes_tls_receipt_without_retry(monkeypatch, profile_path):
    calls = []
    def send(path, target, data, headers, **kwargs):
        calls.append((path, target, data, headers))
        kwargs["observed"].update(tls_version="TLSv1.3")
        return 202, b'{"receipt_id":"public-receipt"}'
    monkeypatch.setattr(mtls_transport, "request", send)
    observed = {}
    assert collector._post("https://gateway:8443/", "/zero-trust/signals/inbox", {"signature": "test"},
        tls_profile=profile_path, observed=observed) == (202, {"receipt_id": "public-receipt"})
    assert len(calls) == 1 and calls[0][1] == "/zero-trust/signals/inbox"
    assert observed == {"tls_version": "TLSv1.3"}


def test_collector_config_error_never_uses_http(monkeypatch, profile_path):
    profile_path.write_text("{")
    monkeypatch.setattr(collector, "build_opener", lambda *a: pytest.fail("HTTP fallback"))
    with pytest.raises(ValueError):
        collector._post("https://gateway:8443", "/zero-trust/signals/inbox", {}, tls_profile=profile_path)


def test_mtls_demo_requires_separate_access_profile_before_reading_signing_key(tmp_path, profile_path):
    with pytest.raises(ValueError, match="separate protected-access"):
        collector.demonstrate(tmp_path, "https://gateway:8443", "local", tls_profile=profile_path)


def test_all_hops_continuous_signal_uses_collector_identity_not_operator_shortcut(monkeypatch):
    from scripts.compare_pep import Lab
    from scripts.test_all_hops_mtls import AllHopsLab
    lab = object.__new__(AllHopsLab)
    lab.prefix, lab.actors, lab.report = "trial", {"collector": "collector-actor"}, {"runs": [{}]}
    sent = []
    def send(self, container, request):
        sent.append((container, request))
        return {"status": 202, "tls_version": "TLSv1.3"}
    monkeypatch.setattr(Lab, "request", send)
    result = lab.request("trial-core-a", {"method": "POST", "path": "/zero-trust/signals/inbox", "payload": {}})
    assert result["status"] == 202 and sent[0][0] == "collector-actor"
    assert sent[0][1]["collector_transport"] and sent[0][1]["tls_profile"] == "/tls/profile.json"
    assert lab.report["runs"][0]["continuous_collector_transport"]["status"] == 202
