import copy
import json

import pytest
import yaml

from scripts import continuous_mtls_runtime as runtime
from scripts import runtime_release as release


@pytest.fixture
def tree(tmp_path):
    for name in release.FIXED:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("source\n", encoding="utf-8")
    (tmp_path / "infra/pep/tools.lock.json").write_text(json.dumps({"platform": "linux/amd64", "tools": {
        "nginx": {"image": "nginx@sha256:" + "a" * 64}}}), encoding="utf-8")
    for name in ("app/data/policy.yaml", "app/static/app.js", "app/service.py", "scripts/helper.py",
                 "infra/runtime/requirements/runtime.lock"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"text\n")
    return tmp_path


@pytest.mark.parametrize("name", ["app/data/policy.yaml", "app/static/app.js", "app/service.py",
    "scripts/helper.py", "infra/runtime/requirements/runtime.lock", "Dockerfile", ".dockerignore"])
def test_any_changed_deployment_input_refuses_saved_release(tree, name):
    old = release.capture(tree, {"environment": {"ANALYZER_MODE": "rule"}})
    (tree / name).write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(old, release.capture(tree, {"environment": {"ANALYZER_MODE": "rule"}}))


@pytest.mark.parametrize("operation", ["add", "remove", "rename"])
def test_source_inventory_change_is_not_missed(tree, operation):
    old = release.capture(tree, {})
    if operation == "add":
        (tree / "scripts/new_helper.py").write_text("new", encoding="utf-8")
    elif operation == "remove":
        (tree / "scripts/helper.py").unlink()
    else:
        (tree / "scripts/helper.py").rename(tree / "scripts/renamed.py")
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(old, release.capture(tree, {}))


def test_text_checkout_line_endings_are_portable(tree):
    before = release.capture(tree, {})
    (tree / "app/service.py").write_bytes(b"text\r\n")
    assert release.verify(before, release.capture(tree, {})) == before["sha256"]


def test_ignored_bytecode_and_unrelated_docs_are_not_inputs(tree):
    before = release.capture(tree, {})
    (tree / "scripts/__pycache__").mkdir()
    (tree / "scripts/__pycache__/helper.py").write_text("cache", encoding="utf-8")
    (tree / "README.md").write_text("documentation", encoding="utf-8")
    assert release.verify(before, release.capture(tree, {})) == before["sha256"]


def test_topology_environment_network_and_limits_are_frozen(tree):
    old = release.capture(tree, {"auth": "mtls", "network": "none", "cpus": 1})
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(old, release.capture(tree, {"auth": "disabled", "network": "host", "cpus": 2}))


@pytest.mark.parametrize("bad", [None, {}, {"payload": {}, "sha256": "0" * 64}])
def test_missing_or_tampered_release_is_not_automatically_resealed(tree, bad):
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(bad, release.capture(tree, {}))


def test_changing_payload_and_rehashing_still_does_not_match_current_inputs(tree):
    current = release.capture(tree, {})
    changed = copy.deepcopy(current)
    changed["payload"]["files"]["Dockerfile"] = "b" * 64
    changed["sha256"] = release.digest(changed["payload"])
    with pytest.raises(ValueError, match="release_changed"):
        release.verify(changed, current)


@pytest.mark.parametrize("image,platform", [("nginx:latest", "linux/amd64"),
    ("nginx@sha256:" + "a" * 63, "linux/amd64"), ("nginx@sha256:" + "a" * 64, "linux/arm64")])
def test_mutable_or_wrong_platform_proxy_selection_refused(tree, image, platform):
    (tree / "infra/pep/tools.lock.json").write_text(json.dumps({"platform": platform,
        "tools": {"nginx": {"image": image}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="digest_platform"):
        release.capture(tree, {})


def test_source_symlink_does_not_import_files_outside_bundle(tree, tmp_path):
    target = tmp_path / "external.txt"
    target.write_text("external", encoding="utf-8")
    path = tree / "scripts/link.py"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")
    with pytest.raises(ValueError, match="symlink"):
        release.capture(tree, {})


@pytest.fixture
def image():
    return {"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "amd64",
            "RepoDigests": ["nginx@sha256:" + "b" * 64]}


@pytest.mark.parametrize("field,value", [("Id", "mutable:tag"), ("Os", "windows"),
                                       ("Architecture", "arm64"), ("RepoDigests", [])])
def test_image_platform_and_registry_identity_verified(image, field, value):
    image[field] = value
    with pytest.raises(ValueError, match="image_identity"):
        release.image_identity(image, "sha256:" + "a" * 64, "nginx@sha256:" + "b" * 64)


def test_tag_replacement_is_not_accepted_as_locked_image(image):
    with pytest.raises(ValueError, match="image_identity"):
        release.image_identity(image, "sha256:" + "c" * 64)
    assert release.image_identity(image, image["Id"], image["RepoDigests"][0]) == image["Id"]


@pytest.fixture
def instance(tree, monkeypatch):
    monkeypatch.setattr(runtime, "ROOT", tree)
    directory = tree / "runtime/c02/locked"
    directory.mkdir(parents=True)
    obj = runtime.Runtime(directory)
    project = "kmtls-012345abcdef"
    obj.state = {"schema": "continuous-mtls-runtime-1", "project": project, "image": project + "-app",
        "volumes": {n: project + "-" + n for n in runtime.VOLUMES}, "initialized": True,
        "image_id": "sha256:" + "a" * 64, "nginx_image_id": "sha256:" + "b" * 64}
    obj.state["release"] = obj.release_inputs()
    obj.save()
    return obj


def test_generated_compose_uses_only_pinned_local_images_and_no_interpolation(instance):
    instance.write_manifest()
    spec = yaml.safe_load(instance.manifest.read_text())
    for name, service in spec["services"].items():
        assert service["image"] == instance.state["nginx_image_id" if name == "proxy" else "image_id"]
        assert service["pull_policy"] == "never" and service["platform"] == "linux/amd64"
        assert "${" not in json.dumps(service) and "env_file" not in service
    assert instance.empty_env.read_bytes() == b""


def test_resume_with_changed_source_never_calls_docker(instance, monkeypatch):
    (runtime.ROOT / "scripts/helper.py").write_text("new code", encoding="utf-8")
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: pytest.fail("must reject before Docker"))
    with pytest.raises(ValueError, match="release_changed"):
        instance.up()


def test_legacy_descriptor_can_be_loaded_for_cleanup_but_cannot_start(instance, monkeypatch):
    instance.state.pop("release")
    instance.save()
    assert instance.load()["initialized"]
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: pytest.fail("legacy start must not call Docker"))
    with pytest.raises(ValueError, match="release_changed"):
        instance.up()


def test_cleanup_manifest_does_not_consume_current_tool_lock(instance):
    (runtime.ROOT / "infra/pep/tools.lock.json").write_text("corrupt", encoding="utf-8")
    assert instance.load()["initialized"]
    assert yaml.safe_load(instance.manifest.read_text())["services"]["proxy"]["image"] == instance.state["nginx_image_id"]


def test_bad_tag_or_missing_image_is_rejected_before_compose_up(instance, monkeypatch, image):
    image["Id"] = "sha256:" + "f" * 64
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: json.dumps([image]))
    monkeypatch.setattr(instance, "compose", lambda *a, **kw: pytest.fail("image mismatch must not start services"))
    with pytest.raises(ValueError, match="image_identity"):
        instance.up()


def test_proxy_volume_drift_does_not_start_or_overwrite_configuration(instance, monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: calls.append(a[0]) or "0" * 64)
    with pytest.raises(runtime.RuntimeFailure, match="public_configuration_changed"):
        instance.verify_public_configuration()
    assert len(calls) == 1
    assert "readonly" in " ".join(calls[0]) and "--network" in calls[0]
    assert instance.state["volumes"]["config"] in " ".join(calls[0])


def test_pinned_proxy_configuration_matches_on_resume(instance, monkeypatch):
    expected = instance.state["release"]["payload"]["files"]["infra/mtls/all-hops-nginx.conf"]
    monkeypatch.setattr(runtime, "command", lambda *a, **kw: expected + "\n")
    instance.verify_public_configuration()
