from pathlib import Path


def test_local_image_runs_as_non_root_with_healthcheck() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "USER secops" in dockerfile
    assert "--uid 10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "ANALYZER_MODE=rule" in dockerfile


def test_compose_uses_cost_free_restricted_rule_mode() -> None:
    compose = Path("compose.yaml").read_text(encoding="utf-8")

    assert "ANALYZER_MODE: rule" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "env_file" not in compose


def test_docker_smoke_script_never_loads_api_key() -> None:
    script = Path("scripts/test-docker.ps1").read_text(encoding="utf-8")

    assert "ANALYZER_MODE=rule" in script
    assert ".env.local" not in script
    assert "OPENAI_API_KEY" not in script
    assert "uid=10001,gid=10001,mode=0700" in script


def test_docker_test_image_normalizes_windows_file_modes() -> None:
    dockerfile = Path("Dockerfile.test").read_text(encoding="utf-8")

    assert 'find app -type f -name "*.py" -exec chmod 0644' in dockerfile
    assert 'find tests -type f -name "*.py" -exec chmod 0644' in dockerfile
