"""Source-aware behavioral detection from public telemetry with no enforcement authority."""

import ast
import posixpath
import re
import shlex
from collections import Counter, defaultdict, deque
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from typing import Annotated, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import Field, field_validator

from app.models import StrictModel
from app.services.sigma import SigmaEngine


class PublicActivity(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    kind: str = Field(min_length=1, max_length=160)
    command: str | None = Field(default=None, max_length=8192)
    connection_id: str | None = Field(default=None, max_length=256)
    principal_hash: str | None = Field(default=None, max_length=256)
    resource_hashes: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        default_factory=list, max_length=128
    )
    api_service: str | None = Field(default=None, max_length=160)
    api_action: str | None = Field(default=None, max_length=160)
    error_code: str | None = Field(default=None, max_length=160)
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    download_path: str | None = Field(default=None, max_length=8192)
    destination: str | None = Field(default=None, max_length=8192)

    @field_validator("timestamp")
    @classmethod
    def aware_timestamp(cls, value):
        if value.utcoffset() is None:
            raise ValueError("source event requires a timezone-aware timestamp")
        return value


class PublicSession(StrictModel):
    source: Literal["cowrie", "cloudtrail"]
    original_group_id: str = Field(min_length=1, max_length=256)
    events: list[PublicActivity] = Field(min_length=1, max_length=50000)
    event_hashes: list[str] = Field(default_factory=list, max_length=50000)

    @field_validator("events")
    @classmethod
    def distinct_events(cls, events):
        if len({event.id for event in events}) != len(events):
            raise ValueError("duplicate source event identifier")
        return events


def shell_segments(command, *, preserve_quotes=False):
    """Tokenize recorded text without executing it or treating quoted text as a program."""
    lexer = shlex.shlex(command, posix=not preserve_quotes, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    segments, current = [], []
    for token in tokens:
        if token == "&" and current and current[-1].endswith((">", "<")):
            current.append(token)
        elif token and all(character in ";&|" for character in token):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def shell_program(tokens):
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index < len(tokens) and tokens[index] in {"sudo", "env", "nohup"}:
        index += 1
    return tokens[index:] if index < len(tokens) else []


def path_in_directory(path, directory):
    return posixpath.normpath(path if path.startswith("/") else posixpath.join(directory, path))


def raw_command_parts(command):
    """Keep quoted operators as data and expose only actual command boundaries."""
    commands, operators, quote, escaped, start, index = [], [], None, False, 0, 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
        elif character == "\\" and quote != "'":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character in ";&|\n":
            commands.append(command[start:index])
            end = index + 1
            while end < len(command) and command[end] == character:
                end += 1
            operators.append(command[index:end])
            index, start = end - 1, end
        index += 1
    commands.append(command[start:])
    if quote:
        return [], []
    return commands, operators


def download_pipe_attempt(command):
    """Recognize a real unquoted download-to-shell pipe without executing shell text."""
    commands, operators = raw_command_parts(command)
    for index, operator in enumerate(operators):
        if operator != "|":
            continue
        left, right = shell_segments(commands[index]), shell_segments(commands[index + 1])
        if len(left) != 1 or len(right) != 1:
            continue
        source, sink = shell_program(left[0]), shell_program(right[0])
        if not source or not sink:
            continue
        name = posixpath.basename(source[0])
        if (
            name not in {"curl", "wget"}
            or posixpath.basename(sink[0])
            not in {
                "sh",
                "bash",
                "dash",
                "zsh",
                "ksh",
            }
            or any(argument not in {"-s", "--"} for argument in sink[1:])
        ):
            continue
        if not any(token.startswith(("http://", "https://", "ftp://")) for token in source[1:]):
            continue
        if name == "wget":
            stdout = any(token.endswith("O-") for token in source[1:]) or any(
                token in {"-O", "--output-document"} and source[position + 1] == "-"
                for position, token in enumerate(source[:-1])
            )
        else:
            stdout = not any(
                token in {"-o", "--output"} and source[position + 1] != "-"
                for position, token in enumerate(source[:-1])
            ) and not any(
                (token.startswith("--output=") and token != "--output=-")
                or (token.startswith("-o") and len(token) > 2 and token != "-o-")
                for token in source
            )
        if stdout:
            return True
    return False


def download_target(tokens, directory):
    name = posixpath.basename(tokens[0])
    flags = {"-O", "--output-document"} if name == "wget" else {"-o", "--output"}
    for index, token in enumerate(tokens[:-1]):
        if token in flags:
            return (
                path_in_directory(tokens[index + 1], directory)
                if tokens[index + 1] != "-"
                else None
            )
    if name == "wget":
        urls = [
            token for token in tokens[1:] if token.startswith(("http://", "https://", "ftp://"))
        ]
        if urls:
            try:
                filename = posixpath.basename(urlsplit(urls[0]).path)
            except ValueError:
                return None
            if filename:
                return path_in_directory(filename, directory)
    return None


def reverse_shell(tokens):
    name = posixpath.basename(tokens[0])
    args = tokens[1:]
    if name in {"nc", "ncat", "netcat"}:
        return netcat_shell_attempt(args)
    if name in {"bash", "sh", "dash", "zsh", "ksh"}:
        # Shell -c payloads are parsed separately; a quoted echo is only text.
        return (
            "-c" not in args
            and any(token == "-i" or re.fullmatch(r"-[a-z]*i[a-z]*", token) for token in args)
            and redirected_socket_endpoint(args)
        )
    if name in {"python", "python3"} and "-c" in args:
        position = args.index("-c") + 1
        if position >= len(args):
            return False
        try:
            tree = ast.parse(args[position])
        except (SyntaxError, ValueError, RecursionError):
            return False
        return python_socket_shell_attempt(tree)
    return False


def redirected_socket_endpoint(args):
    for index, token in enumerate(args):
        if (
            not re.fullmatch(r"/dev/(?:tcp|udp)/[^/\s]+/[0-9]{1,5}", token)
            or not 0 < int(token.rsplit("/", 1)[-1]) <= 65535
        ):
            continue
        if index and re.fullmatch(r"\d*[<>]", args[index - 1]):
            return True
        if index >= 2 and args[index - 1] == "&" and re.fullmatch(r"\d*[<>]", args[index - 2]):
            return True
    return False


def shell_redirection_attempt(command):
    """Preserve literal quotes around operators; unwrap only an actual shell -c argument."""
    for segment in shell_segments(command, preserve_quotes=True):
        tokens = shell_program(segment)
        if not tokens or posixpath.basename(tokens[0]) not in SHELL_NAMES:
            continue
        if "-c" not in tokens:
            if reverse_shell(tokens):
                return True
            continue
        position = tokens.index("-c") + 1
        if position >= len(tokens):
            continue
        try:
            unwrapped = shlex.split(tokens[position])
        except ValueError:
            continue
        if len(unwrapped) != 1:
            continue
        for nested in shell_segments(unwrapped[0], preserve_quotes=True):
            nested = shell_program(nested)
            if nested and posixpath.basename(nested[0]) in SHELL_NAMES and reverse_shell(nested):
                return True
    return False


SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh"}


def shell_executable(value):
    return isinstance(value, str) and (
        value in SHELL_NAMES
        or value
        in {f"{directory}/{name}" for directory in ("/bin", "/usr/bin") for name in SHELL_NAMES}
    )


def netcat_shell_attempt(args):
    """Require an actual outbound peer and shell argument, not an option mention."""
    exec_options = {"-e", "-c", "--exec", "--sh-exec"}
    options = [index for index, value in enumerate(args) if value in exec_options]
    if len(options) != 1:
        return False
    index = options[0]
    if index + 1 >= len(args):
        return False
    command = shell_segments(args[index + 1])
    if len(command) != 1 or not shell_executable(command[0][0]):
        return False
    if any(argument not in {"-i", "-l"} for argument in command[0][1:]):
        return False
    remaining = args[:index] + args[index + 2 :]
    positional = []
    cursor = 0
    while cursor < len(remaining):
        value = remaining[cursor]
        if value in {"-n", "-v", "-u", "-4", "-6", "-N"}:
            cursor += 1
        elif value in {"-w", "-s", "-p", "-q"} and cursor + 1 < len(remaining):
            cursor += 2
        elif value.startswith("-"):
            return False
        else:
            positional.append(value)
            cursor += 1
    return bool(
        len(positional) == 2
        and re.fullmatch(r"[A-Za-z0-9_.:%-]+", positional[0])
        and re.fullmatch(r"[0-9]{1,5}", positional[1])
        and 0 < int(positional[1]) <= 65535
    )


def python_socket_shell_attempt(tree):
    """Recognize a direct socket-to-shell sequence; incomplete or conditional snippets abstain."""
    if any(
        not isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.Expr))
        for node in tree.body
    ):
        return False
    sockets, connected, redirected = {}, {}, defaultdict(dict)
    for index, node in enumerate(tree.body):
        call = node.value if isinstance(node, (ast.Assign, ast.Expr)) else None
        if not isinstance(call, ast.Call):
            continue
        try:
            function = ast.unparse(call.func)
        except RecursionError:
            return False
        if (
            function == "socket.socket"
            and isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            variable = node.targets[0].id
            sockets[variable] = index
            connected.pop(variable, None)
            redirected.pop(variable, None)
        if (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.attr == "connect"
            and len(call.args) == 1
        ):
            variable = call.func.value.id
            target = call.args[0]
            if (
                variable in sockets
                and isinstance(target, (ast.Tuple, ast.List))
                and len(target.elts) == 2
                and isinstance(target.elts[0], ast.Constant)
                and isinstance(target.elts[0].value, str)
                and target.elts[0].value
                and isinstance(target.elts[1], ast.Constant)
                and type(target.elts[1].value) is int
                and 0 < target.elts[1].value <= 65535
            ):
                connected[variable] = index
        if function == "os.dup2" and len(call.args) == 2:
            source, destination = call.args
            if (
                isinstance(source, ast.Call)
                and isinstance(source.func, ast.Attribute)
                and source.func.attr == "fileno"
                and isinstance(source.func.value, ast.Name)
                and not source.args
                and isinstance(destination, ast.Constant)
                and type(destination.value) is int
                and destination.value in {0, 1, 2}
            ):
                variable = source.func.value.id
                if variable in connected:
                    redirected[variable][destination.value] = index
        if (
            function
            in {
                "os.system",
                "os.execl",
                "os.execv",
                "pty.spawn",
                "subprocess.call",
                "subprocess.run",
                "subprocess.Popen",
            }
            and call.args
        ):
            argument = call.args[0]
            if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts:
                argument = argument.elts[0]
            if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str):
                continue
            command = shell_segments(argument.value)
            if len(command) != 1 or not shell_executable(command[0][0]):
                continue
            if any(
                0 in fds and 1 in fds and max(fds[0], fds[1]) < index for fds in redirected.values()
            ):
                return True
    return False


def routine_command(tokens, *, pipeline_input=False):
    name = posixpath.basename(tokens[0])
    if tokens[0] not in {name, f"/bin/{name}", f"/usr/bin/{name}", f"/usr/sbin/{name}"}:
        return False
    if any(any(character in token for character in "><$`\n\r") for token in tokens[1:]):
        return False
    if name in {"whoami", "id", "uname", "uptime", "pwd", "ls", "df", "free", "ps"}:
        return True
    if name == "date":
        return all(token in {"-u", "--utc"} or token.startswith("+") for token in tokens[1:])
    if name == "printf" and "-v" in tokens[1:]:
        return False
    if name in {"echo", "printf", "cd", "exit", "logout"}:
        return True
    if name in {"who", "du"}:
        return True
    if name == "systemctl":
        return len(tokens) >= 2 and tokens[1] in {"status", "is-active", "show"}
    if name == "dmesg":
        return not tokens[1:]
    if name == "top":
        return tokens[1:] in [["-bn1"], ["-b", "-n", "1"], ["-b", "-n1"]]
    if name == "ss":
        return all(re.fullmatch(r"-[tulnpa]+", token) for token in tokens[1:])
    if name in {"cat", "head", "tail"}:
        # head/tail with no file are allowed only as a subsequent pipeline stage.
        has_path = any(token.startswith("/") for token in tokens[1:])
        return all(
            token.startswith("-")
            or token.isdigit()
            or token in {"/etc/os-release", "/etc/issue", "/proc/cpuinfo"}
            or (
                name in {"head", "tail"}
                and token.startswith("/var/log/")
                and ".." not in token.split("/")
            )
            for token in tokens[1:]
        ) and (has_path or (name in {"head", "tail"} and pipeline_input))
    return False


def ssh_features(events):
    matched = defaultdict(set)
    failures = deque()
    downloads = defaultdict(dict)
    # An unknown starting directory is a relative anchor, never an invented root.
    directories = defaultdict(lambda: ".")
    missing = set()
    command_count = login_success = 0
    all_commands_routine = True
    connection_ids, closed, authenticated, command_connections = set(), set(), set(), set()
    for event in events:
        connection = event.connection_id
        if not connection:
            missing.add("connection_id")
        else:
            connection_ids.add(connection)
        if event.kind == "cowrie.session.closed" and connection:
            closed.add(connection)
        if event.kind == "cowrie.login.success":
            login_success += 1
            authenticated.add(connection)
        if event.kind == "cowrie.login.failed":
            failures.append(event)
            while failures and (event.timestamp - failures[0].timestamp).total_seconds() > 60:
                failures.popleft()
            if len(failures) >= 5:
                if len(failures) == 5:
                    matched["ssh_auth_burst"].update(item.id for item in failures)
                else:
                    matched["ssh_auth_burst"].add(event.id)
        if event.kind == "cowrie.session.file_download" and connection:
            all_commands_routine = False
            if event.download_path:
                downloads[connection][
                    path_in_directory(event.download_path, directories[connection])
                ] = event.id
            else:
                missing.add("download_path")
        if event.kind != "cowrie.command.input":
            if event.kind not in {
                "cowrie.session.connect",
                "cowrie.session.closed",
                "cowrie.login.success",
                "cowrie.login.failed",
                "cowrie.client.version",
                "cowrie.client.kex",
                "cowrie.client.size",
                "cowrie.session.params",
                "cowrie.log.closed",
            }:
                all_commands_routine = False
            continue
        command_count += 1
        command_connections.add(connection)
        if connection not in authenticated or connection in closed:
            all_commands_routine = False
        if not event.command or not connection:
            missing.add("command")
            all_commands_routine = False
            continue
        segments = shell_segments(event.command)
        parts, operators = raw_command_parts(event.command)
        pipe_sinks = {
            tuple(segment)
            for index, operator in enumerate(operators)
            if operator == "|"
            for segment in shell_segments(parts[index + 1])
        }
        if download_pipe_attempt(event.command):
            matched["ssh_download_execute"].add(event.id)
        if shell_redirection_attempt(event.command):
            matched["ssh_reverse_shell"].add(event.id)
        # Shell substitutions or multiline scripts require a parser beyond this profile.
        if any(character in event.command for character in ("`", "$", "\n", "\r")):
            all_commands_routine = False
        if not segments:
            missing.add("parseable_command")
            all_commands_routine = False
        # Explicit shell -c arguments are executable text; echo arguments remain data.
        expanded = []
        for segment in segments:
            tokens = shell_program(segment)
            if tokens != segment:
                all_commands_routine = False
            if not tokens:
                continue
            if posixpath.basename(tokens[0]) in {"sh", "bash", "dash"} and "-c" in tokens:
                position = tokens.index("-c") + 1
                if position < len(tokens):
                    expanded.extend(shell_segments(tokens[position]))
                    if download_pipe_attempt(tokens[position]):
                        matched["ssh_download_execute"].add(event.id)
            expanded.append(tokens)
        for segment in expanded:
            tokens = shell_program(segment)
            if not tokens:
                continue
            name = posixpath.basename(tokens[0])
            all_commands_routine &= routine_command(
                tokens, pipeline_input=tuple(tokens) in pipe_sinks
            )
            if name not in SHELL_NAMES and reverse_shell(tokens):
                matched["ssh_reverse_shell"].add(event.id)
            if name == "cd" and len(tokens) == 2:
                directories[connection] = path_in_directory(tokens[1], directories[connection])
            if name in {"wget", "curl"}:
                target = download_target(tokens, directories[connection])
                if target:
                    downloads[connection][target] = event.id
                continue
            executable = tokens[0]
            if name in {"sh", "bash", "python", "python3", "perl"}:
                candidates = [token for token in tokens[1:] if not token.startswith("-")]
                executable = candidates[0] if candidates else ""
            resolved = path_in_directory(executable, directories[connection])
            if executable and resolved in downloads[connection]:
                matched["ssh_download_execute"].update([downloads[connection][resolved], event.id])
    normal_supported = bool(
        login_success
        and command_count
        and all_commands_routine
        and not missing
        and connection_ids
        and connection_ids <= closed
        and connection_ids <= authenticated
        and connection_ids <= command_connections
    )
    features = {
        name: bool(matched[name])
        for name in (
            "ssh_auth_burst",
            "ssh_reverse_shell",
            "ssh_download_execute",
        )
    }
    features.update(command_count=command_count, login_success_count=login_success)
    return features, matched, sorted(missing), normal_supported


OBJECT_ACTIONS = {"GetObject", "PutObject", "DeleteObject", "DeleteObjects"}
IDENTITY_CHAIN = {"CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"}


def cloud_features(events):
    matched = defaultdict(set)
    missing = set()
    object_windows = defaultdict(deque)
    object_resources = defaultdict(Counter)
    pending_evidence = defaultdict(deque)
    identity_steps = defaultdict(dict)
    normal_supported = True
    for event in events:
        if not event.principal_hash:
            missing.add("principal_hash")
        if not event.api_action or not event.api_service:
            missing.add("api_action_or_service")
            normal_supported = False
            continue
        action = event.api_action
        if event.outcome == "unknown":
            missing.add("outcome")
        if event.outcome != "success":
            normal_supported = False
            continue
        if event.api_service == "s3.amazonaws.com" and action in OBJECT_ACTIONS:
            if action != "GetObject":
                normal_supported = False
            if not event.resource_hashes:
                missing.add("resource_hashes")
            group = (event.principal_hash, action)
            window = object_windows[group]
            resources = object_resources[group]
            target = tuple(sorted(event.resource_hashes))
            window.append((event, target))
            if target:
                resources[target] += 1
            while window and (event.timestamp - window[0][0].timestamp).total_seconds() > 60:
                _, previous_target = window.popleft()
                if previous_target:
                    resources[previous_target] -= 1
                    if resources[previous_target] == 0:
                        del resources[previous_target]
            pending = pending_evidence[group]
            pending.append(event)
            while pending and (event.timestamp - pending[0].timestamp).total_seconds() > 60:
                pending.popleft()
            # Multiple aliases on one event must not inflate distinct target counts.
            if event.principal_hash and len(window) >= 100 and len(resources) >= 20:
                matched["cloud_object_burst"].update(item.id for item in pending)
                pending.clear()
        elif event.api_service == "iam.amazonaws.com" and action in IDENTITY_CHAIN:
            normal_supported = False
            if not event.resource_hashes:
                missing.add("resource_hashes")
            for resource in event.resource_hashes:
                steps = identity_steps[(event.principal_hash, resource)]
                if action == "CreateUser":
                    steps.clear()
                steps[action] = event
                first, second = steps.get("CreateUser"), steps.get("CreateAccessKey")
                if (
                    event.principal_hash
                    and first
                    and second
                    and action in {"AttachUserPolicy", "PutUserPolicy"}
                    and first.timestamp <= second.timestamp <= event.timestamp
                    and (event.timestamp - first.timestamp).total_seconds() <= 600
                ):
                    matched["cloud_identity_chain"].update([first.id, second.id, event.id])
        elif not (
            action.startswith(("Describe", "List"))
            or action
            in {
                "GetCallerIdentity",
                "GetBucketLocation",
                "GetBucketVersioning",
                "HeadObject",
                "HeadBucket",
            }
        ):
            normal_supported = False
    features = {
        name: bool(matched[name]) for name in ("cloud_object_burst", "cloud_identity_chain")
    }
    return features, matched, sorted(missing), normal_supported and not missing


FEATURE_POLICIES = {
    "cloud_object_burst": ("cloudtrail", "investigate"),
    "cloud_identity_chain": ("cloudtrail", "investigate"),
    "ssh_auth_burst": ("cowrie", "investigate"),
    "ssh_download_execute": ("cowrie", "investigate"),
    "ssh_reverse_shell": ("cowrie", "threat"),
}


def compile_public_rules(documents):
    """Bind each public finding to its exact selector and an explicit interpretation."""
    engine = SigmaEngine.from_documents(documents)
    if not engine.valid:
        raise ValueError("invalid public behavioral rules")
    policies = {}
    features = set()
    for _, document in documents:
        metadata = document.get("x_secops", {}).get("public_detection")
        if not isinstance(metadata, dict) or set(metadata) != {"feature", "disposition"}:
            raise ValueError("public rule requires feature and disposition metadata")
        feature, disposition = metadata["feature"], metadata["disposition"]
        if not isinstance(feature, str) or feature not in FEATURE_POLICIES:
            raise ValueError("unclassified public rule feature")
        source, expected_disposition = FEATURE_POLICIES[feature]
        if disposition != expected_disposition or feature in features:
            raise ValueError("invalid or duplicate public rule interpretation")
        if document["detection"] != {
            "selection": {"unmapped.public.source": source, f"unmapped.public.{feature}": True},
            "condition": "selection",
        }:
            raise ValueError("public rule feature does not match its selector")
        policies[document["id"]] = {"feature": feature, "disposition": disposition}
        features.add(feature)
    return engine, policies


@lru_cache(maxsize=1)
def _public_rule_bundle():
    documents = [
        (path.name, yaml.safe_load(path.read_text()))
        for path in sorted(files("app.data.public_sigma").iterdir(), key=lambda path: path.name)
        if path.name.endswith(".yml")
    ]
    return compile_public_rules(documents)


def public_sigma_engine():
    return _public_rule_bundle()[0]


def public_rule_policies():
    return {rule_id: dict(policy) for rule_id, policy in _public_rule_bundle()[1].items()}


class PublicDetectionService:
    def evaluate(self, session: PublicSession | dict) -> dict:
        session = PublicSession.model_validate(session)
        # Stable sorting retains original record order when timestamps are tied.
        events = sorted(session.events, key=lambda event: event.timestamp)
        features, evidence, missing, normal_supported = (
            ssh_features(events) if session.source == "cowrie" else cloud_features(events)
        )
        fields = {"class_uid": 6003, "unmapped": {"public": {"source": session.source, **features}}}
        engine = public_sigma_engine()
        detection = engine.evaluate_fields(fields)
        policies = public_rule_policies()
        findings = []
        event_ids = {event.id for event in events}
        for match in sorted(detection.matches, key=lambda match: match.rule_id):
            if match.rule_id not in policies:
                raise ValueError("matched public rule has no interpretation")
            policy = policies[match.rule_id]
            identifiers = set(evidence.get(policy["feature"], ()))
            if (
                not features.get(policy["feature"])
                or not identifiers
                or not identifiers <= event_ids
            ):
                raise ValueError("matched public rule has invalid evidence")
            findings.append(
                {"rule_id": match.rule_id, **policy, "evidence_ids": sorted(identifiers)}
            )
        threat_ids = {
            identifier
            for finding in findings
            if finding["disposition"] == "threat"
            for identifier in finding["evidence_ids"]
        }
        candidate_ids = {
            identifier
            for finding in findings
            if finding["disposition"] == "investigate"
            for identifier in finding["evidence_ids"]
        }
        if threat_ids:
            verdict, reason = "threat", "explicit_remote_shell_attempt"
        elif candidate_ids:
            verdict, reason = "unknown", "observed_activity_requires_context"
        elif normal_supported:
            verdict, reason = "normal", "supported_observed_activity_without_match"
        else:
            verdict, reason = "unknown", "missing_or_unsupported_observed_activity"
        return {
            "verdict": verdict,
            "reason": reason,
            "evidence_ids": sorted(threat_ids),
            "candidate_evidence_ids": sorted(candidate_ids),
            "findings": findings,
            "investigation_required": bool(candidate_ids),
            "covered_rules": [item.rule_id for item in engine.summaries()],
            "missing_fields": missing,
            "features": features,
            "normal_profile_supported": normal_supported,
            "sigma": detection.model_dump(mode="json"),
            "enforcement_eligible": False,
            "authority": "reference_only",
            "interpretation": (
                "Volume, provisioning and installation patterns require investigation context. "
                "Explicit remote-shell commands are observed attempts, not proof of successful compromise."
            ),
        }


def evaluate_public_session(session: PublicSession | dict) -> dict:
    return PublicDetectionService().evaluate(session)
