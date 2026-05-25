#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
import yaml # python3 -m pip install pyyaml



PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud.brain_ingest import create_server  # noqa: E402


DEFAULT_DATA_ROOT = PROJECT_ROOT / "brain_data"
DEFAULT_IMAGE = "ghcr.io/tenki2/btclient:dev"
DEFAULT_LAUNCH_TEMPLATE_NAME = "btclient-default"
DEFAULT_LAUNCH_TEMPLATE_VERSION = "$Default"
DEFAULT_IAM_INSTANCE_PROFILE_NAME = "BTclient-instance-profile"
DEFAULT_SSH_USER = "ubuntu"
DEFAULT_SSH_KEY_PATH = PROJECT_ROOT / "cloud" / "aws.pem"
DEFAULT_BOOTSTRAP_MARKER = "/home/ubuntu/bootstrap.finished"
DEFAULT_EC2INIT_PATH = PROJECT_ROOT / "cloud" / "ec2init.sh"
ADVERSARY_STOP_GRACE_SECONDS = 60

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")


class ConfigError(ValueError):
    pass


class RemoteCommandError(RuntimeError):
    def __init__(self, host: str, result: subprocess.CompletedProcess[str]) -> None:
        self.host = host
        self.result = result
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail_parts = []
        if stderr:
            detail_parts.append(stderr)
        if stdout:
            detail_parts.append(stdout)
        detail = "\n".join(detail_parts) or f"exit code {result.returncode}"
        super().__init__(f"SSH command failed on {host}: {detail}")


@dataclass(frozen=True)
class IngestConfig:
    bind_host: str
    port: int
    destination_url: str


@dataclass(frozen=True)
class AwsConfig:
    ssh_user: str
    ssh_key_path: Path
    bootstrap_marker: str
    ec2init_path: Path
    public_ip_attempts: int
    public_ip_sleep_seconds: int
    bootstrap_attempts: int
    bootstrap_sleep_seconds: int


@dataclass(frozen=True)
class DockerConfig:
    image: str
    runtime_seconds: int
    listen_port: int
    torrent_source: str
    snapshot_interval_ms: int
    victim_start_delay_seconds: int
    stop_adversaries_after_victim: bool
    adversary_preseed_source: str
    adversary_preseed_target: str


@dataclass(frozen=True)
class SessionConfig:
    session_id: str
    data_root: Path
    config_path: Path
    ingest: IngestConfig
    aws: AwsConfig
    docker: DockerConfig
    nodes: list[dict[str, Any]]


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def generate_session_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"session-{stamp}"


def resolve_path(value: Any, default: Path) -> Path:
    if value is None:
        path = default
    else:
        path = Path(str(value))
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def require_mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping.")
    return value


def require_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list.")
    return value


def string_value(
    mapping: dict[str, Any],
    key: str,
    default: Optional[str] = None,
    *,
    required: bool = False,
) -> str:
    value = mapping.get(key, default)
    if value is None or str(value).strip() == "":
        if required:
            raise ConfigError(f"{key} is required.")
        return ""
    return str(value).strip()


def int_value(mapping: dict[str, Any], key: str, default: int) -> int:
    value = mapping.get(key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{key} must be an integer.") from None
    if parsed < 0:
        raise ConfigError(f"{key} must be non-negative.")
    return parsed


def bool_value(mapping: dict[str, Any], key: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ConfigError(f"{key} must be a boolean.")


def validate_identifier(value: str, field_name: str) -> None:
    if not SAFE_IDENTIFIER_RE.fullmatch(value):
        raise ConfigError(
            f"{field_name} must match {SAFE_IDENTIFIER_RE.pattern}; got {value!r}."
        )


def load_session_config(config_path: Path) -> SessionConfig:
    with config_path.open("r", encoding="utf-8") as config_file:
        document = yaml.safe_load(config_file) or {}
    root = require_mapping(document, "config")

    session = require_mapping(root.get("session"), "session")
    session_id = string_value(session, "id") or generate_session_id()
    validate_identifier(session_id, "session.id")
    data_root = resolve_path(session.get("data_root"), DEFAULT_DATA_ROOT)

    ingest_doc = require_mapping(root.get("ingest"), "ingest")
    ingest = IngestConfig(
        bind_host=string_value(ingest_doc, "bind_host", "0.0.0.0"),
        port=int_value(ingest_doc, "port", 8000),
        destination_url=string_value(
            ingest_doc,
            "destination_url",
            required=True,
        ),
    )

    aws_doc = require_mapping(root.get("aws"), "aws")
    aws = AwsConfig(
        ssh_user=string_value(aws_doc, "ssh_user", DEFAULT_SSH_USER),
        ssh_key_path=resolve_path(aws_doc.get("ssh_key_path"), DEFAULT_SSH_KEY_PATH),
        bootstrap_marker=string_value(
            aws_doc,
            "bootstrap_marker",
            DEFAULT_BOOTSTRAP_MARKER,
        ),
        ec2init_path=resolve_path(aws_doc.get("ec2init_path"), DEFAULT_EC2INIT_PATH),
        public_ip_attempts=int_value(aws_doc, "public_ip_attempts", 30),
        public_ip_sleep_seconds=int_value(aws_doc, "public_ip_sleep_seconds", 10),
        bootstrap_attempts=int_value(aws_doc, "bootstrap_attempts", 60),
        bootstrap_sleep_seconds=int_value(aws_doc, "bootstrap_sleep_seconds", 10),
    )

    docker_doc = require_mapping(root.get("docker"), "docker")
    docker = DockerConfig(
        image=string_value(docker_doc, "image", DEFAULT_IMAGE),
        runtime_seconds=int_value(docker_doc, "runtime_seconds", 60),
        listen_port=int_value(docker_doc, "listen_port", 51413),
        torrent_source=string_value(
            docker_doc,
            "torrent_source",
            "/opt/torrents/big.torrent",
        ),
        snapshot_interval_ms=int_value(docker_doc, "snapshot_interval_ms", 1000),
        victim_start_delay_seconds=int_value(
            docker_doc,
            "victim_start_delay_seconds",
            10,
        ),
        stop_adversaries_after_victim=bool_value(
            docker_doc,
            "stop_adversaries_after_victim",
            False,
        ),
        adversary_preseed_source=string_value(
            docker_doc,
            "adversary_preseed_source",
            "/opt/preseed/big-file.bin",
        ),
        adversary_preseed_target=string_value(
            docker_doc,
            "adversary_preseed_target",
            "/app/data/big-file.bin",
        ),
    )

    locations = require_mapping(root.get("locations"), "locations")
    if not locations:
        raise ConfigError("locations must contain at least one location.")

    nodes_doc = require_list(root.get("nodes"), "nodes")
    if not nodes_doc:
        raise ConfigError("nodes must contain at least one node.")

    nodes: list[dict[str, Any]] = []
    seen_labels: set[str] = set()
    for index, raw_node in enumerate(nodes_doc):
        node = require_mapping(raw_node, f"nodes[{index}]")
        if "count" in node:
            raise ConfigError("nodes must not use count; each label is one host.")

        label = string_value(node, "label", required=True)
        validate_identifier(label, "node label")
        if label in seen_labels:
            raise ConfigError(f"duplicate node label: {label}")
        seen_labels.add(label)

        location_name = string_value(node, "location", required=True)
        validate_identifier(location_name, "node location")
        if location_name not in locations:
            raise ConfigError(f"node {label} references unknown location {location_name}.")

        role = string_value(node, "role", required=True)
        validate_identifier(role, f"role for node {label}")

        location = require_mapping(locations[location_name], f"locations.{location_name}")
        if "count" in location:
            raise ConfigError("locations must not use count; each label is one host.")

        provider = string_value(location, "provider", required=True)
        row: dict[str, Any] = {
            "label": label,
            "location": location_name,
            "role": role,
            "provider": provider,
            "image": docker.image,
            "container_name": f"btclient-{session_id}-{label}",
            "host_data_dir": f"/opt/btclient/sessions/{session_id}/{label}/data",
            "host_artifacts_dir": (
                f"/opt/btclient/sessions/{session_id}/{label}/artifacts"
            ),
            "bootstrap_finished": False,
        }

        if provider == "aws_ec2":
            row["aws_region"] = string_value(location, "aws_region", required=True)
            row["instance_id"] = None
            row["public_ip"] = None
            row["ssh_host"] = None
        elif provider == "residential":
            row["ssh_host"] = string_value(location, "ssh_host", required=True)
            row["public_ip"] = None
            row["instance_id"] = None
        else:
            raise ConfigError(
                f"locations.{location_name}.provider must be aws_ec2 or residential."
            )

        nodes.append(row)

    if any(node["provider"] == "aws_ec2" for node in nodes) and not aws.ec2init_path.exists():
        raise ConfigError(f"EC2 user-data script does not exist: {aws.ec2init_path}")

    return SessionConfig(
        session_id=session_id,
        data_root=data_root,
        config_path=config_path,
        ingest=ingest,
        aws=aws,
        docker=docker,
        nodes=nodes,
    )


class StateStore:
    def __init__(self, state: dict[str, Any], state_dir: Path) -> None:
        self.state = state
        self.state_dir = state_dir
        self.state_path = state_dir / "session_state.json"
        self.events_path = state_dir / "events.jsonl"

    @classmethod
    def create(cls, config: SessionConfig) -> "StateStore":
        state_dir = (
            config.data_root
            / "sessions"
            / config.session_id
            / "orchestration"
        )
        state_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "session_id": config.session_id,
            "status": "created",
            "created_at": utc_now(),
            "config_path": str(config.config_path),
            "data_root": str(config.data_root),
            "state_dir": str(state_dir),
            "ingest": {
                "bind_host": config.ingest.bind_host,
                "port": config.ingest.port,
                "destination_url": config.ingest.destination_url,
            },
            "aws": {
                "launch_template_name": DEFAULT_LAUNCH_TEMPLATE_NAME,
                "launch_template_version": DEFAULT_LAUNCH_TEMPLATE_VERSION,
                "iam_instance_profile_name": DEFAULT_IAM_INSTANCE_PROFILE_NAME,
                "ssh_user": config.aws.ssh_user,
                "ssh_key_path": str(config.aws.ssh_key_path),
                "bootstrap_marker": config.aws.bootstrap_marker,
                "ec2init_path": str(config.aws.ec2init_path),
            },
            "docker": {
                "image": config.docker.image,
                "runtime_seconds": config.docker.runtime_seconds,
                "listen_port": config.docker.listen_port,
                "torrent_source": config.docker.torrent_source,
                "snapshot_interval_ms": config.docker.snapshot_interval_ms,
                "victim_start_delay_seconds": (
                    config.docker.victim_start_delay_seconds
                ),
                "stop_adversaries_after_victim": (
                    config.docker.stop_adversaries_after_victim
                ),
                "adversary_preseed_source": (
                    config.docker.adversary_preseed_source
                ),
                "adversary_preseed_target": (
                    config.docker.adversary_preseed_target
                ),
            },
            "nodes": config.nodes,
        }
        store = cls(state, state_dir)
        store.save()
        store.event("session_created")
        return store

    @classmethod
    def load(cls, data_root: Path, session_id: str) -> "StateStore":
        state_dir = data_root / "sessions" / session_id / "orchestration"
        state_path = state_dir / "session_state.json"
        if not state_path.exists():
            raise ConfigError(f"session state not found: {state_path}")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        return cls(state, state_dir)

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.state_path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(self.state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp_path.replace(self.state_path)

    def event(self, event_type: str, **fields: Any) -> None:
        entry = {"timestamp": utc_now(), "event": event_type, **fields}
        with self.events_path.open("a", encoding="utf-8") as event_file:
            event_file.write(json.dumps(entry, sort_keys=True) + "\n")

    def set_status(self, status: str, **fields: Any) -> None:
        self.state["status"] = status
        self.state.update(fields)
        self.save()
        self.event(f"status_{status}", **fields)

    def node(self, label: str) -> dict[str, Any]:
        for node in self.state["nodes"]:
            if node["label"] == label:
                return node
        raise KeyError(label)

    def update_node(self, label: str, **fields: Any) -> None:
        node = self.node(label)
        node.update(fields)
        self.save()
        self.event("node_updated", label=label, fields=fields)


class SshRunner:
    def __init__(self, ssh_user: str, ssh_key_path: Path, known_hosts_path: Path) -> None:
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.known_hosts_path = known_hosts_path

    def ensure_ready(self) -> None:
        if not self.ssh_key_path.exists():
            raise ConfigError(f"SSH key does not exist: {self.ssh_key_path}")
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.ssh_key_path, 0o600)
        except OSError as exc:
            raise ConfigError(
                f"Could not restrict SSH key permissions: {self.ssh_key_path}"
            ) from exc

    def run(
        self,
        host: str,
        script: str,
        *,
        env: Optional[dict[str, Any]] = None,
        check: bool = True,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess[str]:
        self.ensure_ready()
        exports = ""
        for key, value in (env or {}).items():
            exports += f"export {key}={shlex.quote(str(value))}\n"
        command = [
            "ssh",
            "-i",
            str(self.ssh_key_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            f"UserKnownHostsFile={self.known_hosts_path}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{self.ssh_user}@{host}",
            "bash -s",
        ]
        try:
            result = subprocess.run(
                command,
                input=exports + script,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or exc.output or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            timeout_detail = f"SSH command timed out after {exc.timeout} seconds"
            if stderr:
                stderr = f"{stderr.rstrip()}\n{timeout_detail}"
            else:
                stderr = timeout_detail
            result = subprocess.CompletedProcess(
                command,
                124,
                stdout=stdout,
                stderr=stderr,
            )
        if check and result.returncode != 0:
            raise RemoteCommandError(host, result)
        return result


def ec2_client(region: str) -> Any:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised only on missing deps
        raise SystemExit("boto3 is required: python3 -m pip install boto3") from exc
    return boto3.client("ec2", region_name=region)


def aws_nodes(nodes: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [node for node in nodes if node["provider"] == "aws_ec2"]


def residential_nodes(nodes: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [node for node in nodes if node["provider"] == "residential"]


class SessionOrchestrator:
    def __init__(self, config: SessionConfig, store: StateStore) -> None:
        self.config = config
        self.store = store
        self.ssh = SshRunner(
            config.aws.ssh_user,
            config.aws.ssh_key_path,
            store.state_dir / "session_known_hosts",
        )

    def run(self) -> int:
        self.store.set_status("preparing_nodes", started_at=utc_now())
        self.prepare_residential_nodes()
        self.launch_aws_nodes()
        self.wait_for_aws_public_ips()
        self.wait_for_aws_bootstrap()

        self.store.set_status("launching_containers", started_at=utc_now())
        started_labels = self.launch_container_waves()
        if not started_labels:
            raise RuntimeError("No bootstrapped nodes were available for container launch.")

        self.store.set_status("waiting_for_containers", started_at=utc_now())
        if self.config.docker.stop_adversaries_after_victim:
            failed_labels = self.wait_for_victim_then_stop_adversaries(started_labels)
        else:
            failed_labels = self.wait_for_containers(started_labels)
        if failed_labels:
            self.store.set_status(
                "container_failed",
                failed_labels=failed_labels,
                finished_at=utc_now(),
            )
            return 1

        self.store.set_status("containers_finished", finished_at=utc_now())
        return 0

    def launch_aws_nodes(self) -> None:
        nodes = aws_nodes(self.store.state["nodes"])
        if not nodes:
            return

        user_data = self.config.aws.ec2init_path.read_text(encoding="utf-8")
        for node in nodes:
            label = node["label"]
            region = node["aws_region"]
            print(f"Launching AWS node {label} in {region}...")
            client = ec2_client(region)
            try:
                run_args: dict[str, Any] = {
                    "MinCount": 1,
                    "MaxCount": 1,
                    "LaunchTemplate": {
                        "LaunchTemplateName": DEFAULT_LAUNCH_TEMPLATE_NAME,
                        "Version": DEFAULT_LAUNCH_TEMPLATE_VERSION,
                    },
                    "UserData": user_data,
                    "TagSpecifications": [
                        {
                            "ResourceType": "instance",
                            "Tags": [
                                {
                                    "Key": "Name",
                                    "Value": (
                                        f"btclient-{self.config.session_id}-{label}"
                                    ),
                                },
                                {
                                    "Key": "bt-session-id",
                                    "Value": self.config.session_id,
                                },
                                {"Key": "bt-node-label", "Value": label},
                                {"Key": "bt-node-role", "Value": node["role"]},
                            ],
                        }
                    ],
                }
                run_args["IamInstanceProfile"] = {
                    "Name": DEFAULT_IAM_INSTANCE_PROFILE_NAME,
                }
                response = client.run_instances(**run_args)
            except Exception as exc:
                self.store.update_node(
                    label,
                    launch_failed_at=utc_now(),
                    launch_error=str(exc),
                )
                raise
            instance_id = response["Instances"][0]["InstanceId"]
            self.store.update_node(
                label,
                instance_id=instance_id,
                launched_at=utc_now(),
            )
            print(f"Launched {instance_id} for {label}.")

    def prepare_residential_nodes(self) -> None:
        for node in residential_nodes(self.store.state["nodes"]):
            label = node["label"]
            ssh_host = node["ssh_host"]
            print(f"Preparing residential node {label} ({ssh_host})...")
            self.ssh.run(
                ssh_host,
                RESIDENTIAL_PREPARE_SCRIPT,
                env={"BT_IMAGE": self.config.docker.image},
                timeout=1800,
            )
            public_ip = self.ssh.run(
                ssh_host,
                "curl -4 -fsS --max-time 10 https://ifconfig.io/ip",
                timeout=30,
            ).stdout.strip()
            self.store.update_node(
                label,
                public_ip=public_ip,
                public_ip_discovered_at=utc_now(),
                bootstrap_finished=True,
                bootstrap_finished_at=utc_now(),
                prepared_at=utc_now(),
            )
            print(f"Residential node {label} is ready.")

    def wait_for_aws_public_ips(self) -> None:
        pending = [node for node in aws_nodes(self.store.state["nodes"]) if not node.get("ssh_host")]
        if not pending:
            return

        clients: dict[str, Any] = {}
        for attempt in range(1, self.config.aws.public_ip_attempts + 1):
            print(
                f"Checking AWS public IPs "
                f"({attempt}/{self.config.aws.public_ip_attempts})..."
            )
            next_pending: list[dict[str, Any]] = []
            for node in pending:
                region = node["aws_region"]
                clients.setdefault(region, ec2_client(region))
                instance = self.describe_instance(clients[region], node["instance_id"])
                public_ip = instance.get("PublicIpAddress")
                if public_ip:
                    self.store.update_node(
                        node["label"],
                        public_ip=public_ip,
                        ssh_host=public_ip,
                        public_ip_discovered_at=utc_now(),
                    )
                    print(f"Found public IP for {node['label']}: {public_ip}")
                else:
                    next_pending.append(node)

            pending = [self.store.node(node["label"]) for node in next_pending]
            if not pending:
                return
            if attempt < self.config.aws.public_ip_attempts:
                time.sleep(self.config.aws.public_ip_sleep_seconds)

        labels = ", ".join(node["label"] for node in pending)
        raise RuntimeError(f"Timed out waiting for public IPs: {labels}")

    def wait_for_aws_bootstrap(self) -> None:
        pending = [
            node
            for node in aws_nodes(self.store.state["nodes"])
            if node.get("ssh_host") and not node.get("bootstrap_finished")
        ]
        if not pending:
            return

        for attempt in range(1, self.config.aws.bootstrap_attempts + 1):
            print(
                f"Checking AWS bootstrap completion "
                f"({attempt}/{self.config.aws.bootstrap_attempts})..."
            )
            next_pending: list[dict[str, Any]] = []
            for node in pending:
                result = self.ssh.run(
                    node["ssh_host"],
                    CHECK_BOOTSTRAP_SCRIPT,
                    env={"BOOTSTRAP_MARKER": self.config.aws.bootstrap_marker},
                    check=False,
                    timeout=30,
                )
                if result.returncode == 0:
                    self.store.update_node(
                        node["label"],
                        bootstrap_finished=True,
                        bootstrap_finished_at=utc_now(),
                    )
                    print(f"AWS bootstrap finished for {node['label']}.")
                elif result.returncode == 2:
                    self.store.update_node(
                        node["label"],
                        bootstrap_failed_at=utc_now(),
                        bootstrap_error=result.stderr.strip()[-4000:],
                    )
                    raise RuntimeError(
                        f"AWS bootstrap failed for {node['label']}: "
                        f"{result.stderr.strip()[-2000:]}"
                    )
                else:
                    next_pending.append(node)
                    print(f"AWS bootstrap still running for {node['label']}.")

            pending = [self.store.node(node["label"]) for node in next_pending]
            if not pending:
                return
            if attempt < self.config.aws.bootstrap_attempts:
                time.sleep(self.config.aws.bootstrap_sleep_seconds)

        labels = ", ".join(node["label"] for node in pending)
        raise RuntimeError(f"Timed out waiting for AWS bootstrap: {labels}")

    @staticmethod
    def describe_instance(client: Any, instance_id: str) -> dict[str, Any]:
        response = client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise RuntimeError(f"Could not describe EC2 instance {instance_id}")
        return reservations[0]["Instances"][0]

    def launch_container_waves(self) -> list[str]:
        nodes = [
            node
            for node in self.store.state["nodes"]
            if node.get("bootstrap_finished") and node.get("ssh_host")
        ]
        adversaries = [node for node in nodes if node["role"] == "adversary"]
        non_adversaries = [node for node in nodes if node["role"] != "adversary"]

        started: list[str] = []
        for node in adversaries:
            self.launch_container(node)
            started.append(node["label"])

        if adversaries and non_adversaries and self.config.docker.victim_start_delay_seconds:
            delay = self.config.docker.victim_start_delay_seconds
            print(f"Waiting {delay} seconds before launching non-adversary nodes...")
            time.sleep(delay)

        for node in non_adversaries:
            self.launch_container(node)
            started.append(node["label"])

        return started

    def launch_container(self, node: dict[str, Any]) -> None:
        label = node["label"]
        runtime_seconds = self.container_runtime_seconds(node)
        print(f"Launching btclient container on {label}...")
        result = self.ssh.run(
            node["ssh_host"],
            RUN_CONTAINER_SCRIPT,
            env={
                "CONTAINER_NAME": node["container_name"],
                "HOST_DATA_DIR": node["host_data_dir"],
                "HOST_ARTIFACTS_DIR": node["host_artifacts_dir"],
                "BT_IMAGE": self.config.docker.image,
                "BT_TORRENT_SOURCE": self.config.docker.torrent_source,
                "BT_RUNTIME_SECONDS": runtime_seconds,
                "BT_LISTEN_PORT": self.config.docker.listen_port,
                "BT_NODE_ROLE": node["role"],
                "BT_SESSION_ID": self.config.session_id,
                "BT_CLIENT_LABEL": label,
                "BT_DESTINATION_URL": self.config.ingest.destination_url,
                "BT_SNAPSHOT_INTERVAL_MS": self.config.docker.snapshot_interval_ms,
                "BT_PRESEED_SOURCE": self.config.docker.adversary_preseed_source,
                "BT_PRESEED_TARGET": self.config.docker.adversary_preseed_target,
            },
            timeout=120,
        )
        container_id = result.stdout.strip().splitlines()[-1]
        self.store.update_node(
            label,
            container_id=container_id,
            container_runtime_seconds=runtime_seconds,
            container_started_at=utc_now(),
        )
        print(f"Started {node['container_name']} on {label}.")

    def container_runtime_seconds(self, node: dict[str, Any]) -> int:
        if (
            self.config.docker.stop_adversaries_after_victim
            and node["role"] == "adversary"
        ):
            return 0
        return self.config.docker.runtime_seconds

    def wait_for_victim_then_stop_adversaries(self, labels: list[str]) -> list[str]:
        adversary_labels = [
            label for label in labels if self.store.node(label)["role"] == "adversary"
        ]
        victim_labels = [
            label for label in labels if self.store.node(label)["role"] != "adversary"
        ]

        failed = self.wait_for_containers(victim_labels)
        if adversary_labels:
            failed.extend(self.gracefully_stop_containers(adversary_labels))
            failed.extend(
                self.wait_for_containers(
                    adversary_labels,
                    timeout=ADVERSARY_STOP_GRACE_SECONDS + 180,
                )
            )
        return failed

    def gracefully_stop_containers(self, labels: list[str]) -> list[str]:
        failed: list[str] = []
        for label in labels:
            node = self.store.node(label)
            self.store.update_node(label, container_graceful_stop_requested_at=utc_now())
            print(f"Gracefully stopping {node['container_name']} on {label}...")
            result = self.ssh.run(
                node["ssh_host"],
                GRACEFUL_STOP_CONTAINER_SCRIPT,
                env={
                    "CONTAINER_NAME": node["container_name"],
                    "STOP_GRACE_SECONDS": ADVERSARY_STOP_GRACE_SECONDS,
                },
                check=False,
                timeout=ADVERSARY_STOP_GRACE_SECONDS + 60,
            )
            fields: dict[str, Any] = {
                "container_graceful_stop_finished_at": utc_now(),
                "container_graceful_stop_return_code": result.returncode,
            }
            if result.stdout.strip():
                fields["container_graceful_stop_stdout"] = result.stdout.strip()[-2000:]
            if result.stderr.strip():
                fields["container_graceful_stop_stderr"] = result.stderr.strip()[-2000:]
            self.store.update_node(label, **fields)
            if result.returncode != 0:
                failed.append(label)
                print(f"Graceful stop failed on {label}.")
            else:
                print(f"Graceful stop completed on {label}.")
        return failed

    def wait_for_containers(
        self,
        labels: list[str],
        *,
        timeout: Optional[int] = None,
    ) -> list[str]:
        failed: list[str] = []
        for label in labels:
            node = self.store.node(label)
            self.store.update_node(label, container_wait_started_at=utc_now())
            print(f"Waiting for {node['container_name']} on {label}...")
            result = self.ssh.run(
                node["ssh_host"],
                WAIT_CONTAINER_SCRIPT,
                env={"CONTAINER_NAME": node["container_name"]},
                check=False,
                timeout=timeout or max(self.config.docker.runtime_seconds + 300, 600),
            )
            output = result.stdout.strip().splitlines()
            exit_code: Optional[int]
            if result.returncode == 0 and output:
                try:
                    exit_code = int(output[-1])
                except ValueError:
                    exit_code = None
            else:
                exit_code = None

            fields: dict[str, Any] = {
                "container_finished_at": utc_now(),
                "container_wait_return_code": result.returncode,
            }
            if exit_code is not None:
                fields["container_exit_code"] = exit_code
            if result.stderr.strip():
                fields["container_wait_stderr"] = result.stderr.strip()[-2000:]
            self.store.update_node(label, **fields)

            if exit_code != 0:
                failed.append(label)
                print(f"Container on {label} failed with exit code {exit_code}.")
            else:
                print(f"Container on {label} finished successfully.")

        return failed


def stop_session(data_root: Path, session_id: str, *, wait: bool = True) -> int:
    store = StateStore.load(data_root, session_id)
    aws_state = store.state.get("aws", {})
    ssh = SshRunner(
        aws_state.get("ssh_user", DEFAULT_SSH_USER),
        Path(aws_state.get("ssh_key_path", DEFAULT_SSH_KEY_PATH)),
        store.state_dir / "session_known_hosts",
    )

    store.set_status("stopping", stop_requested_at=utc_now())

    stop_failures: list[str] = []
    for node in store.state.get("nodes", []):
        if not node.get("container_started_at") and not node.get("container_id"):
            continue
        if not node.get("ssh_host") or not node.get("container_name"):
            continue
        label = node["label"]
        print(f"Removing container on {label} if present...")
        result = ssh.run(
            node["ssh_host"],
            STOP_CONTAINER_SCRIPT,
            env={"CONTAINER_NAME": node["container_name"]},
            check=False,
            timeout=60,
        )
        fields: dict[str, Any] = {
            "container_stop_requested_at": utc_now(),
            "container_stop_return_code": result.returncode,
        }
        if result.stdout.strip():
            fields["container_stop_stdout"] = result.stdout.strip()[-2000:]
        if result.stderr.strip():
            fields["container_stop_stderr"] = result.stderr.strip()[-2000:]
        store.update_node(label, **fields)
        if result.returncode != 0:
            stop_failures.append(label)

    aws_by_region: dict[str, list[str]] = {}
    for node in aws_nodes(store.state.get("nodes", [])):
        if node.get("instance_id"):
            aws_by_region.setdefault(node["aws_region"], []).append(node["instance_id"])

    for region, instance_ids in aws_by_region.items():
        print(f"Terminating AWS instances in {region}: {' '.join(instance_ids)}")
        client = ec2_client(region)
        client.terminate_instances(InstanceIds=instance_ids)
        now = utc_now()
        for node in aws_nodes(store.state.get("nodes", [])):
            if node.get("aws_region") == region and node.get("instance_id") in instance_ids:
                store.update_node(
                    node["label"],
                    termination_requested=True,
                    termination_requested_at=now,
                )

    if wait:
        for region, instance_ids in aws_by_region.items():
            print(f"Waiting for AWS termination in {region}: {' '.join(instance_ids)}")
            ec2_client(region).get_waiter("instance_terminated").wait(
                InstanceIds=instance_ids
            )
            now = utc_now()
            for node in aws_nodes(store.state.get("nodes", [])):
                if (
                    node.get("aws_region") == region
                    and node.get("instance_id") in instance_ids
                ):
                    store.update_node(node["label"], terminated_at=now)

    status = "stopped_with_errors" if stop_failures else "stopped"
    store.set_status(status, stopped_at=utc_now(), stop_failures=stop_failures)
    return 1 if stop_failures else 0


def stop_command_for(config: SessionConfig) -> str:
    command = [
        "python3",
        "session_runner.py",
        "stop",
        "--session-id",
        config.session_id,
    ]
    if config.data_root != DEFAULT_DATA_ROOT:
        command.extend(["--data-root", str(config.data_root)])
    return " ".join(shlex.quote(part) for part in command)


def run_command(config_path: Path) -> int:
    config = load_session_config(config_path)
    store = StateStore.create(config)
    server = create_server(
        config.ingest.bind_host,
        config.ingest.port,
        config.data_root,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    exit_code = 0
    post_container_wait = False

    try:
        print(
            "Brain ingest service listening on "
            f"http://{config.ingest.bind_host}:{config.ingest.port}"
        )
        print(f"Saving artifacts under {config.data_root / 'sessions'}")
        store.set_status("ingest_running", ingest_started_at=utc_now())
        server_thread.start()

        exit_code = SessionOrchestrator(config, store).run()
        post_container_wait = True
        print()
        if exit_code:
            print("Container phase finished with failures.")
        else:
            print("Container phase finished.")
        print("Ingest server is still running; press Ctrl+C when uploads are done.")
        print(f"Stop infrastructure with: {stop_command_for(config)}")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print()
        print("Interrupted by user. No infrastructure cleanup was attempted.")
        print(f"Stop infrastructure with: {stop_command_for(config)}")
        if post_container_wait:
            store.event("ingest_stopped_by_user")
        else:
            store.set_status("interrupted", interrupted_at=utc_now())
            exit_code = 130
    except Exception as exc:
        store.set_status("failed", failed_at=utc_now(), error=str(exc))
        raise
    finally:
        server.shutdown()
        server.server_close()

    return exit_code


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run or stop btclient sessions.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run a session from YAML")
    run_parser.add_argument("config", type=Path, help="sessionconfig.yaml path")

    stop_parser = subparsers.add_parser("stop", help="stop a recorded session")
    stop_parser.add_argument("--session-id", required=True)
    stop_parser.add_argument(
        "--data-root",
        type=Path,
        default=DEFAULT_DATA_ROOT,
        help="Brain data root used for the session",
    )
    stop_parser.add_argument(
        "--no-wait",
        action="store_true",
        help="request EC2 termination without waiting for terminated state",
    )

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "run":
            return run_command(args.config)
        if args.command == "stop":
            data_root = args.data_root
            if not data_root.is_absolute():
                data_root = PROJECT_ROOT / data_root
            return stop_session(data_root, args.session_id, wait=not args.no_wait)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except RemoteCommandError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2


RESIDENTIAL_PREPARE_SCRIPT = r"""
set -euo pipefail

missing=0
for command_name in docker tailscale ip; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "${command_name} is required on residential nodes" >&2
    missing=1
  fi
done

if ((missing)); then
  exit 1
fi

if ip route show default | grep -qi 'tailscale'; then
  echo "default route appears to use Tailscale; refusing to run btclient" >&2
  exit 1
fi

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
else
  echo "docker exists but is not usable by this SSH user or passwordless sudo" >&2
  exit 1
fi

"${docker_cmd[@]}" pull "${BT_IMAGE}"
"""


CHECK_BOOTSTRAP_SCRIPT = r"""
set -euo pipefail

if test -f "${BOOTSTRAP_MARKER}"; then
  exit 0
fi

if command -v cloud-init >/dev/null 2>&1; then
  cloud_status="$(cloud-init status --long 2>&1 || true)"
  if printf '%s\n' "${cloud_status}" | grep -Eq '^status: (done|error)$'; then
    {
      echo "bootstrap marker missing after cloud-init finished"
      echo "${cloud_status}"
      echo
      echo "last cloud-init-output lines:"
      if command -v sudo >/dev/null 2>&1; then
        sudo -n tail -n 80 /var/log/cloud-init-output.log 2>&1 || true
      else
        tail -n 80 /var/log/cloud-init-output.log 2>&1 || true
      fi
    } >&2
    exit 2
  fi
fi

exit 1
"""


RUN_CONTAINER_SCRIPT = r"""
set -euo pipefail

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
else
  echo "docker exists but is not usable by this SSH user or passwordless sudo" >&2
  exit 1
fi

if mkdir -p "${HOST_DATA_DIR}" "${HOST_ARTIFACTS_DIR}" 2>/dev/null; then
  :
elif command -v sudo >/dev/null && sudo -n mkdir -p "${HOST_DATA_DIR}" "${HOST_ARTIFACTS_DIR}"; then
  sudo -n chown "$(id -u):$(id -g)" "${HOST_DATA_DIR}" "${HOST_ARTIFACTS_DIR}"
else
  echo "could not create btclient host directories" >&2
  exit 1
fi

"${docker_cmd[@]}" rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker_args=(
  run
  -d
  --name "${CONTAINER_NAME}"
  --network host
  -v "${HOST_DATA_DIR}:/app/data"
  -v "${HOST_ARTIFACTS_DIR}:/app/artifacts"
  -e "BT_TORRENT_SOURCE=${BT_TORRENT_SOURCE}"
  -e "BT_RUNTIME_SECONDS=${BT_RUNTIME_SECONDS}"
  -e "BT_LISTEN_PORT=${BT_LISTEN_PORT}"
  -e "BT_NODE_ROLE=${BT_NODE_ROLE}"
  -e "BT_SESSION_ID=${BT_SESSION_ID}"
  -e "BT_CLIENT_LABEL=${BT_CLIENT_LABEL}"
  -e "BT_ARTIFACTS_DIR=/app/artifacts"
  -e "BT_SAVE_PATH=/app/data"
  -e "BT_SNAPSHOT_INTERVAL_MS=${BT_SNAPSHOT_INTERVAL_MS}"
)

if [[ -n "${BT_DESTINATION_URL}" ]]; then
  docker_args+=(-e "BT_DESTINATION_URL=${BT_DESTINATION_URL}")
fi

if [[ "${BT_NODE_ROLE}" == "adversary" ]]; then
  docker_args+=(
    -e "BT_PRESEED_SOURCE=${BT_PRESEED_SOURCE}"
    -e "BT_PRESEED_TARGET=${BT_PRESEED_TARGET}"
  )
fi

docker_args+=("${BT_IMAGE}")
"${docker_cmd[@]}" "${docker_args[@]}"
"""


WAIT_CONTAINER_SCRIPT = r"""
set -euo pipefail

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
else
  echo "docker exists but is not usable by this SSH user or passwordless sudo" >&2
  exit 1
fi

"${docker_cmd[@]}" wait "${CONTAINER_NAME}"
"""


GRACEFUL_STOP_CONTAINER_SCRIPT = r"""
set -euo pipefail

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
else
  echo "docker exists but is not usable by this SSH user or passwordless sudo" >&2
  exit 1
fi

"${docker_cmd[@]}" stop --time "${STOP_GRACE_SECONDS}" "${CONTAINER_NAME}"
"""


STOP_CONTAINER_SCRIPT = r"""
set -euo pipefail

if docker info >/dev/null 2>&1; then
  docker_cmd=(docker)
elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
else
  echo "docker exists but is not usable by this SSH user or passwordless sudo" >&2
  exit 1
fi

if "${docker_cmd[@]}" container inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
  "${docker_cmd[@]}" rm -f "${CONTAINER_NAME}" >/dev/null
  echo "removed ${CONTAINER_NAME}"
else
  echo "no container ${CONTAINER_NAME} found"
fi
"""


if __name__ == "__main__":
    raise SystemExit(main())
