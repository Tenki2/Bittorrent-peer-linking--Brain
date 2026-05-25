from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional, cast
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(os.getenv("BRAIN_DATA_ROOT", PROJECT_ROOT / "brain_data"))
SESSIONS_ROOT = DATA_ROOT / "sessions"
DEFAULT_HOST = os.getenv("BRAIN_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.getenv("BRAIN_PORT", "8000"))

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

REQUIRED_PARTS = ("state_json", "event_log", "summary_json")
INGEST_PATHS = {"/", "/ingest"}
PART_TO_FILENAME = {
    "state_json": "state.json",
    "event_log": "session_events.ndjson",
    "summary_json": "session_summary.json",
}
CLIENT_ID_FIELDS = ("client_label", "hostname", "node_role")


class IngestError(Exception):
    status_code = HTTPStatus.BAD_REQUEST

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ConflictError(IngestError):
    status_code = HTTPStatus.CONFLICT


def parse_json_bytes(part_name: str, content: bytes) -> Any:
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise IngestError(f"{part_name} must be valid JSON.") from None


def string_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        text = str(value).strip()
        return text or None
    return None


def find_metadata_value(document: Any, key: str) -> Optional[str]:
    if isinstance(document, dict):
        direct_value = string_or_none(document.get(key))
        if direct_value:
            return direct_value

        for value in document.values():
            found = find_metadata_value(value, key)
            if found:
                return found

    if isinstance(document, list):
        for value in document:
            found = find_metadata_value(value, key)
            if found:
                return found

    return None


def first_metadata_value(
    key: str,
    summary_document: Any,
    state_document: Any,
) -> Optional[str]:
    return (
        find_metadata_value(summary_document, key)
        or find_metadata_value(state_document, key)
    )


def safe_directory_name(value: str) -> Optional[str]:
    text = value.strip()
    if not text:
        return None

    safe = SAFE_NAME_RE.sub("_", text).strip("._-")
    safe = safe[:120].strip("._-")
    if not safe or safe in {".", ".."}:
        return None

    if safe.upper() in WINDOWS_RESERVED_NAMES:
        safe = f"_{safe}"

    return safe


def resolve_session_id(summary_document: Any, state_document: Any) -> tuple[str, str]:
    raw_session_id = first_metadata_value(
        "session_id",
        summary_document,
        state_document,
    )
    if not raw_session_id:
        raise IngestError(
            "Could not determine session_id from summary_json or state_json."
        )

    session_dir_name = safe_directory_name(raw_session_id)
    if not session_dir_name:
        raise IngestError(
            "session_id is empty or cannot be converted into a safe directory name."
        )

    return raw_session_id, session_dir_name


def resolve_client_id(
    summary_document: Any,
    state_document: Any,
    remote_client_ip: Optional[str],
) -> tuple[str, str]:
    for field_name in CLIENT_ID_FIELDS:
        raw_value = first_metadata_value(field_name, summary_document, state_document)
        if not raw_value:
            continue

        safe_value = safe_directory_name(raw_value)
        if safe_value:
            return safe_value, field_name

    if remote_client_ip:
        safe_ip = safe_directory_name(remote_client_ip)
        if safe_ip:
            return safe_ip, "remote_client_ip"

    return "unknown_client", "fallback"


def parse_multipart_upload(
    content_type: str,
    body: bytes,
) -> tuple[dict[str, bytes], dict[str, Optional[str]]]:
    if not content_type:
        raise IngestError("Content-Type header is required.")

    header_blob = (
        f"Content-Type: {content_type}\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n"
    ).encode("utf-8")
    parsed_message = BytesParser(policy=default).parsebytes(header_blob + body)
    message = cast(EmailMessage, parsed_message)

    if message.get_content_type() != "multipart/form-data" or not message.is_multipart():
        raise IngestError("Request must be multipart/form-data.")

    parts: dict[str, bytes] = {}
    uploaded_filenames: dict[str, Optional[str]] = {}

    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        if "form-data" not in disposition:
            continue

        part_name = part.get_param("name", header="content-disposition")
        if not part_name:
            continue
        if part_name in parts:
            raise IngestError(f"Duplicate upload part: {part_name}.")

        payload = part.get_payload(decode=True)
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif payload is None:
            payload_bytes = b""
        else:
            payload_bytes = payload

        parts[part_name] = payload_bytes
        uploaded_filenames[part_name] = part.get_filename()

    for part_name in REQUIRED_PARTS:
        if part_name not in parts:
            raise IngestError(f"Missing required upload part: {part_name}.")

    return parts, uploaded_filenames


def write_artifacts(
    target_dir: Path,
    parts: dict[str, bytes],
    metadata: dict[str, Any],
) -> None:
    target_dir.mkdir(parents=True, exist_ok=False)

    for part_name, filename in PART_TO_FILENAME.items():
        (target_dir / filename).write_bytes(parts[part_name])

    (target_dir / "ingest_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def ingest_upload(
    parts: dict[str, bytes],
    uploaded_filenames: dict[str, Optional[str]],
    remote_client_ip: Optional[str],
    sessions_root: Path = SESSIONS_ROOT,
) -> dict[str, Any]:
    summary_document = parse_json_bytes("summary_json", parts["summary_json"])
    state_document = parse_json_bytes("state_json", parts["state_json"])

    raw_session_id, session_dir_name = resolve_session_id(
        summary_document,
        state_document,
    )
    client_id, client_id_source = resolve_client_id(
        summary_document,
        state_document,
        remote_client_ip,
    )
    target_dir = sessions_root / session_dir_name / client_id

    metadata = {
        "ingest_timestamp": datetime.now(timezone.utc).isoformat(),
        "part_names": list(REQUIRED_PARTS),
        "uploaded_filenames": {
            part_name: uploaded_filenames.get(part_name)
            for part_name in REQUIRED_PARTS
        },
        "resolved_client_id": client_id,
        "resolved_client_id_source": client_id_source,
        "resolved_session_id": raw_session_id,
        "resolved_session_directory": session_dir_name,
        "remote_client_ip": remote_client_ip,
    }

    try:
        write_artifacts(target_dir, parts, metadata)
    except FileExistsError:
        raise ConflictError(
            "Artifacts already exist for this session/client; refusing to "
            "merge or overwrite existing files."
        ) from None

    return {
        "ok": True,
        "client_id": client_id,
        "session_id": raw_session_id,
        "saved_directory": str(target_dir),
    }


class BrainIngestServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        sessions_root: Path,
    ) -> None:
        super().__init__(server_address, BrainIngestHandler)
        self.sessions_root = sessions_root


class BrainIngestHandler(BaseHTTPRequestHandler):
    server_version = "BrainIngest/0.1"

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/health":
            self.send_json(HTTPStatus.OK, {"ok": True})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self) -> None:
        if urlsplit(self.path).path not in INGEST_PATHS:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        try:
            content_length = self.read_content_length()
            body = self.rfile.read(content_length)
            parts, uploaded_filenames = parse_multipart_upload(
                self.headers.get("Content-Type", ""),
                body,
            )
            response = ingest_upload(
                parts,
                uploaded_filenames,
                self.client_address[0] if self.client_address else None,
                cast(BrainIngestServer, self.server).sessions_root,
            )
            self.send_json(HTTPStatus.OK, response)
        except IngestError as exc:
            self.send_json(exc.status_code, {"error": exc.detail})

    def read_content_length(self) -> int:
        raw_content_length = self.headers.get("Content-Length")
        if raw_content_length is None:
            raise IngestError("Content-Length header is required.")

        try:
            content_length = int(raw_content_length)
        except ValueError:
            raise IngestError("Content-Length header must be an integer.") from None

        if content_length < 0:
            raise IngestError("Content-Length header cannot be negative.")

        return content_length

    def send_json(self, status_code: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    data_root: Path | str = DATA_ROOT,
) -> BrainIngestServer:
    sessions_root = Path(data_root) / "sessions"
    return BrainIngestServer((host, port), sessions_root)


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    data_root: Path | str = DATA_ROOT,
) -> None:
    server = create_server(host, port, data_root)
    print(f"Brain ingest service listening on http://{host}:{port}")
    print(f"Saving artifacts under {server.sessions_root}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
