from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Optional

from flask import Flask, jsonify, request
from werkzeug.serving import make_server


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(os.getenv("BRAIN_DATA_ROOT", PROJECT_ROOT / "brain_data"))
SESSIONS_ROOT = DATA_ROOT / "sessions"
DEFAULT_HOST = os.getenv("BRAIN_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.getenv("BRAIN_PORT", "8000"))

REQUIRED_PARTS = ("state_json", "event_log", "summary_json")
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


def directory_name_or_none(value: str) -> Optional[str]:
    text = value.strip()
    if not text:
        return None

    if text in {".", ".."}:
        return None

    if "/" in text or "\\" in text or "\x00" in text:
        return None

    return text


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

    session_dir_name = directory_name_or_none(raw_session_id)
    if not session_dir_name:
        raise IngestError(
            "session_id is empty or cannot be used as a directory name."
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

        safe_value = directory_name_or_none(raw_value)
        if safe_value:
            return safe_value, field_name

    if remote_client_ip:
        safe_ip = directory_name_or_none(remote_client_ip)
        if safe_ip:
            return safe_ip, "remote_client_ip"

    return "unknown_client", "fallback"


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


def reject_duplicate_form_parts() -> None:
    seen: set[str] = set()
    for collection in (request.files, request.form):
        for part_name, values in collection.lists():
            if part_name in seen or len(values) > 1:
                raise IngestError(f"Duplicate upload part: {part_name}.")
            seen.add(part_name)


def upload_parts_from_request() -> tuple[dict[str, bytes], dict[str, Optional[str]]]:
    if request.mimetype != "multipart/form-data":
        raise IngestError("Request must be multipart/form-data.")

    reject_duplicate_form_parts()

    parts: dict[str, bytes] = {}
    uploaded_filenames: dict[str, Optional[str]] = {}
    for part_name in REQUIRED_PARTS:
        uploaded_file = request.files.get(part_name)
        if uploaded_file is None:
            raise IngestError(f"Missing required upload part: {part_name}.")

        parts[part_name] = uploaded_file.read()
        uploaded_filenames[part_name] = uploaded_file.filename or None

    return parts, uploaded_filenames


def json_response(payload: dict[str, Any], status_code: HTTPStatus = HTTPStatus.OK):
    return jsonify(payload), int(status_code)


def create_app(sessions_root: Path) -> Flask:
    app = Flask(__name__)

    @app.post("/")
    @app.post("/ingest")
    def ingest():
        try:
            parts, uploaded_filenames = upload_parts_from_request()
            response = ingest_upload(
                parts,
                uploaded_filenames,
                request.remote_addr,
                sessions_root,
            )
            return json_response(response)
        except IngestError as exc:
            return json_response({"error": exc.detail}, exc.status_code)

    @app.errorhandler(HTTPStatus.NOT_FOUND.value)
    def not_found(_error):
        return json_response({"error": "Not found."}, HTTPStatus.NOT_FOUND)

    @app.errorhandler(HTTPStatus.METHOD_NOT_ALLOWED.value)
    def method_not_allowed(_error):
        return json_response({"error": "Not found."}, HTTPStatus.NOT_FOUND)

    return app


class BrainIngestServer:
    def __init__(
        self,
        host: str,
        port: int,
        sessions_root: Path,
    ) -> None:
        self.sessions_root = sessions_root
        self.app = create_app(sessions_root)
        self._server = make_server(host, port, self.app, threaded=True)

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()

    def server_close(self) -> None:
        self._server.server_close()


def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    data_root: Path | str = DATA_ROOT,
) -> BrainIngestServer:
    sessions_root = Path(data_root) / "sessions"
    return BrainIngestServer(host, port, sessions_root)


def run_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    data_root: Path | str = DATA_ROOT,
) -> None:
    server = create_server(host, port, data_root)
    print(f"Brain ingest service listening on http://{host}:{port}")
    print(f"Saving artifacts under {server.sessions_root}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
