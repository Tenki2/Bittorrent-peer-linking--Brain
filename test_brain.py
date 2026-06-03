from io import BytesIO
from pathlib import Path
import csv
import json
import sys
import pytest
import yaml
import compare_fingerprints
from analyse_session import adversary_observation_writer, find_victim_peer_summaries
from cloud.brain_ingest import create_app
from session_runner import ConfigError, load_session_config

# run with python3 -m pytest -v test_brain.py

def write_text_file(tmp_path: Path, filename: str, content: str) -> Path:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return path


def test_invalid_config_is_rejected(tmp_path):
    config_path = write_text_file(
        tmp_path,
        "badconfig.yaml",
        """
ingest:
  port: not-a-number
  destination_url: http://127.0.0.1:8000/ingest
""",
    )

    with pytest.raises(ConfigError, match="port must be an integer"):
        load_session_config(config_path)



def test_missing_required_config_field_is_rejected(tmp_path):
    config_path = write_text_file(
        tmp_path,
        "missing-field-config.yaml",
        """
ingest:
  port: 8000
""",
    )

    with pytest.raises(ConfigError, match="destination_url is required"):
        load_session_config(config_path)


def test_malformed_yaml_config_is_rejected(tmp_path):
    config_path = write_text_file(
        tmp_path,
        "malformed.yaml",
        """
ingest:
  destination_url: [unterminated
""",
    )

    with pytest.raises(yaml.YAMLError):
        load_session_config(config_path)

@pytest.mark.parametrize("malformed_part", ["state_json", "summary_json"])
def test_ingestion_rejects_malformed_json(tmp_path, malformed_part):
    sessions_root = tmp_path / "sessions"
    app = create_app(sessions_root)
    client = app.test_client()
    parts = {
        "state_json": (BytesIO(b'{"client_label": "adversary-test"}'), "state.json"),
        "event_log": (BytesIO(b""), "events.ndjson"),
        "summary_json": (BytesIO(b'{"session_id": "session-test"}'), "summary.json"),
    }
    parts[malformed_part] = (BytesIO(b"{not-json"), f"{malformed_part}.json")

    response = client.post("/ingest", data=parts)

    assert response.status_code == 400
    assert response.get_json() == {
        "error": f"{malformed_part} must be valid JSON.",
    }
    assert not sessions_root.exists()


def write_fingerprint(analysis_root: Path, session_id: str, victim_label: str, feature_value: int) -> None:
    path = analysis_root / session_id / "fingerprint_features.csv"
    path.parent.mkdir(parents=True)
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["session_id", "victim_label", "victim_host", "feature_value"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "session_id": session_id,
                "victim_label": victim_label,
                "victim_host": "203.0.113.10",
                "feature_value": feature_value,
            }
        )

def test_compare_fingerprints_generates_session_report(tmp_path, monkeypatch):
    analysis_root = tmp_path / "analysis"
    output_dir = tmp_path / "combined"
    write_fingerprint(analysis_root, "session-a", "victim-a", 10)
    write_fingerprint(analysis_root, "session-b", "victim-a", 9)
    write_fingerprint(analysis_root, "session-c", "victim-b", 1)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare_fingerprints.py",
            str(analysis_root),
            "--out",
            str(output_dir),
        ],
    )

    compare_fingerprints.main()

    assert (output_dir / "all_fingerprints.csv").exists()
    assert (output_dir / "pairwise_similarity.csv").exists()
    report_path = output_dir / "linkability_report.md"
    assert report_path.exists()
    assert "# Linkability Report" in report_path.read_text(encoding="utf-8")


def test_analysis_removes_all_zero_rows(tmp_path, monkeypatch):
    victim_ip = "203.0.113.10"
    state = {
        "session_id": "session-test",
        "nodes": [
            {
                "label": "adversary-one",
                "role": "adversary",
                "public_ip": "203.0.113.20",
            },
            {
                "label": "victim-one",
                "role": "victim",
                "public_ip": victim_ip,
            },
        ],
    }
    summary_path = (tmp_path / "brain_data" / "sessions" / state["session_id"] / "adversary-one" / "session_summary.json")
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(
        json.dumps(
            {
                "peer_summaries": [
                    {
                        "peer_ip": victim_ip,
                        "transport": "tcp",
                        "incoming_requests_received": 0,
                        "blocks_uploaded": 0,
                        "total_upload_bytes": 0,
                    },
                    {
                        "peer_ip": victim_ip,
                        "transport": "tcp",
                        "incoming_requests_received": 3,
                        "blocks_uploaded": 2,
                        "total_upload_bytes": 1024,
                        "active_time_ms": 1000,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    monkeypatch.chdir(tmp_path)

    observations = find_victim_peer_summaries(state)
    rows = adversary_observation_writer(state, observations, output_dir)

    assert len(rows) == 1
    with (output_dir / "adversary_observations.csv").open(
        newline="",
        encoding="utf-8",
    ) as csv_file:
        output_rows = list(csv.DictReader(csv_file))
    assert len(output_rows) == 1
    assert output_rows[0]["bytes_uploaded"] == "1024"
