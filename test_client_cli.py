from pathlib import Path
import subprocess
import tempfile
import pytest

# run with python3 -m pytest -v test_client_cli.py



PROJECT_ROOT = Path(__file__).resolve().parent
CLIENT_ROOT = PROJECT_ROOT.parent / "Bittorrent-peer-linking--Client"
CLIENT = CLIENT_ROOT / "src" / "build" / "btclient"
TORRENT = CLIENT_ROOT / "docker-assets" / "torrents" / "bigAWS.torrent"

def run_client(*args):
    with tempfile.TemporaryDirectory(prefix="btclient-test-") as working_directory:
        return subprocess.run(
            [str(CLIENT), *args],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=working_directory,
        )

@pytest.mark.parametrize("interval", ["-1", "abc", ""])
def test_invalid_snapshot_interval(interval):
    result = run_client("--snapshot-interval-ms", interval, "-f", str(TORRENT))
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "missing value for --snapshot-interval-ms" in output.lower() or "stoll" in output.lower() or "snapshot interval must be" in output.lower()

def test_invalid_role():
    result = run_client("--node-role", "invalidrole", "-f", str(TORRENT))
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "node role must be victim, adversary, or unknown" in output.lower()

def test_missing_torrent_file():
    result = run_client("-f", "does-not-exist.torrent")
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "torrent file not found" in output.lower() or "no such file" in output.lower()

@pytest.mark.parametrize("time", ["-1", "abc", ""])
def test_invalid_time(time):
    result = run_client("-t", time, "-f", str(TORRENT))
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "runtime seconds must be" in output.lower() or "stoi" in output.lower()


def test_no_arguments():
    result = run_client()
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "usage" in output.lower() and "torrent source" in output.lower()

def test_invalid_argument():
    result = run_client("--unknownargument")
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "unknown argument" in output.lower()

def test_help_output():
    result = run_client("-h")
    output = result.stdout + result.stderr

    assert result.returncode == 0
    assert "usage" in output.lower()

@pytest.mark.parametrize("port", ["-1", "65536", "77777777777", "abc", ""])
def test_invalid_port_is_rejected(port):
    result = run_client("-p", port, "-f", str(TORRENT))
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "port" in output.lower()
