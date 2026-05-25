from pathlib import Path
import csv
import argparse
import json
import math

from session_runner import load_session_config, StateStore, ConfigError


def mean(values: list) -> float:
    values = [float(v) for v in values if v not in (None, "")]
    if not values:
        return 0
    return sum(values) / len(values)


def median(values: list) -> float:
    values = sorted(float(v) for v in values if v not in (None, ""))
    if not values:
        return 0

    mid = len(values) // 2
    if len(values) % 2:
        return values[mid]

    return (values[mid - 1] + values[mid]) / 2


def stddev(values: list) -> float:
    values = [float(v) for v in values if v not in (None, "")]
    if len(values) < 2:
        return 0

    avg = mean(values)
    return (sum((v - avg) ** 2 for v in values) / len(values)) ** 0.5


def entropy(shares: list) -> float:
    total = 0
    for share in shares:
        share = float(share)
        if share > 0:
            total += -(share * math.log2(share))
    return total


def weighted_mean(value_weight_pairs: list[tuple[float, float]]) -> float:
    total_weight = sum(weight for value, weight in value_weight_pairs if value is not None)
    if total_weight == 0:
        return 0

    return sum(value * weight for value, weight in value_weight_pairs if value is not None) / total_weight


def parse_args():
    parser = argparse.ArgumentParser(description="Analyse a session.")
    parser.add_argument(
        "session_id",
        type=str,
        help="Name of the session to analyse.",
    )

    return parser.parse_args()

def get_session_state(session_id: str) -> dict:
    data_root = Path("brain_data")
    try:
        store = StateStore.load(data_root, session_id)
    except ConfigError as exc:
        print(f"Config error: {exc}")
        raise

    state = store.state
    return state


def normalise_session_id(session_id: str) -> str:
    if session_id.startswith("session-"):
        return session_id
    return f"session-{session_id}"


def find_victim_peer_summaries(state: dict) -> list[dict]:
    matches = []
    for node in state["nodes"]: # assumes only one victim in session, vicim is normally at the bottom of the list so need to find ip first before looping again.
        if node["role"] == "victim":
            victim_public_ip = node["public_ip"]
            break

    for node in state["nodes"]:
        if node["role"] != "adversary":
            continue
        label = node["label"]
        summary_path = Path("brain_data") / "sessions" / state["session_id"] / label / "session_summary.json"
        if not summary_path.exists():
            continue

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for peer in summary.get("peer_summaries", []):
            if peer.get("peer_ip") != victim_public_ip:
                continue

            incoming_requests = peer.get("incoming_requests_received") or 0
            blocks_uploaded = peer.get("blocks_uploaded") or 0
            bytes_uploaded = peer.get("total_upload_bytes") or 0

            if incoming_requests == 0 and blocks_uploaded == 0 and bytes_uploaded == 0:
                continue
            matches.append({
                "node_label": label,
                "peer_summary": peer,
            })

    return matches


def fingerprint_features_writer(state: dict, adversary_rows: list[dict], output_dir: Path):
    output_path = Path(output_dir) / "fingerprint_features.csv"

    active_rows = []
    for row in adversary_rows:
        requests = int(row["incoming_request_count"] or 0)
        blocks = int(row["block_uploaded_count"] or 0)
        bytes_uploaded = int(row["bytes_uploaded"] or 0)

        if requests > 0 or blocks > 0 or bytes_uploaded > 0:
            active_rows.append(row)

    total_requests = sum(int(row["incoming_request_count"] or 0) for row in active_rows)
    total_blocks = sum(int(row["block_uploaded_count"] or 0) for row in active_rows)
    total_bytes = sum(int(row["bytes_uploaded"] or 0) for row in active_rows)

    tcp_rows = [row for row in active_rows if row["transport"] == "tcp"]
    utp_rows = [row for row in active_rows if row["transport"] == "utp"]

    tcp_bytes = sum(int(row["bytes_uploaded"] or 0) for row in tcp_rows)
    utp_bytes = sum(int(row["bytes_uploaded"] or 0) for row in utp_rows)

    tcp_requests = sum(int(row["incoming_request_count"] or 0) for row in tcp_rows)
    utp_requests = sum(int(row["incoming_request_count"] or 0) for row in utp_rows)

    shares = []
    for row in active_rows:
        if total_bytes:
            shares.append(int(row["bytes_uploaded"] or 0) / total_bytes)
        else:
            shares.append(0)

    sorted_shares = sorted(shares, reverse=True)
    nonzero_shares = [share for share in shares if share > 0]

    request_rates = [
        row["request_rate_per_second"]
        for row in active_rows
        if row["request_rate_per_second"] not in (None, "")
    ]

    active_durations = [
        row["active_duration_seconds"]
        for row in active_rows
        if row["active_duration_seconds"] not in (None, "")
    ]

    weighted_iat_inputs = []
    for row in active_rows:
        iat = row["mean_request_iat_ms"]
        count = int(row["incoming_request_count"] or 0)

        if iat not in (None, "") and count > 0:
            weighted_iat_inputs.append((float(iat), count))

    median_iats = [
        row["median_request_iat_ms"]
        for row in active_rows
        if row["median_request_iat_ms"] not in (None, "")
    ]

    p95_iats = [
        row["p95_request_iat_ms"]
        for row in active_rows
        if row["p95_request_iat_ms"] not in (None, "")
    ]

    victim_label = None
    victim_host = None
    for node in state["nodes"]:
        if node["role"] == "victim":
            victim_label = node["label"]
            victim_host = node.get("public_ip")
            break

    fingerprint = {
        "session_id": state["session_id"],
        "victim_label": victim_label,
        "victim_host": victim_host,

        "active_adversary_count": len(active_rows),
        "total_requests_seen": total_requests,
        "total_blocks_uploaded": total_blocks,
        "total_bytes_uploaded": total_bytes,

        "mean_bytes_per_active_adversary": round(total_bytes / len(active_rows), 3) if active_rows else 0,
        "mean_requests_per_active_adversary": round(total_requests / len(active_rows), 3) if active_rows else 0,

        "tcp_active_adversary_count": len(tcp_rows),
        "utp_active_adversary_count": len(utp_rows),
        "tcp_bytes_uploaded": tcp_bytes,
        "utp_bytes_uploaded": utp_bytes,
        "tcp_upload_share": round(tcp_bytes / total_bytes, 6) if total_bytes else 0,
        "utp_upload_share": round(utp_bytes / total_bytes, 6) if total_bytes else 0,
        "tcp_request_share": round(tcp_requests / total_requests, 6) if total_requests else 0,
        "utp_request_share": round(utp_requests / total_requests, 6) if total_requests else 0,

        "top1_upload_share": round(sorted_shares[0], 6) if sorted_shares else 0,
        "top3_upload_share": round(sum(sorted_shares[:3]), 6) if sorted_shares else 0,
        "upload_share_entropy": round(entropy(shares), 6),
        "upload_share_stddev": round(stddev(shares), 6),
        "max_upload_share": round(max(shares), 6) if shares else 0,
        "min_nonzero_upload_share": round(min(nonzero_shares), 6) if nonzero_shares else 0,

        "mean_request_rate_per_second": round(mean(request_rates), 3),
        "median_request_rate_per_second": round(median(request_rates), 3),
        "max_request_rate_per_second": round(max([float(v) for v in request_rates]), 3) if request_rates else 0,

        "weighted_mean_request_iat_ms": round(weighted_mean(weighted_iat_inputs), 6),
        "median_of_median_request_iat_ms": round(median(median_iats), 6),
        "max_p95_request_iat_ms": round(max([float(v) for v in p95_iats]), 6) if p95_iats else 0,

        "mean_active_duration_seconds": round(mean(active_durations), 3),
        "median_active_duration_seconds": round(median(active_durations), 3),
        "max_active_duration_seconds": round(max([float(v) for v in active_durations]), 3) if active_durations else 0,
    }

    # Fixed per-adversary features.
    for node in state["nodes"]:
        if node["role"] != "adversary":
            continue

        label = node["label"]
        fingerprint[f"bytes_{label}"] = 0
        fingerprint[f"share_{label}"] = 0
        fingerprint[f"requests_{label}"] = 0
        fingerprint[f"request_rate_{label}"] = 0
        fingerprint[f"tcp_{label}"] = 0
        fingerprint[f"utp_{label}"] = 0

    for row in active_rows:
        label = row["adversary_label"]

        bytes_uploaded = int(row["bytes_uploaded"] or 0)
        requests = int(row["incoming_request_count"] or 0)
        share = float(row["upload_share"] or 0)
        rate = float(row["request_rate_per_second"] or 0)
        transport = row["transport"]

        fingerprint[f"bytes_{label}"] += bytes_uploaded
        fingerprint[f"share_{label}"] += share
        fingerprint[f"requests_{label}"] += requests
        fingerprint[f"request_rate_{label}"] = max(
            fingerprint[f"request_rate_{label}"],
            rate,
        )

        if transport == "tcp":
            fingerprint[f"tcp_{label}"] = 1

        if transport == "utp":
            fingerprint[f"utp_{label}"] = 1

    headings = list(fingerprint.keys())

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headings)
        writer.writeheader()
        writer.writerow(fingerprint)

    print(f"Successfully written fingerprint features to {output_path}")


def adversary_observation_writer(state: dict, adversary_observations: list[dict], output_dir: Path):
    output_path = Path(output_dir) / "adversary_observations.csv"
    rows = []
    headings = ["session_id","adversary_label","victim_host","transport","incoming_request_count","block_uploaded_count","bytes_uploaded","upload_share","active_duration_seconds","request_rate_per_second","mean_request_iat_ms","median_request_iat_ms","p95_request_iat_ms"]

    total_bytes_uploaded = 0
    for observation in adversary_observations:
        peer_summary = observation["peer_summary"]
        total_bytes_uploaded += peer_summary.get("total_upload_bytes") or 0

    for observation in adversary_observations:
        peer_summary = observation["peer_summary"]
        incoming_request_count = peer_summary.get("incoming_requests_received") or 0
        bytes_uploaded = peer_summary.get("total_upload_bytes") or 0

        row = {
            "session_id": state["session_id"],
            "adversary_label": None,
            "victim_host": None,
            "transport": None,
            "incoming_request_count": 0,
            "block_uploaded_count": 0,
            "bytes_uploaded": 0,
            "upload_share": None,
            "active_duration_seconds": None,
            "request_rate_per_second": None,
            "mean_request_iat_ms": None,
            "median_request_iat_ms": None,
            "p95_request_iat_ms": None
        }

        row["adversary_label"] = observation["node_label"]
        row["victim_host"] = peer_summary.get("peer_ip")
        row["transport"] = peer_summary.get("transport")
        row["incoming_request_count"] = incoming_request_count
        row["block_uploaded_count"] = peer_summary.get("blocks_uploaded") or 0
        row["bytes_uploaded"] = bytes_uploaded
        row["mean_request_iat_ms"] = peer_summary.get("mean_incoming_request_gap_ms")
        row["median_request_iat_ms"] = peer_summary.get("p50_incoming_request_gap_ms")
        row["p95_request_iat_ms"] = peer_summary.get("p95_incoming_request_gap_ms")

        active_time_ms = peer_summary.get("active_time_ms")
        if active_time_ms is not None:
            row["active_duration_seconds"] = round(active_time_ms / 1000, 3)
        if row["active_duration_seconds"]:
            row["request_rate_per_second"] = round(
                incoming_request_count / row["active_duration_seconds"],
                3,
            )
        if total_bytes_uploaded:
            row["upload_share"] = round(bytes_uploaded / total_bytes_uploaded, 6)

        rows.append(row)

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headings)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        print(f"Successfully written analysis to {output_path}")
    return rows

def node_summary_writer(state: dict, output_dir: Path):
    output_path = Path(output_dir) / "node_summary.csv"
    rows = []
    headings = ["session_id","node_label","role","ip_address","summary_present","events_present","event_count","parse_error_count","tracker_reply_count","alert_loss_detected","final_state","final_progress","container_exit_code","container_wait_return_code","runtime_seconds"]
    for node in state["nodes"]:
        row = {
            "session_id": state["session_id"],
            "node_label": node["label"],
            "role": node["role"],
            "ip_address": node["public_ip"],
            "summary_present": False,
            "events_present": False,
            "event_count": 0,
            "parse_error_count": 0,
            "tracker_reply_count": 0,
            "alert_loss_detected": 0,
            "final_state": None,
            "final_progress": None,
            "container_exit_code": None,
            "container_wait_return_code": None,
            "runtime_seconds": None
        }
        summary_path = Path("brain_data") / "sessions" / state["session_id"] / node["label"] / "session_summary.json"
        events_path = Path("brain_data") / "sessions" / state["session_id"] / node["label"] / "session_events.ndjson"
        row["container_exit_code"] = node.get("container_exit_code")
        row["container_wait_return_code"] = node.get("container_wait_return_code")
        if summary_path.exists():
            row["summary_present"] = True
            try:
                with summary_path.open("r", encoding="utf-8") as file:
                    summary = json.load(file)
                global_metrics = summary.get("global_metrics", {})
                runtime_ms = global_metrics.get("total_runtime_ms")
                if runtime_ms is not None:
                    row["runtime_seconds"] = round(float(runtime_ms) / 1000, 3)

                torrent_summary = summary.get("torrent", {})
                row["final_progress"] = torrent_summary.get("final_progress")
                row["final_state"] = torrent_summary.get("final_state")
            except json.JSONDecodeError:
                row["summary_present"] = True
                row["final_state"] = "parse_error"

        if events_path.exists():
            row["events_present"] = True
            with events_path.open("r", encoding="utf-8") as file:
                for line in file:
                    try:
                        event = json.loads(line)
                        row["event_count"] += 1
                        event_type = event.get("event_type")
                        if event_type == "tracker_reply":
                            row["tracker_reply_count"] += 1
                        if event_type in {"alerts_dropped", "alert_loss", "alerts_lost"}:
                            row["alert_loss_detected"] += 1
                    except json.JSONDecodeError:
                        row["parse_error_count"] += 1

        else:
            row["event_count"] = None
        rows.append(row)

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headings)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        print(f"Successfully written analysis to {output_path}")






def main():
    args = parse_args()
    session_id = normalise_session_id(args.session_id)
    output_dir = Path("analysis") / session_id
    output_dir.mkdir(parents=True, exist_ok=True)
    state = get_session_state(session_id)
    node_summary_writer(state, output_dir)
    adversary_observations = find_victim_peer_summaries(state)
    adversary_rows = adversary_observation_writer(state, adversary_observations, output_dir)
    fingerprint_features_writer(state, adversary_rows, output_dir)

if __name__ == "__main__":
    raise SystemExit(main())


