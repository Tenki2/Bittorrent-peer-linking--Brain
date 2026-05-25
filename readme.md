# BitTorrent Peer Linking: Brain

Tool for receiving and computing data from the client, as well as orchestrating
data collection sessions.

This repository currently contains a small ingest MVP. It only receives client
artifact uploads and saves them to disk.

No database, auth, queues, dashboard, Docker setup, or analysis is included yet.

## Run locally

This service uses only the Python standard library.

```bash
python3 cloud/brain_ingest.py
```

By default it listens on:

```text
http://127.0.0.1:8000
```

You can override the host, port, or data directory with environment variables:

```bash
BRAIN_HOST=0.0.0.0 BRAIN_PORT=8000 BRAIN_DATA_ROOT=/tmp/brain_data python3 cloud/brain_ingest.py
```

## Endpoints

```text
GET /health
POST /ingest
POST /
```

The client can upload to the base service URL:

```bash
./build/btclient ... --destination-url http://127.0.0.1:8000
```

Both `POST /` and `POST /ingest` accept multipart form-data with these required
file parts:

- `state_json`
- `event_log`
- `summary_json`

`summary_json` and `state_json` must parse as JSON. `event_log` is saved
unchanged as raw NDJSON.

Example:

```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -F state_json=@state.json \
  -F event_log=@session_events.ndjson \
  -F summary_json=@session_summary.json
```

## Saved directory structure

Artifacts are saved under:

```text
brain_data/sessions/<session_id>/<client_id>/
```

The saved files are:

```text
state.json
session_events.ndjson
session_summary.json
ingest_metadata.json
```

If the resolved session/client directory already exists, the service returns
HTTP 409 and refuses to overwrite or merge files.

## Metadata resolution

`session_id` is resolved from uploaded JSON content, never from the request path
or filename. The service checks `summary_json` first, then falls back to
`state_json`. Requests without a usable `session_id` are rejected with HTTP 400.

`client_id` is resolved in this order:

1. `client_label`
2. `hostname`
3. `node_role`
4. remote client IP address seen by the service
5. `unknown_client`

For each JSON field, `summary_json` is checked first, then `state_json`.

Directory names are sanitized to keep only letters, numbers, `_`, `-`, and `.`.
Unsafe runs of characters are replaced with `_`.
