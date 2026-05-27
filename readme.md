# BitTorrent Peer Linking: Brain

Tool for receiving and computing data from the client, as well as orchestrating
data collection sessions.

## Run locally

```bash
python3 cloud/brain_ingest.py
```



## Endpoints

```text
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

