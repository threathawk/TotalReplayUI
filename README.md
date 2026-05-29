# Total Replay — Web Console

**Repository:** [github.com/threathawk/TotalReplay-UI](https://github.com/threathawk/TotalReplay-UI)

Flask dashboard for [Splunk TOTAL-REPLAY](https://github.com/splunk/attack_data/tree/master/total_replay) and [attack_data](https://github.com/splunk/attack_data). Connect to a remote lab over SSH, browse detections, run attack replays, and send events to Splunk HEC.

## Features

- **Local mode** — Browse `security_content` detections and `attack_data` on the machine running this app. Run `total_replay.py` locally (same host as the web UI) or send events via HEC from the web app.
- **Remote mode (SSH)** — Connect to a server where TOTAL-REPLAY, attack_data, and security_content are installed; list catalog over SSH; run `total_replay.py` on the remote host or pull logs and post via HEC from the web app.
- **Attack Test panel** — Multi-select replay detections; live log streaming (SSE); MITRE and use-case metadata in the catalog.
- **Delivery methods**
  - *Local TOTAL-REPLAY CLI* — Runs `total_replay.py` on the machine where the web app runs (local mode).
  - *Remote TOTAL-REPLAY CLI* — Same, but over SSH on a lab server (remote mode).
  - *Web UI HEC* — Reads or downloads attack logs and posts to Splunk from this app (local paths, SSH fetch, or HTTP URLs).
- Optional **SSH tunnel** for HEC when Splunk is only reachable through the same SSH host.
- **Index Map** — Sync Splunk index/sourcetype inventory via `tstats`, map detection sourcetypes to target indexes, and route replays away from the default `test` index.
- Replay logs (SQLite history).

## Install

```bash
cd totalreplay-ui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp data/config.json.example data/config.json
# Edit data/config.json with your Splunk and path settings
python app.py
```

Open http://localhost:5055 (listens on `0.0.0.0:5055` for LAN access).

## Local setup (TOTAL-REPLAY on this machine)

1. Clone [attack_data](https://github.com/splunk/attack_data) and [security_content](https://github.com/splunk/security_content); install TOTAL-REPLAY per [upstream readme](https://github.com/splunk/attack_data/blob/master/total_replay/readme.md).
2. In **Settings** choose **Local filesystem**.
3. Set **TOTAL-REPLAY directory** (e.g. `/opt/attack_data/total_replay`) or only **attack_data path** (auto-detects `total_replay/` underneath).
4. Click **Load paths from local configuration/config.yml** to fill security_content and attack_data paths.
5. Set **Splunk host**, **HEC token**, and **Default delivery method** → *Run TOTAL-REPLAY on this machine (local CLI)*.
6. On **Attack Test**, pick detections and run (sequential option supported).

Splunk must be reachable from this machine when using local CLI (`SPLUNK_HOST` / `SPLUNK_HEC_TOKEN` are passed into `total_replay.py`).

## Remote server setup

On your lab VM ([attack_data](https://github.com/splunk/attack_data) + [security_content](https://github.com/splunk/security_content)):

1. Clone repos and install TOTAL-REPLAY per [upstream readme](https://github.com/splunk/attack_data/blob/master/total_replay/readme.md) (`poetry install` in `total_replay/`).
2. Edit `total_replay/configuration/config.yml` with paths to detections and attack_data.
3. Ensure Splunk HEC is enabled (port 8088) and the token can write to your test index.

In the web UI **Settings**:

1. Choose **Remote server (SSH)**.
2. Set **TOTAL-REPLAY directory** (e.g. `/opt/attack_data/total_replay`).
3. Enter **SSH host**, user, and password or private key path (on the machine running the web app).
4. Click **Load paths from remote configuration/config.yml** or **Test SSH**.
5. Set **Splunk host** to the address reachable from the *replay origin* (remote server for CLI mode, or your network for HEC + tunnel).
6. Save **HEC token** and **Test Splunk HEC**.

## Index Planner (Splunk inventory + sourcetype routing)

All index/sourcetype work is in the **Index Planner** tab (replaces separate Index Map / Sourcetypes tabs).

1. **Settings** — HEC token, Management API token (8089), **Test REST API**, HTTPS for 8089 if needed.
2. **Index Planner** waterfall:
   - **Step 1** — **Sync Splunk** (tstats index/sourcetype inventory).
   - **Step 2** — **Build routes** (extract replay detection sourcetypes, compare to Splunk).
   - **Step 3** — Pick **Target index** from the searchable Splunk index dropdown → **Save map**. Waterfall: manual map → Splunk inventory → default index.
2. **Attack Test** — select detections and run; index mapping applies when enabled in **Settings**.

Routing priority: **saved manual map** → **Splunk REST inventory** → **Settings default index**.

## Attack Test workflow

1. Open **Attack Test** → **Refresh** to load the catalog.
2. Search by detection name, use case, MITRE ID, tactic, or sourcetype.
3. Select attacks, set **Splunk index** and **Delivery method**.
4. Click **Run selected attacks** and watch **Live output**.

Index mapping runs automatically when enabled in **Settings** (no extra routing UI on Attack Test).

## Logs

The **Logs** tab shows replay history: status, index, item count, and rerun from a past job.

## Security notes

- HEC token, management API token (8089), and SSH password are stored in plaintext at `data/config.json`. **Do not commit this file** — copy from `data/config.json.example` locally. Restrict file permissions and rotate credentials in production.
- SQLite database: `data/totalreplay.db`.

## References

- [TOTAL-REPLAY](https://github.com/splunk/attack_data/tree/master/total_replay)
- [attack_data](https://github.com/splunk/attack_data/tree/master)
