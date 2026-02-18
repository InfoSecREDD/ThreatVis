# InfoBot THREAT-VIS Honeypot Client/WebUI (Python)

This is an all-in-one honeypot client for the InfoBot Threat Intelligence Network.

- Listens on **all TCP ports by default** (1-65535, where permitted) or on a configured list of ports.
- Captures incoming connection payloads and reports them to the central Threat Reporter API.
- Includes a small built-in **web dashboard** with a dark, cyber-styled theme that matches the main project.

## Requirements

- Python 3.10+
- Network permissions to bind to the desired ports (root is required for ports < 1024 on most systems).

Install dependencies:

```bash
cd clients/honeypot-python
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The honeypot uses two sources of configuration:

1. **Environment variables** for Threat Reporter credentials
2. **`config.json`** for honeypot behavior (ports, UI settings)

### 1. Threat Reporter Credentials (env)

These must match a registered Threat Reporter client on your server.

```bash
export THREAT_REPORTER_CLIENT_ID="client-us-east-1"
export THREAT_REPORTER_API_KEY="pk_xxxx"
export THREAT_REPORTER_SECRET="sk_xxxx"
export THREAT_REPORTER_SERVER="https://your-infobot-server.example.com"
```

### 2. Honeypot Settings (`config.json`)

Copy the example file and adjust as needed:

```bash
cp config.example.json config.json
```

`config.json` fields:

- `mode`: `"all"` or `"list"`
  - `"all"`: attempt to listen on a large range of TCP and UDP ports (1–65535) but capped by `max_listen_ports` so you don’t exhaust file descriptors. Ports already in use or restricted will be skipped.
  - `"list"`: only listen on the ports defined in `ports`.
- `ports`: array of port numbers to listen on when `mode` is `"list"`. The example config ships with a curated set of common/high-value service ports (~100+).
- `exclude_ports`: array of port numbers to **never** listen on (applied in both `"all"` and `"list"` modes). The example excludes the Web UI port by default.
- `ui_host`: dashboard bind host (default `"0.0.0.0"`).
- `ui_port`: dashboard HTTP port (default `8080`).
- `max_events`: maximum number of recent events kept in memory for the dashboard.
- `reporting_enabled`: `true` or `false`. When `false`, the honeypot still captures and stores events locally for the dashboard, but **does not** send any data to the Threat Reporter server (local/anonymous mode).
- `broadcast_location`: `true` or `false`. When `true`, the client will set a flag in each report so the central server can treat this honeypot as broadcasting its approximate location on the Threats globe.
- `max_listen_ports`: safety cap for how many ports are actually bound when `mode` is `"all"` (defaults to `1000`). Raise this only if you also raise the OS `ulimit -n`.

> Note: Listening on all ports can be resource-intensive. For production, consider using `"list"` mode with a curated set of high-value ports.

## Running the Honeypot

```bash
cd clients/honeypot-python
source .venv/bin/activate
python honeypot.py
```

- The honeypot will start listeners on the configured ports.
- It will also start a small dashboard on `http://ui_host:ui_port` (default `http://localhost:8080`).
- Incoming connections are logged locally and reported to `/api/threats/report` via the Threat Reporter API using HMAC-SHA256.

## Dashboard

The dashboard shows:

- Active listening ports
- Total connections observed
- Recent connection events with:
  - source IP
  - destination port
  - bytes captured
  - short preview of payload
  - timestamp

The styling is a lightweight, static approximation of the main app theme: dark background, cyan/primary accents, and subtle glow effects.

These will show up on the Threats page globe and Recent Events list the same way as other honeypot and remote client events, including more precise origin points when `lat`/`lon` are available.
