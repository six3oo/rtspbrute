# RTSPBrute

> Forked from https://gitlab.com/woolf/RTSPbrute and significantly patched for real-world camera compatibility.

## DISCLAIMER
This software is provided for research and ethical uses only.

---

## Features

- **Find accessible RTSP streams** on any target
- Brute-force **stream routes** with corrected 200-only confirmation logic
- Brute-force **credentials** with native Digest auth two-step
- **Automatic route recovery** — if credentials are found but the route is wrong, sweeps routes again with known-good credentials
- **Make screenshots** on accessible streams
- Hikvision multi-channel expansion (`/Streaming/Channels/101/` → channels 101–1601)
- **Always records streams to `result.txt`** even when screenshots fail
- Appends confirmed working stream URLs to `targets.txt` in the working directory (cleared on each run)
- Time-stamped per-run reports under `reports/<timestamp>/`
- Generate **user-friendly report** of the results:
  - `result.txt`: each found stream URL on a new line — rename to `.m3u` to open directly in VLC
  - `index.html`: click a screenshot to copy its RTSP URL

---

## Fixes & Changes (vs upstream)

### Route discovery (`attack.py`)

The upstream code treated HTTP `401` and `403` responses as confirmation that a route was valid. This caused false negatives on cameras (e.g. Tapo, Dahua) that return `401` for **every** route whether it exists or not, making it impossible to distinguish a valid route from a bad one.

**Changes:**
- Only `200 OK` confirms a route. `401`/`403` are now treated as "camera is alive and requires auth" — the target is passed through to credential bruting with a placeholder route.
- Added `_check_status()` helper — checks only the **status line** (first line) of the RTSP response, preventing false positive matches on nonces, dates, or challenge strings embedded in response headers.
- Added `_reset_connection()` helper — closes the socket and resets connection state cleanly between bruteforce attempts. Fixes stale-socket hangs where many cameras close their TCP connection after the first RTSP exchange.
- Added `_find_working_route()` — once valid credentials are cracked, performs a second route sweep using those credentials to find a route that returns `200`. Handles cameras that gate routes behind authentication.
- `attack_credentials()` now distinguishes `404` (correct credentials, wrong route) from `401` (wrong credentials) and calls `_find_working_route()` before recording the result.

### Digest authentication (`rtsp.py`)

The upstream code sent one DESCRIBE request and returned whatever the server replied, which meant Digest-auth cameras always returned a raw `401` challenge (with `realm` and `nonce`) — the credential was never actually tested.

**Changes:**
- `RTSPClient.authorize()` now handles the **Digest two-step** inline: on a `401` response that includes a `realm`+`nonce`, it immediately sends a second authenticated DESCRIBE on the same connection. The caller sees the real result (`200`, `401`, or `404`) rather than always seeing the raw challenge.
- Added `status_line` property on `RTSPClient` — returns only the first line of `self.data`, preventing the nonce or date strings in WWW-Authenticate headers from being matched as status codes.
- Nonce chaining: if the server sends a fresh nonce in its authenticated response, it is captured for use in any follow-up requests.

### Screenshot / result recording (`worker.py`)

Upstream silently dropped stream URLs from the report when PyAV failed to capture a screenshot (common on slow or auth-gated streams).

**Changes:**
- All streams that pass credential bruting are **always written to `result.txt`**, regardless of whether a screenshot succeeds.
- Hikvision streams (`/Streaming/Channels/101/`) are automatically expanded across 16 channel variants (`/Streaming/Channels/101/` through `/Streaming/Channels/1601/`).
- Streams with no explicit route path (ending in `:554/`) are tried as-is before any channel iteration.

### Run isolation (`__main__.py`)

- `targets.txt` is **truncated at the start of each run** so results from previous runs do not accumulate.

---

## Installation

### Requirements

- `python` >= `3.6`
- `av`
- `Pillow`
- `rich`

Install from this repo — the PyPI version is an older release with known segfaults:

```
pip install -e .
```

---

## CLI

```
USAGE
    $ rtspbrute -t TARGETS [-p PORTS [PORTS ...]] [-r ROUTES] [-c CREDENTIALS]
                [-ct N] [-bt N] [-st N] [-T TIMEOUT] [-d] [-h]

ARGUMENTS
    -h, --help                     show this help message and exit
    -t, --targets TARGETS          the targets on which to scan for open RTSP streams
    -p, --ports PORTS [PORTS ...]  the ports on which to search for RTSP streams
    -r, --routes ROUTES            the path on which to load a custom routes
    -c, --credentials CREDENTIALS  the path on which to load a custom credentials
    -ct, --check-threads N         the number of threads to brute-force the routes
    -bt, --brute-threads N         the number of threads to brute-force the credentials
    -st, --screenshot-threads N    the number of threads to screenshot the streams
    -T, --timeout TIMEOUT          the timeout to use for sockets
    -d, --debug                    enable the debug logs

EXAMPLES
    $ rtspbrute -h
    $ rtspbrute -t hosts.txt -p 554 5554 8554 -d
    $ rtspbrute -t ips.txt -r routes.txt -c combinations.txt
    $ rtspbrute -t targets.txt -st 10 -T 10
```

### Arguments

- **`-t, --targets`** _(required)_: Path to input file. Accepts IPs, IP ranges, and CIDRs — one per line:

```
0.0.0.0
192.168.100.1-192.168.254.1
192.17.0.0/16
```

- **`-p, --ports`** (`554`): Ports to scan, e.g. `-p 554 5554 8554`
- **`-r, --routes`** (`routes.txt`): Path to routes file. Each route must start with `/`:

```
/1
/h264
/stream1
```

- **`-c, --credentials`** (`credentials.txt`): Path to credentials file. Each line must contain `:`:

```
admin:admin
admin:12345
user:user
```

- **`-ct, --check-threads`** (`500`): Threads for route bruteforce
- **`-bt, --brute-threads`** (`200`): Threads for credential bruteforce
- **`-st, --screenshot-threads`** (`20`): Threads for screenshots. Lower values yield more successful captures — PyAV drops connections under high thread contention.
- **`-T, --timeout`** (`2`): Socket timeout in seconds
- **`-d, --debug`** (`False`): Write debug log to `reports/<timestamp>/debug.log`
