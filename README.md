# ADB Matrix Bot

Transparent MITM proxy for Android Debug Bridge (ADB) that intercepts commands and screenshots, forwarding them to a Matrix room with full end-to-end encryption (E2EE).

## How it works

```
adb client  ──→  ADB Matrix Bot (proxy)  ──→  real adbd
                       │
                       ▼
                 Matrix room (E2EE)
```

1. **TCP proxy** — listens on a configurable port, transparently forwards to the real ADB server
2. **Protocol scanner** — parses the ADB binary protocol, detects shell commands and extracts screenshot PNG data from shell_v2 frames
3. **Matrix bot** — sends formatted notifications (commands, screenshots, errors) to a Matrix room using `matrix-nio` with full E2EE (Olm/Megolm)

## Features

- Transparent ADB proxy — no changes required to your adb workflow
- Command interception with configurable include/exclude filters
- Screenshot capture — automatically detects `screencap` commands and extracts the PNG from the raw ADB stream
- **APK interception** — captures `.apk` files pushed via `adb install` or `adb push` by parsing the ADB sync protocol (SEND/DATA/DONE)
- **Logcat capture** — optionally intercepts `logcat` output and forwards it to Matrix in configurable line batches
- Matrix E2EE — all messages are encrypted using Olm/Megolm
- Device-aware — includes device serial in notifications
- Persistent E2EE session store — survive restarts without re-verifying

## Requirements

- Python 3.11+
- [matrix-nio](https://github.com/poljar/matrix-nio) >= 0.25.0 (with E2EE support)
- PyYAML >= 6.0

## Installation

```bash
git clone https://github.com/your-username/adb-matrix-bot.git
cd adb-matrix-bot
pip install -r requirements.txt
```

## Configuration

Copy `config.yaml` and edit it:

```yaml
matrix:
  homeserver: "https://matrix.org"
  user_id: "@adb-bot:matrix.org"
  access_token: "syt_..."      # or use password
  room_id: "!abc123:matrix.org" # room ID or #alias:server

adb:
  listen_host: "127.0.0.1"
  listen_port: 5038
  target_host: "127.0.0.1"
  target_port: 5037             # real ADB server

intercept:
  shell_commands: true
  screenshots: true
  apk_files: true           # capture APK files from adb install/push
  logcat_output: false       # set to true to intercept logcat output

filters:
  exclude_commands:
    - "logcat"
    - "dumpsys"
```

## Usage

```bash
# Start the bot
python -m adb_bot --config config.yaml

# Or use the launcher script
./run.sh

# Verbose mode
python -m adb_bot --config config.yaml --verbose

# Then use adb normally, pointing at the proxy port
adb -P 5038 shell "screencap -p"
adb -P 5038 shell "input tap 540 960"
adb -P 5038 install myapp.apk
```

## How it works — ADB protocol

The proxy understands the ADB binary protocol:

- **Command frames**: `XXXX<command>` where `XXXX` is a 4-digit ASCII hex length
- **OKAY responses**: transport OKAY (12 bytes) and shell OKAY (4 bytes) are handled separately
- **Shell v2 frames**: `[1 byte ID][4 bytes LE uint32 length][data]` — ID=1 stdout, ID=2 stderr, ID=3 exit code

Screenshot PNG data is scattered across multiple shell_v2 stdout chunks. The proxy accumulates clean stdout data and searches for complete PNG (header + IEND) before forwarding to Matrix.

### Sync protocol (APK capture)

When `adb install` or `adb push` is used, ADB switches to the sync protocol after a `sync:` command:

- **SEND**: `[4 bytes "SEND"][4 bytes LE length]["path,mode"]` — file transfer request
- **DATA**: `[4 bytes "DATA"][4 bytes LE length][chunk data]` — file data chunk
- **DONE**: `[4 bytes "DONE"][4 bytes mtime]` — file transfer complete

The proxy enters sync mode on detecting `sync:`, parses SEND/DATA/DONE packets, and captures the complete file if the path ends with `.apk`.

## Environment variables

All config values can be overridden via environment variables:

| Variable | Config key |
|---|---|
| `MATRIX_HOMESERVER` | `matrix.homeserver` |
| `MATRIX_USER_ID` | `matrix.user_id` |
| `MATRIX_ACCESS_TOKEN` | `matrix.access_token` |
| `MATRIX_PASSWORD` | `matrix.password` |
| `MATRIX_ROOM_ID` | `matrix.room_id` |
| `ADB_LISTEN_PORT` | `adb.listen_port` |
| `ADB_TARGET_PORT` | `adb.target_port` |

## License

MIT
