#!/bin/bash
# ADB Matrix Bot launcher
# Usage: ./run.sh [--config config.yaml] [--verbose]
cd "$(dirname "$0")"
exec python3 -m adb_bot "$@"
