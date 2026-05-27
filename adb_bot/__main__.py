#!/usr/bin/env python3
"""
ADB Matrix Bot — ADB proxy that forwards intercepts to Matrix with E2EE.

Usage:
  cd adb-bot && python -m adb_bot [--config config.yaml] [--verbose]

Environment variables:
  MATRIX_ACCESS_TOKEN   — Matrix access token
  MATRIX_PASSWORD       — Matrix password (if no token)
  MATRIX_ROOM_ID        — Target room ID or alias
  ADB_LISTEN_PORT       — Proxy listen port (default: 5038)
"""

import argparse
import asyncio
import logging
import signal
import sys

from adb_bot.config import load_config
from adb_bot.proxy import AdbProxyServer, AdbIntercept
from adb_bot.bot import MatrixBot

log = logging.getLogger("adb-bot")


async def main():
    parser = argparse.ArgumentParser(description="ADB Matrix Bot — MITM proxy + Matrix E2EE")
    parser.add_argument("--config", "-c", default="config.yaml", help="Config file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose debug output")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config(args.config)
    cfg_matrix = config["matrix"]
    cfg_adb = config["adb"]
    cfg_intercept = config["intercept"]
    cfg_filters = config["filters"]
    cfg_fmt = config["formatting"]

    log.info("=== ADB Matrix Bot ===")
    log.info("Config: %s", args.config)
    log.info("Proxy: %s:%s -> %s:%s",
             cfg_adb["listen_host"], cfg_adb["listen_port"],
             cfg_adb["target_host"], cfg_adb["target_port"])
    log.info("Matrix: %s @ %s", cfg_matrix["user_id"], cfg_matrix["homeserver"])

    if not cfg_matrix["user_id"]:
        log.error("matrix.user_id is required in config")
        return 1
    if not cfg_matrix["room_id"]:
        log.error("matrix.room_id is required in config")
        return 1
    if not cfg_matrix["access_token"] and not cfg_matrix["password"]:
        log.error("Either matrix.access_token or matrix.password is required")
        return 1

    bot = MatrixBot(
        homeserver=cfg_matrix["homeserver"],
        user_id=cfg_matrix["user_id"],
        room_id=cfg_matrix["room_id"],
        access_token=cfg_matrix["access_token"],
        password=cfg_matrix["password"],
        device_name=cfg_matrix["device_name"],
        store_path=cfg_matrix["store_path"],
        command_prefix=cfg_fmt["command_prefix"],
        screenshot_prefix=cfg_fmt["screenshot_prefix"],
        error_prefix=cfg_fmt["error_prefix"],
        show_timestamps=cfg_fmt["show_timestamps"],
        show_device=cfg_fmt["show_device"],
    )

    async def on_intercept(intercept: AdbIntercept):
        await bot.send_intercept(intercept)

    proxy = AdbProxyServer(
        listen_host=cfg_adb["listen_host"],
        listen_port=cfg_adb["listen_port"],
        target_host=cfg_adb["target_host"],
        target_port=cfg_adb["target_port"],
        on_intercept=on_intercept,
        intercept_screenshots=cfg_intercept["screenshots"],
        intercept_commands=cfg_intercept["shell_commands"],
        exclude_commands=cfg_filters["exclude_commands"],
        max_screenshot_bytes=cfg_intercept["max_screenshot_bytes"],
        capture_apks=cfg_intercept.get("apk_files", True),
        max_apk_bytes=cfg_intercept.get("max_apk_bytes", 100 * 1024 * 1024),
        capture_logcat=cfg_intercept.get("logcat_output", False),
        logcat_lines_per_message=cfg_intercept.get("logcat_lines_per_message", 50),
        logcat_max_total_lines=cfg_intercept.get("logcat_max_total_lines", 500),
        hold_seconds=cfg_adb.get("session_hold_seconds", 0.0),
    )

    log.info("Starting Matrix bot (login + E2EE)...")
    ok = await bot.start()
    if not ok:
        log.error("Failed to start Matrix bot")
        return 1

    await proxy.start()

    log.info("Ready. Intercepting ADB traffic...")
    log.info("Use: adb -P %s <command>", cfg_adb["listen_port"])

    stop_event = asyncio.Event()

    def shutdown():
        log.info("Shutting down...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown)

    await stop_event.wait()

    await proxy.stop()
    await bot.stop()
    log.info("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
