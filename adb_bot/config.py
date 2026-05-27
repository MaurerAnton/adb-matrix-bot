"""
Configuration loader — YAML config with defaults.
"""

import os
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = {
    "matrix": {
        "homeserver": "https://matrix.org",
        "user_id": "",
        "access_token": "",
        "password": "",
        "room_id": "",
        "device_name": "adb-mitm-bot",
        "store_path": "./e2ee_store",
    },
    "adb": {
        "listen_host": "127.0.0.1",
        "listen_port": 5038,
        "target_host": "127.0.0.1",
        "target_port": 5037,
    },
    "intercept": {
        "shell_commands": True,
        "screenshots": True,
        "command_output": True,
        "apk_files": True,
        "logcat_output": False,
        "max_output_bytes": 4096,
        "max_screenshot_bytes": 4 * 1024 * 1024,
        "max_apk_bytes": 100 * 1024 * 1024,  # 100 MB
        "logcat_lines_per_message": 50,
        "logcat_max_total_lines": 500,
    },
    "filters": {
        "include_commands": [],
        "exclude_commands": [
            "logcat", "dumpsys", "bugreport", "cmd stats", "dumpsys meminfo"
        ],
    },
    "formatting": {
        "command_prefix": "📱 ADB",
        "screenshot_prefix": "📸 Screenshot",
        "error_prefix": "⚠️ ADB Error",
        "show_timestamps": True,
        "show_device": True,
    },
}


def load_config(path: str | Path = "config.yaml") -> dict[str, Any]:
    """Load config from YAML file, merging with defaults."""
    config = DEFAULT_CONFIG.copy()

    config_path = Path(path)
    if config_path.exists():
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}

        # Deep merge
        _deep_merge(config, user_config)

    # Resolve env var overrides
    _apply_env_overrides(config)

    # Resolve relative paths
    _resolve_paths(config, config_path.parent)

    return config


def _deep_merge(base: dict, override: dict):
    """Recursively merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _apply_env_overrides(config: dict):
    """Override config from environment variables."""
    env_map = {
        "MATRIX_HOMESERVER": ("matrix", "homeserver"),
        "MATRIX_USER_ID": ("matrix", "user_id"),
        "MATRIX_ACCESS_TOKEN": ("matrix", "access_token"),
        "MATRIX_PASSWORD": ("matrix", "password"),
        "MATRIX_ROOM_ID": ("matrix", "room_id"),
        "ADB_LISTEN_PORT": ("adb", "listen_port"),
        "ADB_TARGET_PORT": ("adb", "target_port"),
    }
    for env_var, (section, key) in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            if key.endswith("_port"):
                val = int(val)
            config[section][key] = val


def _resolve_paths(config: dict, config_dir: Path):
    """Resolve relative paths in config."""
    store_path = config["matrix"].get("store_path", "")
    if store_path and not os.path.isabs(store_path):
        config["matrix"]["store_path"] = str((config_dir / store_path).resolve())
