"""
generate_dashboard_config.py
Writes dashboards/dashboard.config.js using environment-driven settings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def build_config() -> dict:
    return {
        "apiBaseUrl": os.getenv("MISTCODER_BASE_URL", "").strip(),
        "refreshMs": int(os.getenv("MISTCODER_REFRESH_MS", "45000")),
        "timeoutMs": int(os.getenv("MISTCODER_TIMEOUT_MS", "10000")),
        "cacheTtlMs": int(os.getenv("MISTCODER_CACHE_TTL_MS", "30000")),
    }


def write_config(out_path: Path = Path("dashboards/dashboard.config.js")) -> Path:
    config = build_config()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    content = "window.EDEN_DASHBOARD_CONFIG = " + json.dumps(config, indent=2) + ";\n"
    out_path.write_text(content, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    path = write_config()
    print(f"Dashboard config generated → {path}")
