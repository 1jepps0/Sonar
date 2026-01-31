from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def find_harvester_binary() -> str:
    for name in ("theHarvester", "theharvester"):
        p = shutil.which(name)
        if p:
            return p
    raise FileNotFoundError("theHarvester not found (sudo apt install theharvester)")


def _safe_name(value: str) -> str:
    value = value.strip()
    if not value:
        return "target"
    return _SAFE_NAME_RE.sub("_", value)


def run_harvester(
    target: str,
    *,
    source: str = "all",
    limit: int = 500,
    output_dir: str | Path = "output",
    quiet: bool = True,
    extra_args: list[str] | None = None,
    raw_dir: str | None = None,
) -> dict[str, Any]:
    harvester_bin = find_harvester_binary()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / f"theharvester_{_safe_name(target)}"

    cmd = [
        harvester_bin,
        "-d", target,
        "-l", str(limit),
        "-b", source,
        "-f", str(base),
    ]
    if quiet:
        cmd.append("-q")
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())

    json_path = base.with_suffix(".json")
    if not json_path.exists():
        return {}
    data = {}
    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError:
        data = {}

    if raw_dir:
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        meta = {
            "timestamp_utc": ts,
            "tool": "theHarvester",
            "cmd": cmd,
            "target": target,
            "returncode": result.returncode,
        }
        prefix = Path(raw_dir) / f"theharvester_{ts.replace(':', '').replace('-', '')}"
        (prefix.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        # Keep theHarvester native outputs in output_dir; only add metadata/stderr here.
        if result.stderr:
            (prefix.with_suffix(".stderr")).write_text(result.stderr, encoding="utf-8")

    return data


def extract_hosts_ips(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    hosts_out: list[str] = []
    ips_out: list[str] = []

    for ip in data.get("ips", []) or []:
        if isinstance(ip, str) and ip.strip():
            ips_out.append(ip.strip())

    for entry in data.get("hosts", []) or []:
        host = None
        ip = None
        if isinstance(entry, str):
            host = entry.strip()
        elif isinstance(entry, dict):
            host = entry.get("host") or entry.get("hostname")
            ip = entry.get("ip")
        if not host:
            continue
        host = host.strip()
        if ":" in host:
            host, possible_ip = host.split(":", 1)
            if possible_ip:
                ip = possible_ip
        host = host.lstrip("*.").lower()
        if host:
            hosts_out.append(host)
        if ip and isinstance(ip, str) and ip.strip():
            ips_out.append(ip.strip())

    return sorted(set(hosts_out)), sorted(set(ips_out))
