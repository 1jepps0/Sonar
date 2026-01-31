from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

def find_katana_binary() -> str:
    env_bin = os.environ.get("KATANA_BIN")
    if env_bin:
        return env_bin
    p = shutil.which("katana")
    if p:
        return p
    common = [
        "/usr/local/bin/katana",
        "/usr/bin/katana",
        "/home/kali/go/bin/katana",
        os.path.expanduser("~/go/bin/katana"),
    ]
    for path in common:
        if os.path.exists(path):
            return path
    raise FileNotFoundError("katana not found (install with: go install github.com/projectdiscovery/katana/cmd/katana@latest)")

def run_katana(
    targets: Iterable[str],
    *,
    depth: int = 2,
    concurrency: int = 10,
    timeout: int = 10,
    js_crawl: bool = False,
    js_linkfinder: bool = False,
    tech_detect: bool = False,
    headless: bool = False,
    extra_args: list[str] | None = None,
    raw_dir: str | None = None,
) -> list[dict[str, Any]]:
    """
    Runs katana and returns parsed JSONL records.
    Targets are provided via a temp list file.
    """
    katana_bin = find_katana_binary()
    targets_list = [t.strip() for t in targets if t and t.strip()]
    if not targets_list:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for t in targets_list:
            f.write(t + "\n")
        list_path = f.name

    cmd = [
        katana_bin,
        "-list", list_path,
        "-silent",
        "-j",
        "-d", str(depth),
        "-c", str(concurrency),
        "-timeout", str(timeout),
    ]

    if js_crawl:
        cmd.append("-jc")
    if js_linkfinder:
        cmd.append("-jsl")
    if tech_detect:
        cmd.append("-td")
    if headless:
        cmd.append("-hl")
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(cmd, capture_output=True, text=True)

    records: list[dict[str, Any]] = []
    raw_lines: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        raw_lines.append(line)
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    # Fallback: if katana emitted plain URLs, capture them
    if not records and raw_lines:
        for u in raw_lines:
            records.append({"url": u})

    # Optional raw logging
    if raw_dir:
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        meta = {
            "timestamp_utc": ts,
            "tool": "katana",
            "cmd": cmd,
            "targets_count": len(targets_list),
            "returncode": proc.returncode,
        }
        prefix = Path(raw_dir) / f"katana_{ts.replace(':', '').replace('-', '')}"
        (prefix.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (prefix.with_suffix(".jsonl")).write_text(proc.stdout, encoding="utf-8")
        if proc.stderr:
            (prefix.with_suffix(".stderr")).write_text(proc.stderr, encoding="utf-8")

    return records
