from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

def find_httpx_binary() -> str:
    for name in ("httpx-toolkit",):
        p = shutil.which(name)
        if p:
            return p
    raise FileNotFoundError("httpx-toolkit not found (sudo apt install httpx-toolkit)")

def run_httpx(
    targets: Iterable[str],
    *,
    threads: int = 50,
    timeout: int = 5,
    ports: str | None = None,
    no_verify: bool = True,
    extra_args: list[str] | None = None,
    raw_dir: str | None = None,
) -> list[dict[str, Any]]:
    """
    Runs Kali's httpx-toolkit and returns parsed JSONL records.
    Targets are passed via stdin (one per line).
    """
    httpx_bin = find_httpx_binary()

    cmd = [
        httpx_bin,
        "-silent",
        "-json",
        "-td",
        "-title",
        "-sc",
        "-server",
        "-cl",
        "-ct",
        "-location",
        "-fr",
        "-include-chain",
        "-ip",
        "-t", str(threads),          # this version supports -t
        "-timeout", str(timeout),    # this version supports -timeout (int seconds)
    ]

    if no_verify:
        # In this build it's "--no-verify" equivalent isn't listed; use -tls-grab? No.
        # For TLS verification, httpx-toolkit typically accepts "-tls-grab" not disable verify.
        # So we do NOT add a flag here unless your help shows one.
        pass

    if ports:
        cmd.extend(["-p", ports])
    if extra_args:
        cmd.extend(extra_args)

    # Feed targets on stdin
    targets_list = [t.strip() for t in targets if t and t.strip()]
    stdin_data = "\n".join(targets_list) + "\n"

    proc = subprocess.run(cmd, input=stdin_data, capture_output=True, text=True)

    # If you want visibility while debugging:
    # print("rc:", proc.returncode, "stderr:", proc.stderr[:500])

    records: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if raw_dir:
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        meta = {
            "timestamp_utc": ts,
            "tool": "httpx-toolkit",
            "cmd": cmd,
            "targets_count": len(targets_list),
            "returncode": proc.returncode,
        }
        prefix = Path(raw_dir) / f"httpx_{ts.replace(':', '').replace('-', '')}"
        (prefix.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (prefix.with_suffix(".jsonl")).write_text(proc.stdout, encoding="utf-8")
        if proc.stderr:
            (prefix.with_suffix(".stderr")).write_text(proc.stderr, encoding="utf-8")

    return records
