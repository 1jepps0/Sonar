from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

def find_ferox_binary() -> str:
    p = shutil.which("feroxbuster")
    if p:
        return p
    raise FileNotFoundError("feroxbuster not found (sudo apt install feroxbuster)")

def run_feroxbuster(
    targets: Iterable[str],
    *,
    threads: int = 50,
    depth: int = 2,
    timeout: int = 7,
    wordlist: str | None = None,
    extra_args: list[str] | None = None,
    raw_dir: str | None = None,
) -> list[dict[str, Any]]:
    """
    Runs feroxbuster in JSON mode and returns parsed records.
    Targets are passed via stdin.
    """
    ferox_bin = find_ferox_binary()
    targets_list = [t.strip() for t in targets if t and t.strip()]
    if not targets_list:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_path = f.name

    cmd = [
        ferox_bin,
        "--stdin",
        "--json",
        "-o", output_path,
        "-q",
        "--redirects",
        "-d", str(depth),
        "-t", str(threads),
        "-T", str(timeout),
    ]

    if wordlist:
        cmd.extend(["-w", wordlist])
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(cmd, input="\n".join(targets_list) + "\n", text=True, capture_output=True)
    # ignore non-zero; ferox can return non-zero on some scan conditions

    records: list[dict[str, Any]] = []
    try:
        with open(output_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []

    if raw_dir:
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        meta = {
            "timestamp_utc": ts,
            "tool": "feroxbuster",
            "cmd": cmd,
            "targets": targets_list,
            "returncode": proc.returncode,
        }
        prefix = Path(raw_dir) / f"ferox_{ts.replace(':', '').replace('-', '')}"
        (prefix.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (prefix.with_suffix(".jsonl")).write_text(Path(output_path).read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        if proc.stderr:
            (prefix.with_suffix(".stderr")).write_text(proc.stderr, encoding="utf-8")

    return records
