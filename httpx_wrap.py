from __future__ import annotations

import json
import shutil
import subprocess
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

    # Feed targets on stdin
    stdin_data = "\n".join(t.strip() for t in targets if t and t.strip()) + "\n"

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

    return records
