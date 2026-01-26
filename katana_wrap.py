from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from typing import Any, Iterable

def find_katana_binary() -> str:
    p = shutil.which("katana")
    if p:
        return p
    raise FileNotFoundError("katana not found (install with: go install github.com/projectdiscovery/katana/cmd/katana@latest)")

def run_katana(
    targets: Iterable[str],
    *,
    depth: int = 2,
    concurrency: int = 10,
    timeout: int = 10,
    js_crawl: bool = False,
    tech_detect: bool = False,
    headless: bool = False,
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
    if tech_detect:
        cmd.append("-td")
    if headless:
        cmd.append("-hl")

    proc = subprocess.run(cmd, capture_output=True, text=True)

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
