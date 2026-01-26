from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import subprocess
from typing import Iterable

def find_chromium_binary() -> str:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(name)
        if p:
            return p
    raise FileNotFoundError("chromium not found (sudo apt install chromium)")

def _url_to_filename(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return f"{digest}.png"

def capture_screenshots(
    urls: Iterable[str],
    out_dir: str | Path,
    *,
    width: int = 1280,
    height: int = 720,
    timeout_sec: int = 12,
) -> dict[str, str]:
    """
    Capture screenshots with headless Chromium.
    Returns a mapping of url -> relative png path.
    """
    chromium = find_chromium_binary()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    mapping: dict[str, str] = {}
    for url in urls:
        if not url:
            continue
        filename = _url_to_filename(url)
        out_path = out_dir / filename
        if out_path.exists():
            mapping[url] = str(out_path)
            continue
        cmd = [
            chromium,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--hide-scrollbars",
            f"--window-size={width},{height}",
            f"--screenshot={out_path}",
            url,
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
        except Exception:
            continue
        if out_path.exists():
            mapping[url] = str(out_path)
    return mapping
