from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

from httpx_wrap import run_httpx
from katana_wrap import run_katana
from ferox_wrap import run_feroxbuster

HTTP_PORTS = {80, 443, 8080, 8000, 8443}
HTTPS_PORTS = {443, 8443}

def http_targets_from_nmap(results: list[dict]) -> list[str]:
    targets = set()
    for host in results:
        ip = host.get("ip")
        if not ip:
            continue
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            port = int(p.get("port", -1))
            service = (p.get("service") or "").lower()
            if port in HTTP_PORTS or service in {"http", "https"}:
                scheme = "https" if (service == "https" or port in HTTPS_PORTS) else "http"
                targets.add(f"{scheme}://{ip}:{port}")
    return sorted(targets)

def _record_ip(rec: dict) -> str | None:
    ip = rec.get("ip") or rec.get("host") or rec.get("input")
    if ip and isinstance(ip, str):
        if ip.startswith("http://") or ip.startswith("https://"):
            try:
                return urlparse(ip).hostname
            except Exception:
                return None
        if ":" in ip:
            return ip.split(":")[0]
        return ip
    url = rec.get("url")
    if isinstance(url, str) and (url.startswith("http://") or url.startswith("https://")):
        try:
            return urlparse(url).hostname
        except Exception:
            return None
    return None

def _get_key(rec: dict, *keys: str):
    for k in keys:
        if k in rec:
            return rec.get(k)
    return None

def normalize_httpx_record(rec: dict) -> dict:
    tech = _get_key(rec, "tech", "technologies")
    if isinstance(tech, list):
        tech = sorted(set(t for t in tech if t))
    return {
        "url": _get_key(rec, "url"),
        "final_url": _get_key(rec, "final_url", "location", "redirect"),
        "host": _get_key(rec, "host"),
        "ip": _get_key(rec, "ip"),
        "port": _get_key(rec, "port"),
        "scheme": _get_key(rec, "scheme"),
        "status_code": _get_key(rec, "status_code", "status-code"),
        "title": _get_key(rec, "title"),
        "webserver": _get_key(rec, "webserver", "server"),
        "content_type": _get_key(rec, "content_type", "content-type"),
        "content_length": _get_key(rec, "content_length", "content-length"),
        "location": _get_key(rec, "location"),
        "tech": tech,
        "from_katana": False,
    }

def _record_key(rec: dict) -> str:
    url = rec.get("url")
    if url:
        return url
    host = rec.get("host") or rec.get("ip")
    port = rec.get("port")
    scheme = rec.get("scheme")
    if host and port:
        if scheme:
            return f"{scheme}://{host}:{port}"
        return f"{host}:{port}"
    if host:
        return str(host)
    return ""

def _katana_urls(records: Iterable[dict], extra_urls: Iterable[str] | None = None) -> list[str]:
    targets = [r.get("url") for r in records if r.get("url")]
    if extra_urls:
        targets.extend(u for u in extra_urls if u)
    if not targets:
        return []
    katana_records = run_katana(targets, depth=2, concurrency=10, timeout=10)
    urls: list[str] = []
    for rec in katana_records:
        url = (
            rec.get("url")
            or rec.get("rurl")
            or rec.get("qurl")
            or (rec.get("request") or {}).get("endpoint")
        )
        if url:
            urls.append(url)
    return urls

def _normalize_ferox_record(rec: dict) -> dict:
    url = rec.get("url") or rec.get("full_url")
    headers = rec.get("headers") or {}
    return {
        "url": url,
        "status": rec.get("status") or rec.get("status_code") or rec.get("status-code"),
        "content_type": rec.get("content_type") or rec.get("content-type") or headers.get("content-type"),
        "content_length": rec.get("content_length") or rec.get("content-length") or headers.get("content-length"),
        "method": rec.get("method"),
    }

def http_enrichment_from_nmap(
    nmap_result: list[dict],
    *,
    httpx_threads: int = 200,
    httpx_timeout: int = 5,
    katana_depth: int = 2,
    katana_concurrency: int = 10,
    katana_timeout: int = 10,
) -> dict[str, dict[str, list[dict]]]:
    httpx_targets = http_targets_from_nmap(nmap_result)
    records = run_httpx(httpx_targets, threads=httpx_threads, timeout=httpx_timeout)

    httpx_by_ip: dict[str, list[dict]] = {}
    existing_httpx_urls: set[str] = set()
    for r in records:
        ip = _record_ip(r)
        if not ip:
            continue
        item = normalize_httpx_record(r)
        key = _record_key(item)
        if key:
            existing_httpx_urls.add(key)
        httpx_by_ip.setdefault(ip, []).append(item)

    ferox_targets = http_targets_from_nmap(nmap_result)
    ferox_records = run_feroxbuster(ferox_targets)
    ferox_urls: list[str] = []
    ferox_by_ip: dict[str, list[dict]] = {}
    host_lookup: dict[str, str] = {}
    for host in nmap_result:
        ip = host.get("ip")
        if not ip:
            continue
        host_lookup[ip] = ip
        for name in host.get("names", []) or []:
            host_lookup[name] = ip

    for rec in ferox_records:
        if rec.get("type") and rec.get("type") != "response":
            continue
        url = rec.get("url") or rec.get("full_url")
        if not url:
            continue
        status = rec.get("status") or rec.get("status_code") or rec.get("status-code")
        if status not in {200, 301, 302, 401, 403, 500}:
            continue
        ferox_urls.append(url)
        try:
            host = urlparse(url).hostname
        except Exception:
            continue
        if not host:
            continue
        ip = host_lookup.get(host)
        if not ip:
            continue
        ferox_by_ip.setdefault(ip, []).append(_normalize_ferox_record(rec))

    katana_urls = _katana_urls(records, extra_urls=ferox_urls)
    katana_urls = [u for u in katana_urls if u and u not in existing_httpx_urls]
    if katana_urls:
        katana_httpx = run_httpx(katana_urls, threads=httpx_threads, timeout=httpx_timeout)
        for r in katana_httpx:
            ip = _record_ip(r)
            if not ip:
                continue
            item = normalize_httpx_record(r)
            item["from_katana"] = True
            key = _record_key(item)
            if key and key in existing_httpx_urls:
                continue
            if key:
                existing_httpx_urls.add(key)
            httpx_by_ip.setdefault(ip, []).append(item)

    return {
        "httpx": httpx_by_ip,
        "ferox": ferox_by_ip,
    }
