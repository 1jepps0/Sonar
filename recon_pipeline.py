from __future__ import annotations

import socket
from typing import Iterable
from urllib.parse import urlparse

from httpx_wrap import run_httpx
from katana_wrap import run_katana
from ferox_wrap import run_feroxbuster
from scope_utils import is_blocked_url

HTTP_PORTS = {80, 443, 8080, 8000, 8443}
HTTPS_PORTS = {443, 8443}

def http_targets_from_nmap(results: list[dict]) -> list[str]:
    targets = set()
    for host in results:
        ip = host.get("ip")
        if not ip:
            continue
        names = [n for n in (host.get("names") or []) if n]
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            port = int(p.get("port", -1))
            service = (p.get("service") or "").lower()
            if port in HTTP_PORTS or service in {"http", "https"}:
                scheme = "https" if (service == "https" or port in HTTPS_PORTS) else "http"
                targets.add(f"{scheme}://{ip}:{port}")
                for name in names:
                    targets.add(f"{scheme}://{name}:{port}")
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

def _map_ip_from_record(rec: dict, host_lookup: dict[str, str], nmap_ips: set[str]) -> str | None:
    ip = _record_ip(rec)
    if not ip:
        return None
    if ip in nmap_ips:
        return ip
    if ip in host_lookup:
        return host_lookup[ip]
    if not _is_ip(ip):
        try:
            resolved = socket.gethostbyname(ip)
        except Exception:
            resolved = None
        if resolved and resolved in nmap_ips:
            host_lookup[ip] = resolved
            return resolved
    return ip

def _get_key(rec: dict, *keys: str):
    for k in keys:
        if k in rec:
            return rec.get(k)
    return None

def normalize_httpx_record(rec: dict) -> dict:
    tech = _get_key(rec, "tech", "technologies")
    if isinstance(tech, list):
        tech = sorted(set(t for t in tech if t))
    url = _get_key(rec, "url")
    chain = _get_key(rec, "chain")
    final_url = None
    if isinstance(chain, list) and chain:
        tail = chain[-1]
        if isinstance(tail, dict):
            final_url = tail.get("url") or tail.get("location")
        elif isinstance(tail, str):
            final_url = tail
    if not final_url:
        final_url = _get_key(rec, "final_url", "location", "redirect")
    if isinstance(final_url, dict):
        final_url = final_url.get("url") or final_url.get("location")
    if isinstance(url, dict):
        url = url.get("url") or url.get("location")
    display_url = final_url or url
    return {
        "url": url,
        "final_url": final_url,
        "display_url": display_url,
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
    url = rec.get("display_url") or rec.get("final_url") or rec.get("url")
    if isinstance(url, dict):
        url = url.get("url") or url.get("location")
    if isinstance(url, str) and url:
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

def _is_ip(host: str | None) -> bool:
    if not host:
        return False
    # Simple IPv4 check
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True

def _base_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        p = urlparse(url)
    except Exception:
        return None
    host = p.hostname
    if not host:
        return None
    scheme = (p.scheme or "http").lower()
    port = p.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    elif port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    return f"{scheme}://{netloc}/"

def _katana_urls(
    records: Iterable[dict],
    extra_urls: Iterable[str] | None = None,
    *,
    extra_args: list[str] | None = None,
    raw_dir: str | None = None,
) -> list[str]:
    targets = [
        (r.get("display_url") or r.get("final_url") or r.get("url"))
        for r in records
        if (r.get("display_url") or r.get("final_url") or r.get("url"))
    ]
    if extra_urls:
        targets.extend(u for u in extra_urls if u)
    if not targets:
        return []
    katana_records = run_katana(
        targets,
        depth=2,
        concurrency=10,
        timeout=10,
        js_crawl=True,
        js_linkfinder=True,
        extra_args=extra_args,
        raw_dir=raw_dir,
    )
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
    run_ferox: bool = True,
    scope_blacklist: dict | None = None,
    httpx_extra_args: list[str] | None = None,
    katana_extra_args: list[str] | None = None,
    ferox_extra_args: list[str] | None = None,
    httpx_raw_dir: str | None = None,
    katana_raw_dir: str | None = None,
    ferox_raw_dir: str | None = None,
    verbose: bool = False,
) -> dict[str, dict[str, list[dict]]]:
    host_lookup: dict[str, str] = {}
    nmap_ips: set[str] = set()
    for host in nmap_result:
        ip = host.get("ip")
        if not ip:
            continue
        nmap_ips.add(ip)
        host_lookup[ip] = ip
        for name in host.get("names", []) or []:
            host_lookup[name] = ip
            if not name.startswith("www."):
                host_lookup[f"www.{name}"] = ip
            elif name.startswith("www.") and len(name) > 4:
                host_lookup[name[4:]] = ip

    scope_blacklist = scope_blacklist or {}
    httpx_targets = [t for t in http_targets_from_nmap(nmap_result) if not is_blocked_url(t, scope_blacklist)]
    if verbose:
        sample = ", ".join(httpx_targets[:5])
        more = " ..." if len(httpx_targets) > 5 else ""
        print(f"[+] httpx targets: {len(httpx_targets)} {sample}{more}")
    records = run_httpx(
        httpx_targets,
        threads=httpx_threads,
        timeout=httpx_timeout,
        extra_args=httpx_extra_args,
        raw_dir=httpx_raw_dir,
    )
    if verbose:
        print(f"[+] httpx records: {len(records)}")

    httpx_by_ip: dict[str, list[dict]] = {}
    existing_httpx_urls: set[str] = set()
    for r in records:
        ip = _map_ip_from_record(r, host_lookup, nmap_ips)
        if not ip:
            continue
        item = normalize_httpx_record(r)
        key = _record_key(item)
        if isinstance(key, str) and key:
            existing_httpx_urls.add(key)
        httpx_by_ip.setdefault(ip, []).append(item)

    katana_seed_urls: set[str] = set()
    # Seed from known hostnames (and their www/non-www variants)
    for host in nmap_result:
        for name in host.get("names", []) or []:
            if not name or _is_ip(name):
                continue
            katana_seed_urls.add(f"https://{name}/")
            katana_seed_urls.add(f"http://{name}/")
            if name.startswith("www.") and len(name) > 4:
                bare = name[4:]
                katana_seed_urls.add(f"https://{bare}/")
                katana_seed_urls.add(f"http://{bare}/")
            elif not name.startswith("www."):
                katana_seed_urls.add(f"https://www.{name}/")
                katana_seed_urls.add(f"http://www.{name}/")

    # Also seed from httpx final/display URLs to follow redirects to canonical hosts
    for items in httpx_by_ip.values():
        for it in items:
            seed = it.get("display_url") or it.get("final_url") or it.get("url")
            base = _base_url(seed)
            if base:
                katana_seed_urls.add(base)

    # Pick one canonical base URL per IP for ferox (avoid brute-forcing duplicates)
    ferox_records: list[dict[str, Any]] = []
    if run_ferox:
        ferox_targets: list[str] = []
        for ip, items in httpx_by_ip.items():
            candidates: list[str] = []
            for it in items:
                base = _base_url(it.get("display_url") or it.get("final_url") or it.get("url"))
                if not base:
                    continue
                candidates.append(base)
            if not candidates:
                continue
            def _score(u: str) -> tuple[int, int, str]:
                try:
                    p = urlparse(u)
                except Exception:
                    return (0, 0, u)
                host = p.hostname
                scheme = (p.scheme or "").lower()
                https = 1 if scheme == "https" else 0
                name = 1 if (host and not _is_ip(host)) else 0
                return (https, name, u)
            pick = sorted(set(candidates), key=_score, reverse=True)[0]
            ferox_targets.append(pick)

        if not ferox_targets:
            ferox_targets = http_targets_from_nmap(nmap_result)
        ferox_targets = [u for u in ferox_targets if not is_blocked_url(u, scope_blacklist)]
        ferox_records = run_feroxbuster(
            ferox_targets,
            extra_args=ferox_extra_args,
            raw_dir=ferox_raw_dir,
        )
    ferox_urls: list[str] = []
    ferox_by_ip: dict[str, list[dict]] = {}

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
        if not ip and host not in nmap_ips:
            try:
                resolved = socket.gethostbyname(host)
            except Exception:
                resolved = None
            if resolved and resolved in nmap_ips:
                host_lookup[host] = resolved
                ip = resolved
        if not ip:
            continue
        ferox_by_ip.setdefault(ip, []).append(_normalize_ferox_record(rec))

    extra_urls = [u for u in dict.fromkeys([*ferox_urls, *katana_seed_urls]) if not is_blocked_url(u, scope_blacklist)]
    katana_urls_raw = _katana_urls(
        records,
        extra_urls=extra_urls,
        extra_args=katana_extra_args,
        raw_dir=katana_raw_dir,
    )
    if verbose:
        sample = ", ".join(katana_urls_raw[:5])
        more = " ..." if len(katana_urls_raw) > 5 else ""
        print(f"[+] katana targets (raw): {len(katana_urls_raw)} {sample}{more}")
    katana_urls = [u for u in katana_urls_raw if u and not is_blocked_url(u, scope_blacklist)]
    if verbose:
        sample = ", ".join(katana_urls[:5])
        more = " ..." if len(katana_urls) > 5 else ""
        print(f"[+] katana targets: {len(katana_urls)} {sample}{more}")
    if katana_urls:
        katana_httpx = run_httpx(
            katana_urls,
            threads=httpx_threads,
            timeout=httpx_timeout,
            extra_args=httpx_extra_args,
            raw_dir=httpx_raw_dir,
        )
        if verbose:
            print(f"[+] katana httpx records: {len(katana_httpx)}")
        for r in katana_httpx:
            ip = _map_ip_from_record(r, host_lookup, nmap_ips)
            if not ip:
                continue
            item = normalize_httpx_record(r)
            item["from_katana"] = True
            key = _record_key(item)
            if isinstance(key, str) and key and key in existing_httpx_urls:
                continue
            if isinstance(key, str) and key:
                existing_httpx_urls.add(key)
            httpx_by_ip.setdefault(ip, []).append(item)

    return {
        "httpx": httpx_by_ip,
        "ferox": ferox_by_ip,
    }
