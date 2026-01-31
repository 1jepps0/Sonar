from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


def build_scope_blacklist(cfg: dict[str, Any] | None) -> dict[str, Any]:
    cfg = cfg or {}
    domains = {d.strip().lower() for d in cfg.get("domains", []) if isinstance(d, str) and d.strip()}
    ips = {i.strip() for i in cfg.get("ips", []) if isinstance(i, str) and i.strip()}
    cidrs_raw = [c.strip() for c in cfg.get("cidrs", []) if isinstance(c, str) and c.strip()]
    regex_raw = [r for r in cfg.get("regex", []) if isinstance(r, str) and r]

    cidrs = []
    for c in cidrs_raw:
        try:
            cidrs.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue

    regex = []
    for r in regex_raw:
        try:
            regex.append(re.compile(r))
        except re.error:
            continue

    return {
        "domains": domains,
        "ips": ips,
        "cidrs": cidrs,
        "cidr_raw": set(cidrs_raw),
        "regex": regex,
    }


def _host_in_cidrs(host: str, cidrs: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for c in cidrs:
        if ip in c:
            return True
    return False


def is_blocked_host(host: str | None, bl: dict[str, Any]) -> bool:
    if not host:
        return False
    host = host.strip().lower()
    if not host:
        return False

    if host in bl.get("ips", set()):
        return True
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            net = None
        if net:
            for c in bl.get("cidrs", []):
                if net == c:
                    return True
    if host in bl.get("cidr_raw", set()):
        return True
    if _host_in_cidrs(host, bl.get("cidrs", [])):
        return True

    # domain/subdomain match
    domains = bl.get("domains", set())
    for d in domains:
        if host == d or host.endswith("." + d):
            return True

    for rx in bl.get("regex", []):
        if rx.search(host):
            return True

    return False


def is_blocked_url(url: str | None, bl: dict[str, Any]) -> bool:
    if not url:
        return False
    try:
        host = urlparse(url).hostname
    except Exception:
        host = None
    if host and is_blocked_host(host, bl):
        return True
    for rx in bl.get("regex", []):
        if rx.search(url):
            return True
    return False
