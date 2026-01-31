import argparse
import json
from pathlib import Path
import socket
from datetime import datetime
from urllib.parse import urlparse
from nmap_wrap import nmap_scan, parse_nmap_xml
from reporting.render import render_report
from recon_pipeline import http_enrichment_from_nmap
from screenshot_wrap import capture_screenshots
from harvester_wrap import run_harvester, extract_hosts_ips
from scope_utils import build_scope_blacklist, is_blocked_host, is_blocked_url

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated Recon & Enumeration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # --------------------
    # Basic Scope Options
    # --------------------
    target_group = parser.add_argument_group("Target Scope")

    target_group.add_argument(
        "-d", "--domain",
        action="append",
        help="Target domain(s). Can be specified multiple times."
    )

    target_group.add_argument(
        "--asn",
        action="append",
        help="Target ASN(s), e.g. AS13335. Can be specified multiple times."
    )

    target_group.add_argument(
        "--cidr",
        action="append",
        help="Target IP ranges in CIDR notation. Can be specified multiple times."
    )

    target_group.add_argument(
        "--company",
        action="append",
        help="Company or organization name (used for OSINT/passive enrichment). Can be specified multiple times."
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output."
    )

    parser.add_argument(
        "--skip-ferox",
        action="store_true",
        help="Skip feroxbuster content discovery."
    )

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to config JSON file."
    )

    # --------------------
    # Scope Input Files
    # --------------------
    file_group = parser.add_argument_group("Input Files")

    file_group.add_argument(
        "--domain-file",
        help="File containing domains (one per line)."
    )

    file_group.add_argument(
        "--asn-file",
        help="File containing ASNs (one per line, e.g. AS13335)."
    )

    file_group.add_argument(
        "--cidr-file",
        help="File containing CIDR ranges (one per line)."
    )

    args = parser.parse_args()

    # warn no args
    if not any([args.domain, args.asn, args.cidr, args.company, args.domain_file, args.asn_file, args.cidr_file]):
        parser.error("At least one target must be specified (--domain, --asn, --cidr, or --company).")

    return args

def _load_list_file(path: str | None) -> list[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    items: list[str] = []
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        items.append(line)
    return items

def clean_args(args):
    # get values from args
    domains = (args.domain or []) + _load_list_file(args.domain_file)
    asns    = (args.asn or []) + _load_list_file(args.asn_file)
    cidrs   = (args.cidr or []) + _load_list_file(args.cidr_file)
    companies = args.company or []

    # deduplicate, clean and sort
    domains = sorted(set(d.lower() for d in domains))
    asns = sorted({a.upper() for a in asns})
    cidrs = sorted(set(cidrs))
    companies = sorted(set(c.strip() for c in companies if c and c.strip()))

    return domains, asns, cidrs, companies

def main():
    args = parse_args()
    domains, asns, cidrs, companies = clean_args(args)
    verbose = bool(args.verbose)
    cfg: dict = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON in config file {cfg_path}: {exc}")
        if verbose:
            print(f"[+] Loaded config: {cfg_path}")
    scope_blacklist = build_scope_blacklist(cfg.get("scope_blacklist", {}))

    run_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path("output") / run_id
    raw_root = run_dir / "raw"
    screens_dir = run_dir / "screens"
    if verbose:
        print(f"[+] Run output dir: {run_dir}")

    harvester_hosts: set[str] = set()
    harvester_ips: set[str] = set()
    if domains or companies:
        if verbose:
            print(f"[+] Running theHarvester on {len(domains) + len(companies)} target(s)...")
        for target in domains + companies:
            if verbose:
                print(f"[+] theHarvester: {target}")
            data = run_harvester(
                target,
                extra_args=cfg.get("tools", {}).get("theharvester", {}).get("extra_args"),
                raw_dir=str(raw_root / "theharvester"),
                output_dir=str(raw_root / "theharvester"),
            )
            hosts, ips = extract_hosts_ips(data)
            harvester_hosts.update(hosts)
            harvester_ips.update(ips)
        if verbose:
            print(f"[+] theHarvester found {len(harvester_hosts)} host(s) and {len(harvester_ips)} IP(s)")

    # Apply scope blacklist to harvested hosts/IPs and input domains/cidrs
    domains = [d for d in domains if not is_blocked_host(d, scope_blacklist)]
    cidrs = [c for c in cidrs if not is_blocked_host(c, scope_blacklist)]
    harvester_hosts = {h for h in harvester_hosts if not is_blocked_host(h, scope_blacklist)}
    harvester_ips = {i for i in harvester_ips if not is_blocked_host(i, scope_blacklist)}

    # build nmap targets
    nmap_targets: set[str] = set()
    nmap_targets.update(cidrs)
    nmap_targets.update(domains)
    nmap_targets.update(harvester_hosts)
    nmap_targets.update(harvester_ips)
    nmap_targets = {t for t in nmap_targets if not is_blocked_host(t, scope_blacklist)}

    # Collapse domains that resolve to IPs already in scope (avoid duplicate nmap scans)
    domain_aliases_by_ip: dict[str, list[str]] = {}
    if domains:
        for d in domains:
            try:
                resolved_ip = socket.gethostbyname(d)
            except Exception:
                resolved_ip = None
            if not resolved_ip:
                continue
            domain_aliases_by_ip.setdefault(resolved_ip, []).append(d)
            if resolved_ip in nmap_targets:
                nmap_targets.discard(d)

    def _resolve_rdns(ip: str) -> str | None:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
        except Exception:
            return None
        if name:
            return name.rstrip(".").lower()
        return None

    def _merge_nmap_hosts(hosts: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}
        for h in hosts:
            ip = h.get("ip")
            if not ip:
                continue
            if ip not in merged:
                merged[ip] = {
                    **h,
                    "names": list(dict.fromkeys(h.get("names", []) or [])),
                    "ports": list(h.get("ports", []) or []),
                    "os": list(h.get("os", []) or []),
                    "host_scripts": list(h.get("host_scripts", []) or []),
                }
                continue
            cur = merged[ip]
            cur_names = list(dict.fromkeys((cur.get("names", []) or []) + (h.get("names", []) or [])))
            cur["names"] = cur_names

            def _port_key(p: dict) -> tuple:
                return (p.get("protocol"), int(p.get("port", 0)))
            port_map = { _port_key(p): p for p in (cur.get("ports", []) or []) }
            for p in (h.get("ports", []) or []):
                key = _port_key(p)
                if key not in port_map:
                    port_map[key] = p
            cur["ports"] = list(port_map.values())

            cur_os = list(cur.get("os", []) or [])
            cur_os.extend(h.get("os", []) or [])
            cur["os"] = cur_os

            cur_scripts = list(cur.get("host_scripts", []) or [])
            for s in (h.get("host_scripts", []) or []):
                if s not in cur_scripts:
                    cur_scripts.append(s)
            cur["host_scripts"] = cur_scripts

        return list(merged.values())

    # scan ips
    if nmap_targets:
        if verbose:
            print(f"[+] Running nmap on {len(nmap_targets)} target(s)...")
        nmap_result = _merge_nmap_hosts(parse_nmap_xml(nmap_scan(
            sorted(nmap_targets),
            extra_args=cfg.get("tools", {}).get("nmap", {}).get("extra_args"),
            raw_dir=str(raw_root / "nmap"),
        )))
        for h in nmap_result:
            ip = h.get("ip")
            if not ip:
                continue
            aliases = domain_aliases_by_ip.get(ip, [])
            if aliases:
                names = h.get("names", []) or []
                for a in aliases:
                    if a not in names:
                        names.append(a)
                h["names"] = names
            rdns = _resolve_rdns(ip)
            if rdns:
                h["rdns"] = rdns
                names = h.get("names", []) or []
                if rdns not in names:
                    names.append(rdns)
                    h["names"] = names
        if verbose:
            print(f"[+] Nmap hosts parsed: {len(nmap_result)}")
            if args.skip_ferox:
                print("[+] Running httpx/katana enrichment (ferox skipped)...")
            else:
                print("[+] Running httpx/katana/ferox enrichment...")
        enrichment = http_enrichment_from_nmap(
            nmap_result,
            run_ferox=not args.skip_ferox,
            scope_blacklist=scope_blacklist,
            httpx_extra_args=cfg.get("tools", {}).get("httpx", {}).get("extra_args"),
            katana_extra_args=cfg.get("tools", {}).get("katana", {}).get("extra_args"),
            ferox_extra_args=cfg.get("tools", {}).get("ferox", {}).get("extra_args"),
            httpx_raw_dir=str(raw_root / "httpx"),
            katana_raw_dir=str(raw_root / "katana"),
            ferox_raw_dir=str(raw_root / "ferox"),
            verbose=verbose,
        )
        httpx_by_ip = enrichment.get("httpx", {})
        ferox_by_ip = enrichment.get("ferox", {})
        if verbose:
            httpx_count = sum(len(v) for v in httpx_by_ip.values())
            ferox_count = sum(len(v) for v in ferox_by_ip.values())
            print(f"[+] httpx records: {httpx_count}  ferox records: {ferox_count}")
    else:
        nmap_result = []
        httpx_by_ip = {}
        ferox_by_ip = {}

    def _norm_url(url: str) -> str:
        try:
            p = urlparse(url)
        except Exception:
            return url
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        port = p.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return f"{scheme}://{netloc}{path}"

    def _alt_urls(url: str) -> list[str]:
        n = _norm_url(url)
        alts = {url, n}
        if n.endswith("/") and n != "http://" and n != "https://":
            alts.add(n.rstrip("/"))
        else:
            alts.add(n + "/" if n != "http://" and n != "https://" else n)
        return list(alts)

    # Build screenshot list: discovered paths only (plus root)
    all_urls: set[str] = set()
    host_discovered: dict[str, list[str]] = {}
    for host in nmap_result:
        ip = host.get("ip")
        if not ip:
            continue
        httpx_items = httpx_by_ip.get(ip, [])
        # Include all base URLs (even 404s) for screenshots
        for r in httpx_items:
            if r.get("from_katana"):
                continue
            url = r.get("display_url") or r.get("final_url") or r.get("url")
            if url and not is_blocked_url(url, scope_blacklist):
                all_urls.add(url)
        discovered_urls = []
        for r in httpx_items:
            if r.get("from_katana"):
                url = r.get("display_url") or r.get("final_url") or r.get("url")
                if url and not is_blocked_url(url, scope_blacklist):
                    discovered_urls.append(url)
        for f in ferox_by_ip.get(ip, []):
            if f.get("url") and not is_blocked_url(f.get("url"), scope_blacklist):
                discovered_urls.append(f.get("url"))
        # limit to avoid huge galleries
        discovered_urls = list(dict.fromkeys(discovered_urls))[:20]
        host_discovered[ip] = discovered_urls
        all_urls.update(discovered_urls)

    if all_urls:
        if verbose:
            print(f"[+] Capturing screenshots for {len(all_urls)} URL(s)...")
        screen_map_abs = capture_screenshots(all_urls, screens_dir)
        screen_map = {u: str(Path(p).relative_to(run_dir)) for u, p in screen_map_abs.items()}
    else:
        screen_map = {}
    # Add normalized/alternate keys for robust lookup
    expanded_map: dict[str, str] = {}
    for u, path in screen_map.items():
        for alt in _alt_urls(u):
            expanded_map[alt] = path
    screen_map = expanded_map

    results = []
    for host in nmap_result:
        host_ip = host.get("ip")
        screen_urls = host_discovered.get(host_ip, [])
        screens = {}
        for u in screen_urls:
            for alt in _alt_urls(u):
                if alt in screen_map:
                    screens[u] = screen_map[alt]
                    break
        results.append({
            **host,
            "httpx": httpx_by_ip.get(host_ip, []),
            "ferox": ferox_by_ip.get(host_ip, []),
            "screens": screens,
        })

    if verbose:
        print("[+] Rendering report...")
    render_report(results, run_dir / "report.html", meta={"cidrs": cidrs, "domains": domains, "asns": asns, "companies": companies})
    if verbose:
        print(f"[+] Done. Report written to {run_dir / 'report.html'}")



if __name__ == "__main__":
    main()
