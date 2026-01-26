import argparse
from pathlib import Path
from nmap_wrap import nmap_scan, parse_nmap_xml
from reporting.render import render_report
from recon_pipeline import http_enrichment_from_nmap
from screenshot_wrap import capture_screenshots

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
        help="Company or organization name (used for OSINT/passive enrichment)."
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
    if not any([args.domain, args.asn, args.cidr]):
        parser.error("At least one target must be specified (--domain, --asn, or --cidr).")

    return args

def clean_args(args):
    # get values from args
    domains = args.domain or []
    asns    = args.asn or []
    cidrs   = args.cidr or []

    # deduplicate, clean and sort
    domains = sorted(set(d.lower() for d in domains))
    asns = sorted(set(a.upper()) for a in asns)
    cidrs = sorted(set(cidrs))

    return domains, asns, cidrs

def main():
    args = parse_args()
    domains, asns, cidrs = clean_args(args)

    # scan ips
    nmap_result = parse_nmap_xml(nmap_scan(cidrs[0]))

    enrichment = http_enrichment_from_nmap(nmap_result)
    httpx_by_ip = enrichment.get("httpx", {})
    ferox_by_ip = enrichment.get("ferox", {})

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
        # Ensure root is always included when we have a base URL
        for r in httpx_items:
            if r.get("from_katana"):
                continue
            if r.get("url"):
                all_urls.add(r.get("url"))
                break
        discovered_urls = []
        for r in httpx_items:
            if r.get("from_katana") and r.get("url"):
                discovered_urls.append(r.get("url"))
        for f in ferox_by_ip.get(ip, []):
            if f.get("url"):
                discovered_urls.append(f.get("url"))
        # limit to avoid huge galleries
        discovered_urls = list(dict.fromkeys(discovered_urls))[:20]
        host_discovered[ip] = discovered_urls
        all_urls.update(discovered_urls)

    screen_dir = Path("output/screens")
    screen_map_abs = capture_screenshots(all_urls, screen_dir)
    screen_map = {u: str(Path(p).relative_to(Path("output"))) for u, p in screen_map_abs.items()}
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

    render_report(results, "output/report.html", meta={"cidrs": cidrs, "domains": domains, "asns": asns})



if __name__ == "__main__":
    main()
