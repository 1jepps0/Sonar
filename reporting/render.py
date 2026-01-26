from __future__ import annotations
from pathlib import Path
from datetime import datetime
from typing import Any
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

def dedupe_os(os_matches: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for m in os_matches or []:
        name = m.get("name")
        acc = int(m.get("accuracy", 0))
        if not name:
            continue
        if name not in best or acc > int(best[name].get("accuracy", 0)):
            best[name] = {"name": name, "accuracy": acc}
    return sorted(best.values(), key=lambda x: x["accuracy"], reverse=True)

def port_counts(ports: list[dict[str, Any]] | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in ports or []:
        state = p.get("state", "unknown")
        counts[state] = counts.get(state, 0) + 1
    return counts

def render_report(results: list[dict[str, Any]], out_html: str | Path, meta: dict[str, Any] | None = None) -> Path:
    out_html = Path(out_html)
    out_html.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader("reporting/templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("report.html.j2")

    # Preprocess results so templates stay simple
    def _split_kv_output(text: str | None, labels: list[str]) -> dict[str, str]:
        if not text:
            return {}
        out = text
        for label in labels:
            out = out.replace(f" {label}", f"\n{label}")
        kv = {}
        for line in out.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k:
                kv[k] = v
        return kv

    def parse_smb_os(output: str | None) -> dict[str, str]:
        labels = [
            "OS:", "Computer name:", "NetBIOS computer name:", "Domain name:",
            "Forest name:", "FQDN:", "System time:"
        ]
        return _split_kv_output(output, labels)

    def parse_smb2_security_mode(output: str | None) -> dict[str, str]:
        if not output:
            return {}
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if not lines:
            return {}
        if ":" in lines[0]:
            version, msg = lines[0].split(":", 1)
            msg = msg.strip()
            if not msg and len(lines) > 1:
                msg = lines[1]
            return {"SMB2": version.strip(), "Signing": msg}
        return {"Signing": lines[0]}

    def parse_smb2_time(output: str | None) -> dict[str, str]:
        labels = ["date:", "start_date:"]
        return _split_kv_output(output, labels)

    def parse_smb_shares(output: str | None) -> tuple[list[dict[str, str]], list[str], str | None]:
        if not output:
            return [], [], None
        entries: list[dict[str, str]] = []
        notes: list[str] = []
        current: dict[str, str] | None = None
        account_used: str | None = None

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("account_used:"):
                account_used = line.split("account_used:", 1)[1].strip()
                if account_used == "<blank>":
                    account_used = "anonymous"
                continue
            if line.startswith("note:"):
                notes.append(line)
                continue
            if line.startswith("\\\\"):
                share = line.split(":", 1)[0].strip()
                current = {"share": share, "access": "", "note": ""}
                entries.append(current)
                continue
            if line.startswith("warning:"):
                if current:
                    current["note"] = line.split("warning:", 1)[1].strip()
                continue
            if line.startswith("Anonymous access:"):
                val = line.split("Anonymous access:", 1)[1].strip()
                if current:
                    if val in {"<none>", "none"}:
                        current["access"] = "NO ACCESS"
                    else:
                        current["access"] = val
                continue

        return entries, notes, account_used

    def parse_ldap_rootdse(output: str | None) -> list[dict[str, str]]:
        if not output:
            return []
        allow = {
            "defaultNamingContext",
            "dnsHostName",
            "ldapServiceName",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
            "isGlobalCatalogReady",
            "domainFunctionality",
            "forestFunctionality",
            "domainControllerFunctionality",
            "currentTime",
        }
        rows: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for line in output.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if not k or k not in allow:
                continue
            key = (k, v)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"key": k, "value": v})
        return rows

    def summarize_ldap_rootdse(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        if not rows:
            return []
        values: dict[str, list[str]] = {}
        for r in rows:
            k = r.get("key")
            v = r.get("value")
            if not k or v is None:
                continue
            values.setdefault(k, [])
            if v not in values[k]:
                values[k].append(v)

        def pick_max_int(vals: list[str]) -> str:
            nums = []
            for v in vals:
                try:
                    nums.append(int(v))
                except ValueError:
                    pass
            if nums:
                return str(max(nums))
            return ", ".join(vals)

        out: list[dict[str, str]] = []
        order = [
            "dnsHostName",
            "ldapServiceName",
            "defaultNamingContext",
            "isGlobalCatalogReady",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
            "domainFunctionality",
            "forestFunctionality",
            "domainControllerFunctionality",
            "currentTime",
        ]
        for k in order:
            if k not in values:
                continue
            if k == "supportedLDAPVersion":
                v = pick_max_int(values[k])
            else:
                v = ", ".join(values[k])
            out.append({"key": k, "value": v})
        return out

    def parse_kv_lines(output: str | None) -> dict[str, str]:
        if not output:
            return {}
        rows = {}
        for line in output.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k and v:
                rows[k] = v
        return rows

    def parse_ssl_cert(output: str | None) -> dict[str, str]:
        if not output:
            return {}
        rows = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            for key in ("Subject:", "Issuer:", "Not valid before:", "Not valid after:", "Public Key type:", "Public Key bits:", "MD5:", "SHA-1:", "SHA-256:"):
                if line.startswith(key):
                    rows[key[:-1]] = line[len(key):].strip()
        return rows

    def windows_build_to_name(build: str) -> str | None:
        mapping = {
            "10.0.14393": "Windows Server 2016 (build 14393)",
            "10.0.17763": "Windows Server 2019 (build 17763)",
            "10.0.20348": "Windows Server 2022 (build 20348)",
            "10.0.19041": "Windows 10 2004/20H1 (build 19041)",
            "10.0.19042": "Windows 10 20H2 (build 19042)",
            "10.0.19043": "Windows 10 21H1 (build 19043)",
            "10.0.19044": "Windows 10 21H2 (build 19044)",
            "10.0.19045": "Windows 10 22H2 (build 19045)",
            "10.0.22000": "Windows 11 21H2 (build 22000)",
            "10.0.22621": "Windows 11 22H2 (build 22621)",
        }
        return mapping.get(build)
    def merge_discovered(katana_httpx: list[dict[str, Any]], ferox: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}

        def norm_url(url: str | None) -> str | None:
            if not url:
                return None
            try:
                from urllib.parse import urlparse, urlunparse
                p = urlparse(url)
                scheme = (p.scheme or "http").lower()
                host = (p.hostname or "").lower()
                port = p.port
                # drop default ports
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    netloc = host
                elif port:
                    netloc = f"{host}:{port}"
                else:
                    netloc = host
                path = p.path or "/"
                # drop trailing slash except root
                if path != "/" and path.endswith("/"):
                    path = path[:-1]
                return urlunparse((scheme, netloc, path, "", p.query, ""))
            except Exception:
                return url

        def score(item: dict[str, Any]) -> int:
            s = 0
            if item.get("status") or item.get("status_code"):
                s += 1
            if item.get("content_type"):
                s += 1
            if item.get("content_length"):
                s += 1
            return s

        def add_item(item: dict[str, Any]):
            url = item.get("url")
            if not url:
                return
            key = norm_url(url)
            if not key:
                return
            existing = merged.get(key)
            if not existing:
                merged[key] = item
                return
            # Prefer ferox over katana/httpx when both exist for same URL
            if existing.get("source") != item.get("source"):
                if item.get("source") == "ferox":
                    merged[key] = item
                    return
                if existing.get("source") == "ferox":
                    return
            if score(item) > score(existing):
                merged[key] = item

        for r in katana_httpx:
            add_item({
                "url": r.get("url") or r.get("host"),
                "status": r.get("status_code"),
                "content_type": r.get("content_type"),
                "content_length": r.get("content_length"),
                "source": "katana",
            })
        for f in ferox:
            add_item({
                "url": f.get("url"),
                "status": f.get("status"),
                "content_type": f.get("content_type"),
                "content_length": f.get("content_length"),
                "source": "ferox",
            })

        def sort_key(item: dict[str, Any]):
            status = item.get("status")
            if status is None:
                status = 0
            priority = 0 if status == 200 else 1
            return (priority, status, item.get("url") or "")

        return sorted(merged.values(), key=sort_key)

    enriched = []
    for h in results:
        ports = h.get("ports", []) or []
        os_matches = dedupe_os(h.get("os", []) or [])
        names = h.get("names", []) or []
        httpx = h.get("httpx", []) or []
        ferox = h.get("ferox", []) or []
        screens = h.get("screens", {}) or {}
        katana_httpx = [r for r in httpx if r.get("from_katana")]
        host_scripts = h.get("host_scripts", []) or []
        smb_ad_scripts = []
        ldap_scripts = []
        smb_ids = {"smb-enum-shares", "smb-os-discovery", "smb2-security-mode", "smb2-time"}
        ldap_ids = {"ldap-rootdse"}
        for p in ports:
            for s in p.get("scripts", []) or []:
                sid = s.get("id")
                if not sid:
                    continue
                entry = {
                    "port": p.get("port"),
                    "service": p.get("service"),
                    "id": sid,
                    "output": s.get("output"),
                }
                if sid in smb_ids:
                    smb_ad_scripts.append(entry)
                if sid in ldap_ids:
                    ldap_scripts.append(entry)
        for s in host_scripts:
            sid = s.get("id")
            if not sid:
                continue
            entry = {
                "port": None,
                "service": "host",
                "id": sid,
                "output": s.get("output"),
            }
            if sid in smb_ids:
                smb_ad_scripts.append(entry)
            if sid in ldap_ids:
                ldap_scripts.append(entry)

        smb_summary: dict[str, str] = {}
        smb_shares: list[dict[str, str]] = []
        smb_notes: list[str] = []
        smb_account_used: str | None = None
        ldap_rootdse: list[dict[str, str]] = []
        for s in smb_ad_scripts:
            if s.get("id") == "smb-os-discovery":
                smb_summary.update(parse_smb_os(s.get("output")))
            elif s.get("id") == "smb2-security-mode":
                smb_summary.update(parse_smb2_security_mode(s.get("output")))
            elif s.get("id") == "smb2-time":
                smb_summary.update(parse_smb2_time(s.get("output")))
            elif s.get("id") == "smb-enum-shares":
                shares, notes, account = parse_smb_shares(s.get("output"))
                smb_shares.extend(shares)
                smb_notes.extend(notes)
                if account:
                    smb_account_used = account
        for s in ldap_scripts:
            if s.get("id") == "ldap-rootdse":
                ldap_rootdse.extend(parse_ldap_rootdse(s.get("output")))
        ldap_rootdse = summarize_ldap_rootdse(ldap_rootdse)

        rdp_info: dict[str, str] = {}
        rdp_cert: dict[str, str] = {}
        rdp_encryption: dict[str, str] = {}
        rdp_port = None
        for p in ports:
            if int(p.get("port", 0)) != 3389:
                continue
            rdp_port = p.get("port")
            for s in p.get("scripts", []) or []:
                sid = s.get("id")
                if sid == "rdp-ntlm-info":
                    rdp_info.update(parse_kv_lines(s.get("output")))
                if sid == "rdp-enum-encryption":
                    rdp_encryption.update(parse_kv_lines(s.get("output")))
                if sid == "ssl-cert":
                    rdp_cert.update(parse_ssl_cert(s.get("output")))

        rdp_dns_computer = None
        for key in ("DNS_Computer_Name", "DNS Computer Name"):
            if key in rdp_info:
                rdp_dns_computer = rdp_info[key]
                break

        for key in (
            "port",
            "Target_Name",
            "NetBIOS_Domain_Name",
            "NetBIOS_Computer_Name",
            "DNS_Domain_Name",
            "DNS_Computer_Name",
            "DNS_Tree_Name",
            "Product_Version",
        ):
            rdp_info.pop(key, None)

        ldap_dns_host = None
        for row in ldap_rootdse:
            if row.get("key") == "dnsHostName":
                ldap_dns_host = row.get("value")
                break


        # trim SMB summary to high-signal fields
        if smb_summary:
            cleaned: dict[str, str] = {}
            if smb_summary.get("OS"):
                cleaned["OS"] = smb_summary["OS"]
            domain = smb_summary.get("Domain name")
            forest = smb_summary.get("Forest name")
            if domain:
                cleaned["Domain"] = domain
            if forest and forest != domain:
                cleaned["Forest"] = forest
            if smb_summary.get("FQDN"):
                cleaned["FQDN"] = smb_summary["FQDN"]
            smb2 = smb_summary.get("SMB2")
            signing = smb_summary.get("Signing")
            if smb2 or signing:
                cleaned["SMB2"] = smb2 or ""
                if signing:
                    cleaned["Signing"] = signing
            if smb_summary.get("System time"):
                cleaned["System time"] = smb_summary["System time"]
            elif smb_summary.get("date"):
                cleaned["System time"] = smb_summary["date"]
            if smb_summary.get("start_date"):
                cleaned["Uptime (since)"] = smb_summary["start_date"]
            smb_summary = cleaned

        smb_os = smb_summary.get("OS") if smb_summary else None
        smb_fqdn = smb_summary.get("FQDN") if smb_summary else None
        rdp_os = None
        if rdp_info:
            pname = rdp_info.get("Product_Name") or rdp_info.get("Product Name")
            pver = rdp_info.get("Product_Version") or rdp_info.get("Product Version")
            if pver:
                friendly = windows_build_to_name(pver)
                if friendly:
                    rdp_os = friendly
                elif pname:
                    rdp_os = f"{pname} {pver}"
                else:
                    rdp_os = pver
            elif pname:
                rdp_os = pname

        if smb_os:
            os_display = smb_os
            os_source = "SMB"
        elif rdp_os:
            os_display = rdp_os
            os_source = "RDP"
        elif os_matches:
            os_display = os_matches[0].get("name")
            os_source = f"Nmap ({os_matches[0].get('accuracy', '')}%)"
        else:
            os_display = None
            os_source = None

        dns_display = None
        dns_source = None
        if ldap_dns_host:
            dns_display = ldap_dns_host
            dns_source = "LDAP"
        elif smb_fqdn:
            dns_display = smb_fqdn
            dns_source = "SMB"
        elif rdp_dns_computer:
            dns_display = rdp_dns_computer
            dns_source = "RDP"

        enriched.append({
            **h,
            "os_deduped": os_matches,
            "names": names,
            "os_top": os_matches[0] if os_matches else None,
            "os_display": os_display,
            "os_source": os_source,
            "smb_fqdn": smb_fqdn,
            "dns_display": dns_display,
            "dns_source": dns_source,
            "port_counts": port_counts(ports),
            "ports_sorted": sorted(ports, key=lambda x: (x.get("protocol",""), int(x.get("port", 0)))),
            "httpx_sorted": sorted(httpx, key=lambda x: (x.get("url") or x.get("host") or "")),
            "discovered_sorted": merge_discovered(katana_httpx, ferox),
            "screens": screens,
            "smb_ad_scripts": smb_ad_scripts,
            "ldap_scripts": ldap_scripts,
            "smb_summary": smb_summary,
            "smb_shares": smb_shares,
            "smb_notes": smb_notes,
            "smb_account_used": smb_account_used,
            "ldap_rootdse": ldap_rootdse,
            "ldap_dns_host": ldap_dns_host,
            "rdp_info": rdp_info,
            "rdp_cert": rdp_cert,
            "rdp_port": rdp_port,
            "rdp_dns_computer": rdp_dns_computer,
            "rdp_encryption": rdp_encryption,
        })

    # Sort hosts by open ports (desc), then IP
    def _host_sort_key(h: dict[str, Any]):
        return (
            -int(h.get("port_counts", {}).get("open", 0)),
            h.get("ip") or "",
        )
    enriched = sorted(enriched, key=_host_sort_key)

    # Summary stats
    os_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}
    open_ports: list[int] = []
    service_counts: dict[str, int] = {}
    for h in enriched:
        if h.get("os_display"):
            os_counts[h["os_display"]] = os_counts.get(h["os_display"], 0) + 1
        dns = h.get("dns_display")
        if dns and "." in dns:
            parts = dns.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        open_ports.append(int(h.get("port_counts", {}).get("open", 0)))
        for p in h.get("ports_sorted", []) or []:
            if p.get("state") != "open":
                continue
            svc = p.get("service")
            if svc:
                service_counts[svc] = service_counts.get(svc, 0) + 1

    top_os = sorted(os_counts.items(), key=lambda x: (-x[1], x[0]))[:3]
    top_domains = sorted(domain_counts.items(), key=lambda x: (-x[1], x[0]))[:5]
    top_services = sorted(service_counts.items(), key=lambda x: (-x[1], x[0]))[:5]
    max_open = max(open_ports) if open_ports else 0
    avg_open = round(sum(open_ports) / len(open_ports), 2) if open_ports else 0

    summary = {
        "top_os": top_os,
        "top_domains": top_domains,
        "top_services": top_services,
        "max_open": max_open,
        "avg_open": avg_open,
    }

    html_text = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        host_count=len(enriched),
        hosts=enriched,
        summary=summary,
        meta=meta or {},
    )

    out_html.write_text(html_text, encoding="utf-8")
    return out_html
