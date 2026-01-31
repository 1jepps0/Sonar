import json
import subprocess
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

def dedupe_os_matches(os_matches):
    deduped = {}

    for match in os_matches:
        name = match["name"]
        acc = match["accuracy"]

        if name not in deduped or acc > deduped[name]["accuracy"]:
            deduped[name] = match

    return sorted(
        deduped.values(),
        key=lambda x: x["accuracy"],
        reverse=True
    )

def prefer_specific(matches):
    return [
        m for m in matches
        if " or " not in m["name"]
    ] or matches

def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)

    hosts = []
    for host in root.findall("host"):
        addr = host.find("address").attrib.get("addr")
        ports = []
        os_matches = []
        host_scripts = []

        # get OS matches
        for osmatch in host.findall(".//osmatch"):
            os_matches.append({
                "name": osmatch.attrib.get("name"),
                "accuracy": int(osmatch.attrib.get("accuracy", 0))
            })
            
        # remove dupes & multiple os detects, and only grab top 3
        os_matches = prefer_specific(dedupe_os_matches(os_matches))[:3]
        
        # Host-level scripts
        for s in host.findall("./hostscript/script"):
            host_scripts.append({
                "id": s.attrib.get("id"),
                "output": s.attrib.get("output"),
            })

        # Ports, protocols, services
        for port in host.findall(".//port"):
            if port.find("state").attrib["state"] == "closed": continue
            service_elem = port.find("service")
            scripts = []
            for s in port.findall("script"):
                scripts.append({
                    "id": s.attrib.get("id"),
                    "output": s.attrib.get("output"),
                })
            cpes = []
            if service_elem is not None:
                for c in service_elem.findall("cpe"):
                    if c.text:
                        cpes.append(c.text)
            ports.append({
                "port": int(port.attrib["portid"]),
                "protocol": port.attrib["protocol"],
                "state": port.find("state").attrib["state"],
                "service": service_elem.attrib.get("name") if service_elem is not None else None,
                "product": service_elem.attrib.get("product") if service_elem is not None else None,
                "version": service_elem.attrib.get("version") if service_elem is not None else None,
                "extrainfo": service_elem.attrib.get("extrainfo") if service_elem is not None else None,
                "tunnel": service_elem.attrib.get("tunnel") if service_elem is not None else None,
                "cpe": cpes,
                "scripts": scripts,
            })

        # domain name
        names = []
        for hn in host.findall("./hostnames/hostname"):
            name = hn.attrib.get("name")
            if name:
                names.append(name.rstrip(".").lower())


        # combine all
        hosts.append({
            "ip": addr,
            "os": os_matches, 
            "ports": ports,
            "names": names,
            "host_scripts": host_scripts,
        })

    return hosts


def nmap_scan(targets, extra_args=None, raw_dir: str | None = None):
    if isinstance(targets, str):
        target_list = [targets]
    else:
        target_list = [t for t in targets if t]
    if not target_list:
        raise ValueError("No nmap targets provided")

    cmd = [
        "nmap",
        "-Pn",
        "-O",
        "-sS",
        "-sV",
        "--script", "default,smb-enum-shares,smb-os-discovery,smb2-security-mode,smb2-time,ldap-rootdse,rdp-ntlm-info,rdp-enum-encryption,ssl-cert",
        "--top-ports", "1000",
        #"-p", "53",

        "--max-retries", "2",
        "--host-timeout", "5m",
        # "-T4" breaks parser for some reason
        "-oX", "-",      # XML output to stdout
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend(target_list)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    if raw_dir:
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        meta = {
            "timestamp_utc": ts,
            "tool": "nmap",
            "cmd": cmd,
            "targets": target_list,
            "returncode": result.returncode,
        }
        prefix = Path(raw_dir) / f"nmap_{ts.replace(':', '').replace('-', '')}"
        (prefix.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (prefix.with_suffix(".xml")).write_text(result.stdout, encoding="utf-8")
        if result.stderr:
            (prefix.with_suffix(".stderr")).write_text(result.stderr, encoding="utf-8")

    return result.stdout
