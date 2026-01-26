# Recon Automation Script

## Overview
This project runs Nmap for host/port discovery, enriches web services with httpx, crawls discovered URLs with katana, and renders an HTML report.

## Requirements

### System tools
- `nmap` (OS/port scanning; XML output)
- `httpx-toolkit` (web probing + metadata)
- `katana` (crawler for URL discovery)
- `feroxbuster` (content discovery brute force)
- `chromium` (headless screenshots)
- `nmap` (Kerberos user enum via krb5-enum-users)

### Python
- Python 3.11+ recommended
- Dependencies in `requirements.txt`:
  - `Jinja2`
  - `MarkupSafe`

### Optional
- Go toolchain (only required if you install katana via `go install`)

## Install (Kali)

```bash
sudo apt update
sudo apt install -y nmap httpx-toolkit feroxbuster chromium python3 python3-venv
```

### Katana
If installed via Go:

```bash
sudo apt install -y golang
go install github.com/projectdiscovery/katana/cmd/katana@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Python setup

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 main.py --cidr 192.168.56.0/24
```

Output report:
- `output/report.html`
