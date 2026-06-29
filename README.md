# Python Port Scanner

A multithreaded TCP port scanner built from scratch in Python. Scans individual hosts for open ports, grabs service banners to identify running software, and outputs structured JSON results. Built as a foundational security engineering project to understand network reconnaissance at the socket level.

---

## Why this exists

Most security analysts use nmap without understanding what's happening underneath. This project rebuilds that core functionality from first principles — raw TCP socket connections, concurrent threading, and service identification via banner grabbing — to develop a genuine understanding of how network scanning works and how defenders can detect it.

---

## Features

- **TCP connect scanning** via raw sockets — no external dependencies for core scanning
- **Multithreaded** — scans 1000+ ports in under 10 seconds using configurable thread pool
- **Banner grabbing** — reads service responses to identify software and versions on open ports
- **Input validation** — validates IPv4 addresses and parses flexible port expressions (`22`, `1-1024`, `22,80,443`)
- **JSON output** — structured results file for downstream ingestion by other tools or SIEMs
- **Threat intel lookup** — optional AbuseIPDB check before scanning (`--intel`)
- **Webhook alerting** — POST to Slack/Discord when high-risk ports open (`--alert`)
- **CLI interface** — argparse-based flags matching standard tool conventions

---

## Demo

```
$ python scanner.py scanme.nmap.org -p 1-1024 -o

Scanning scanme.nmap.org — 1024 ports

  OPEN  scanme.nmap.org:22   |  SSH-2.0-OpenSSH_6.6.1p1
  OPEN  scanme.nmap.org:80   |  HTTP/1.1 200 OK

Done. 2 open port(s) found in 8.3s
Results saved to: results/scan_scanme_nmap_org_20240615_143022.json
```

**JSON output structure:**

```json
{
  "target": "scanme.nmap.org",
  "scanned_at": "20240615_143022",
  "total_ports_scanned": 1024,
  "open_ports": [22, 80],
  "open_count": 2,
  "full_results": {
    "22": true,
    "80": true,
    "443": false
  }
}
```

---

## Installation

Core scanning uses only the Python standard library. Threat intel lookup requires `requests`.

```bash
git clone https://github.com/yourusername/port-scanner
cd port-scanner
pip install -r requirements.txt
python scanner.py --help
```

For `--intel`, create a free API key at [abuseipdb.com](https://www.abuseipdb.com/) and export it:

```bash
export ABUSEIPDB_API_KEY="your_key_here"
```

**Webhook setup (`--alert`):**

- **Slack:** Apps → Incoming Webhooks → Add to workspace → copy URL
- **Discord:** Server Settings → Integrations → Webhooks → New Webhook → copy URL

```bash
export WEBHOOK_URL="https://hooks.slack.com/services/..."
# or
export WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

---

## Usage

```bash
# Scan common ports
python scanner.py 192.168.1.1 -p 22,80,443,3306,8080

# Scan a range
python scanner.py 192.168.1.1 -p 1-1024

# Scan with more threads and save output
python scanner.py 192.168.1.1 -p 1-65535 -t 200 -o

# Adjust timeout (useful for slow networks)
python scanner.py 192.168.1.1 -p 1-1024 --timeout 2.0

# Check AbuseIPDB reputation before scanning
python scanner.py 45.33.32.156 -p 22,80,443 --intel

# Threat intel + save JSON (intel included in output file)
python scanner.py 45.33.32.156 -p 22,80,443 --intel -o

# Alert Slack/Discord if high-risk ports (22, 3389, etc.) are open
export WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python scanner.py 192.168.1.1 -p 1-1024 --alert

# Full pipeline: intel check, scan, save JSON, alert on risk
python scanner.py 45.33.32.156 -p 1-1024 --intel -o --alert
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `target` | required | IPv4 address to scan |
| `-p`, `--ports` | `1-1024` | Port expression: single, range, or comma-separated |
| `-t`, `--threads` | `100` | Max concurrent threads |
| `--timeout` | `1.0` | Seconds to wait per port |
| `-o`, `--output` | off | Save results to JSON file |
| `--intel` | off | Query AbuseIPDB for IP reputation before scanning |
| `--alert` | off | Send Slack/Discord webhook if high-risk ports are open |
| `--webhook` | env `WEBHOOK_URL` | Override webhook URL for `--alert` |

---

## How it works

**Phase 1 — TCP connect scan**

Each port is tested with `socket.connect_ex()`, which attempts a full TCP three-way handshake. A return value of `0` means the port accepted the connection (open). Any non-zero value indicates the port is closed or filtered by a firewall.

```python
def scan_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0
```

**Phase 2 — Banner grabbing**

On confirmed open ports, the scanner reads the first 1024 bytes the service sends. For HTTP ports, it sends a minimal HEAD request first. The banner reveals the service type and version — the same data vulnerability scanners use to cross-reference CVE databases.

**Phase 3 — Threading**

A thread pool with a configurable ceiling runs scans concurrently. A `threading.Lock()` protects the shared results dictionary from race conditions when multiple threads write simultaneously.

---

## Security relevance

| Concept | Where it appears in the real world |
|--------|-----------------------------------|
| TCP connect scanning | MITRE ATT&CK T1046 — Network Service Discovery |
| Banner grabbing | Vulnerability scanners (Nessus, Qualys) use this to map CVEs to running software |
| Port sweep detection | SOC teams write SIEM rules to flag hosts scanning >N ports in <T seconds |
| JSON output | Standard format for SIEM ingestion and security pipeline automation |

Understanding how this tool works helps write better detections against it. A scanner hitting 1000 ports from one source IP in under 10 seconds produces a very specific traffic signature.

---

## Known limitations

- **TCP only** — UDP scanning requires raw sockets and elevated privileges, not implemented
- **Single host** — does not support CIDR range scanning (e.g. `192.168.1.0/24`)
- **No evasion** — high thread counts will trigger IDS/IPS on monitored networks
- **IPv4 only** — IPv6 not supported
- **Firewall behavior** — hosts that silently drop packets (filtered) are indistinguishable from offline hosts at the default timeout

---

## What I'd build next

- CIDR range support to scan an entire subnet
- CVE lookup via NVD API using grabbed banner versions
- UDP scanning mode
- Rate limiting option to evade basic IDS thresholds
- VirusTotal / Shodan enrichment alongside AbuseIPDB

---

## Legal

Only scan hosts you own or have explicit written permission to scan. `scanme.nmap.org` is a legal public target maintained by the nmap project for testing purposes.

Unauthorized port scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in other jurisdictions.

---

## Built with

- `socket` — TCP connection and banner grabbing
- `threading` — concurrent port scanning
- `argparse` — CLI interface
- `json` — structured output
- `re` — IP validation and input parsing
- `requests` — AbuseIPDB threat intel + Slack/Discord webhooks (optional)

---

*Part of a security engineering project series focused on building foundational tools from scratch to develop genuine understanding of the concepts behind professional security software.*