# Port Scanner

A command-line port scanner built in Python from scratch for educational purposes.

## Project structure

```
port_scanner/
├── scanner.py        # main script — run this
├── utils.py          # helper functions (IP validation, output formatting)
├── results/          # JSON output files go here
└── README.md
```

## Requirements

Python 3.6+. Uses only built-in libraries: `socket`, `json`, `threading`, `argparse`.

## Usage

```bash
# Scan common ports
python scanner.py 192.168.1.1 -p 22,80,443

# Scan a port range with threading
python scanner.py scanme.nmap.org -p 1-1024 -t 50

# Save results to JSON
python scanner.py scanme.nmap.org -p 1-1024 -o
```

### Options

| Flag | Description |
|------|-------------|
| `target` | IP address to scan (required) |
| `-p, --ports` | Ports to scan: `80`, `22,80,443`, or `1-1024` (default: `1-1024`) |
| `-t, --threads` | Max concurrent threads (default: 100) |
| `--timeout` | Timeout per port in seconds (default: 1.0) |
| `-o, --output` | Save results to a JSON file in `results/` |

## Legal note

Only scan hosts you own or have explicit permission to scan. [scanme.nmap.org](https://scanme.nmap.org/) is a legal public target maintained by the nmap project for testing scanners.
