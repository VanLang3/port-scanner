import os
from datetime import datetime

import requests

# Ports that are risky when exposed unexpectedly on a host
DEFAULT_HIGH_RISK_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def get_high_risk_open_ports(open_ports, watch_ports=None):
    """
    Return {port: service_name} for open ports that match the watch list.
    """
    watch = watch_ports or DEFAULT_HIGH_RISK_PORTS
    return {port: watch[port] for port in open_ports if port in watch}


def format_alert_message(target, high_risk, open_ports, threat_intel=None):
    """Build a formatted alert string for Slack or Discord."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "🚨 *Port Scanner Security Alert*",
        f"*Target:* `{target}`",
        f"*Time:* {timestamp}",
        "",
        "*High-risk open ports detected:*",
    ]

    for port, service in sorted(high_risk.items()):
        lines.append(f"  • Port {port} ({service}) — OPEN")

    lines.extend([
        "",
        f"*Total open ports:* {len(open_ports)}",
        f"*All open ports:* {', '.join(str(p) for p in sorted(open_ports)) or 'none'}",
    ])

    if threat_intel:
        lines.extend([
            "",
            "*Threat intel (AbuseIPDB):*",
            f"  • Abuse score: {threat_intel['abuse_confidence_score']}/100",
            f"  • Reports: {threat_intel['total_reports']}",
            f"  • Flagged: {'yes' if threat_intel['flagged'] else 'no'}",
        ])

    lines.append("")
    lines.append("_Automated alert from port-scanner_")
    return "\n".join(lines)


def _build_webhook_payload(message, webhook_url):
    """Slack uses 'text'; Discord uses 'content'. Auto-detect from URL."""
    if "discord.com" in webhook_url:
        return {"content": message}
    return {"text": message}


def send_webhook_alert(webhook_url, message):
    """
    POST an alert to a Slack or Discord incoming webhook.
    Returns True on success, False on failure.
    """
    payload = _build_webhook_payload(message, webhook_url)

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Webhook alert failed: {e}")
        return False


def maybe_send_alert(target, open_ports, threat_intel=None, webhook_url=None):
    """
    Check for high-risk ports and send a webhook alert if any are found.
    Returns True if an alert was sent.
    """
    webhook_url = webhook_url or os.environ.get("WEBHOOK_URL")
    if not webhook_url:
        print("Warning: --alert set but no webhook URL provided.")
        print("Use --webhook URL or export WEBHOOK_URL='https://...'\n")
        return False

    high_risk = get_high_risk_open_ports(open_ports)
    if not high_risk:
        print("\nNo high-risk ports open — alert not sent.")
        return False

    message = format_alert_message(target, high_risk, open_ports, threat_intel)
    if send_webhook_alert(webhook_url, message):
        print(f"\nAlert sent — {len(high_risk)} high-risk port(s) reported to webhook.")
        return True
    return False
