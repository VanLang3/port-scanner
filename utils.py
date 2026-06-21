import re


def is_valid_ip(ip):
    """Return True if ip is a valid IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def is_private_ip(ip):
    """Return True if IP is RFC1918 private (not routable on internet)."""
    return (ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172."))


def parse_port_input(port_str):
    """
    Parse user port input into a list of ints.
    Accepts: "80", "80,443,8080", "1-1024"
    Returns: list of ints
    """
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))