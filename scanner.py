import argparse
import json
import os
import socket
import threading # used for multitasking 
from datetime import datetime

from utils import is_valid_ip, is_private_ip, parse_port_input


def scan_port(ip, port, timeout=1):
    """
    Attempt a TCP connection to ip:port.
    Returns True if open, False if closed or filtered.
    timeout: seconds to wait before giving up
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def grab_banner(ip, port, timeout=2):
    """
    Connect to an open port and read the first response.
    Returns banner string or None if nothing is sent.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # For HTTP, we need to send a request first
        if port in (80, 8080, 443, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner if banner else None
    except Exception:
        return None


def scan_range(ip, ports, timeout=1):
    """
    Scan a list of ports on a single IP.
    Returns a dict: { port: True/False }
    ports: list of ints, e.g. [22, 80, 443, 8080]
    """
    results = {}
    for port in ports:
        is_open = scan_port(ip, port, timeout)
        if is_open:
            banner = grab_banner(ip, port)
            if banner:
                first_line = banner.split('\n')[0]
                print(f"  {ip}:{port:>5}  —  OPEN  |  {first_line}")
            else:
                print(f"  {ip}:{port:>5}  —  OPEN")
        else:
            print(f"  {ip}:{port:>5}  —  closed")
        results[port] = is_open
    return results


def scan_range_threaded(ip, ports, timeout=1, max_threads=100):
    """
    Scan ports concurrently using threads.
    max_threads: how many simultaneous connections (keep under 200)
    """
    results = {}
    lock = threading.Lock()

    def scan_worker(port):
        is_open = scan_port(ip, port, timeout)
        with lock:
            results[port] = is_open
            if is_open:
                banner = grab_banner(ip, port)
                if banner:
                    first_line = banner.split('\n')[0]
                    print(f"  OPEN  {ip}:{port}  |  {first_line}")
                else:
                    print(f"  OPEN  {ip}:{port}")

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_worker, args=(port,))
        threads.append(t)
        t.start()

        # Limit concurrent threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads
    for t in threads:
        t.join()

    return results


def save_results(ip, results, output_dir="results"):
    """
    Save scan results as a JSON file.
    Filename includes IP and timestamp.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/scan_{ip.replace('.', '_')}_{timestamp}.json"

    open_ports = [port for port, is_open in results.items() if is_open]

    output = {
        "target": ip,
        "scanned_at": timestamp,
        "total_ports_scanned": len(results),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "full_results": {str(port): is_open for port, is_open in results.items()}
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: {filename}")
    return filename


def main():
    parser = argparse.ArgumentParser(
        description="Port scanner — educational security tool"
    )
    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan. Examples: 80, 22,80,443, 1-1024")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout per port in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", action="store_true",
                        help="Save results to JSON file")
    args = parser.parse_args()

    # Validate input
    if not is_valid_ip(args.target):
        print(f"Error: '{args.target}' is not a valid IP address")
        return

    ports = parse_port_input(args.ports)
    print(f"\nScanning {args.target} — {len(ports)} ports\n")

    results = scan_range_threaded(args.target, ports, args.timeout, args.threads)

    open_ports = [p for p, o in results.items() if o]
    print(f"\nDone. {len(open_ports)} open port(s) found.")

    if args.output:
        save_results(args.target, results)


if __name__ == "__main__":
    main()
