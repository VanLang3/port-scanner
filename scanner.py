import socket

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