#!/usr/bin/env python3
"""Module that checks if a specific port is open on a host."""
import socket


def check_port(host, port):
    """Check whether a TCP port on a given host is open.

    Args:
        host (str): The hostname or IP address to check.
        port (int): The port number to check.

    Returns:
        bool: True if the port is open, False if closed or unreachable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            return result == 0
    except (socket.gaierror, socket.timeout, OSError):
        return False
