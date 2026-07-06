#!/usr/bin/env python3
"""Module that resolves a domain name to its IPv4 address."""
import socket


def resolve_domain_to_ipv4(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None
    except Exception as e:
        return f"Error: {e}"

