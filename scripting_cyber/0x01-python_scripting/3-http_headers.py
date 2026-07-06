#!/usr/bin/env python3
"""Module that retrieves and displays HTTP response headers from a URL."""
import requests


def get_http_headers(url):
    """Retrieve HTTP response headers from a given URL.

    Args:
        url (str): The URL to send the GET request to.

    Returns:
        dict: A dictionary containing 'status_code' and 'headers'
            if the request succeeds.
        None: If the request fails.
    """
    try:
        response = requests.get(url)
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }
    except requests.exceptions.RequestException:
        return None
