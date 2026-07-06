#!/usr/bin/env python3
"""Module that downloads a web page and returns formatted HTML content."""
import requests
from bs4 import BeautifulSoup


def download_page(url):
    """Download a web page and return its formatted HTML content.

    Args:
        url (str): The URL of the web page to download.

    Returns:
        str: The prettified HTML content if successful,
             otherwise an error message string.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.prettify()
    except requests.exceptions.RequestException as e:
        return f"Error downloading page: {e}"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 2-download_page.py <url>")
        sys.exit(1)

    page_url = sys.argv[1]
    print(download_page(page_url))
