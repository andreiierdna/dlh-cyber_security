#!/usr/bin/env python3
"""Recursive web crawler that discovers internal links up to a max depth."""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    """Recursively crawl a website and return visited same-domain URLs."""
    visited = set()
    try:
        domain = urlparse(start_url).netloc
    except (ValueError, AttributeError):
        return visited
    if not domain:
        return visited
    _crawl(start_url, max_depth, domain, visited)
    return visited


def _crawl(url, depth, domain, visited):
    """Helper that performs the actual recursive crawling."""
    if depth < 0 or url in visited:
        return
    if urlparse(url).netloc != domain:
        return

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.Timeout:
        return
    except requests.exceptions.RequestException:
        return
    except ValueError:
        return

    visited.add(url)
    print(f"Crawling: {url}")

    if depth == 0:
        return

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception:
        return

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        try:
            absolute_url = urljoin(url, href)
        except ValueError:
            continue

        parsed = urlparse(absolute_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc != domain:
            continue
        if absolute_url in visited:
            continue

        _crawl(absolute_url, depth - 1, domain, visited)
