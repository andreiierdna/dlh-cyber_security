# Passive Reconnaissance Report: holbertonschool.com

This report consolidates target data collected via **WhatWeb** fingerprinting and **Shodan** passive keyword searches. The information maps routing behavior, infrastructure providers, and underlying technologies.

---

## 1. Domain Redirection & Routing Flow

The root domain `holbertonschool.com` actively forces secure HTTPS traffic before handing off users via a cascading redirection chain to a target destination platform (`hbtn.dev`).

| Origin URL | Status Code | Destination URL | Primary Action |
| --- | --- | --- | --- |
| `http://holbertonschool.com` | `301 Moved Permanently` | `https://holbertonschool.com/` | Forces upgrade to HTTPS |
| `https://holbertonschool.com` | `301 Moved Permanently` | `https://hbtn.dev/` | Cross-domain redirect to live site |
| `https://holbertonschool.com/` | `301 Moved Permanently` | `https://hbtn.dev/` | Canonical trailing slash normalization |
| `https://hbtn.dev/` | **`200 OK`** | *N/A (Final Landing Page)* | Resolves successfully |

---

## 2. Infrastructure & Fingerprint Summary

The destination endpoint and core proxies share a single frontend IP presence optimized by edge security providers.

| Asset / Parameter | Observed Value & Details |
| --- | --- |
| **Resolved IP (Core)** | `198.202.211.1` |
| **Geo-Location** | United States (`US`) |
| **Edge Web Server** | Cloudflare / OpenResty (Nginx-based engine) |
| **Security Headers** | `Strict-Transport-Security` (HSTS enabled for 1 year, subdomains preloaded) |
| **Session Cookies** | `_cfuvid` (Cloudflare User ID cookie set with `HttpOnly` flags) |
| **Custom / Uncommon Headers** | `cf-ray`, `cf-cache-status`, `surrogate-control`, `surrogate-key`, `x-wf-region`, `x-lambda-id` |

---

## 3. Technology Stack & Frameworks

The final target endpoint (`hbtn.dev`) features structural integration with standard commercial marketing tools, web builders, and embedded media.

| Technology Component | Category | Purpose / Details |
| --- | --- | --- |
| **Webflow** | CMS / Generator | Core frontend layout builder (`MetaGenerator`) |
| **HTML5** | Markup Language | Modern document structure compliance |
| **jQuery** | JavaScript Library | Client-side scripting and browser compatibility |
| **Open-Graph-Protocol** | Metadata Framework | Social media link preview optimization (`type: website`) |
| **JSON-LD** | Structured Data | `application/ld+json` search engine schemas |
| **YouTube** | Media Integration | Embedded video elements / video hosting dependency |

---

## 4. Shodan Discovered Hosts & Network Edge

Passive keyword sweeps across Shodan expose actual origin network elements hosted behind standard public cloud platforms. This infrastructure is deployed on Amazon Web Services (AWS) in the EU-West-3 (Paris) region.

| Target Hostname / Pointer | Associated IP Address | Server Daemon | Operating System Info |
| --- | --- | --- | --- |
| `yriry2.holbertonschool.com` | `52.47.143.83` | `nginx` | Standard reverse proxy configuration |
| `ec2-52-47-143-83.eu-west-3.compute.amazonaws.com` | `52.47.143.83` | `nginx/1.21.6` | Custom/Updated standalone Nginx |
| `ec2-35-180-27-154.eu-west-3.compute.amazonaws.com` | `35.180.27.154` | `nginx/1.18.0` | Linux deployment (**Ubuntu Linux**) |
