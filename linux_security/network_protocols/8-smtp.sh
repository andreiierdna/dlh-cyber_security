#!/bin/bash
postconf -h smtpd_tls_security_level smtpd_use_tls 2>/dev/null | grep -qiE '^(encrypt|yes|may)$' || echo "STARTTLS not configured"
