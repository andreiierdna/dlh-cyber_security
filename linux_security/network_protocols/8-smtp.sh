#!/bin/bash
postconf | grep "^smtpd_tls_security_level" /etc/postfix/main.cf || echo "STARTTLS not configured"
