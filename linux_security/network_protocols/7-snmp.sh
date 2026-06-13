#!/bin/bash
grep -v '^[[:space:]]*#' /etc/snmp/snmpd.conf 2>/dev/null | grep -iE '\b(public)\b'
