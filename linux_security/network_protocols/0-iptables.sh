#!/bin/bash
# Ensure the script is being run with root privileges

if [ "$EUID" -ne 0 ]; then

   echo "Error: This script must be run as root. Please use 'sudo'."

   exit 1

fi

# Display all iptables rules with verbose stats and line numbers

iptables -vnL --line-numbers
