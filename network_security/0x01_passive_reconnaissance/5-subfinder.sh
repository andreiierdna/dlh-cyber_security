#!/bin/bash
subfinder -d "$1" -silent | tee /dev/tty | xargs -I {} sh -c 'ip=$(dig +short "{}" | tail -n1); [ -n "$ip" ] && echo "{},$ip"' > "$1.txt"
