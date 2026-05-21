#!/bin/bash
useradd /bin/sh "$1"
echo "$1:$2" | chpasswd
