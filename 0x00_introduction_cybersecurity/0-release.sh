#!/bin/bash
grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"'
