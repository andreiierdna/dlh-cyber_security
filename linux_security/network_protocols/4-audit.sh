#!/bin/bash
awk '!/^\s*(#|$)/' /etc/ssh/sshd_config
