#!/usr/bin/env bash

# install additional dependencies
dnf update -y
dnf install -y gcc vim libsodium-devel libpcap-devel libcurl-devel traceroute nmap trace-cmd strace tcpdump curl

systemctl reboot

echo "192.168.56.11 nyako" >> /etc/hosts
