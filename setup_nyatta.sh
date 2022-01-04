#!/usr/bin/env bash

# install additional dependencies
dnf config-manager --set-enabled powertools
dnf update -y
dnf install -y gcc libsodium-devel libpcap-devel libcurl-devel traceroute nmap

systemctl reboot

echo "192.168.56.11 nyako" >> /etc/hosts
