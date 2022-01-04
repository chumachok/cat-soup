#!/usr/bin/env bash

# update kernel version
dnf update -y
dnf install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
dnf makecache
dnf --enablerepo="elrepo-kernel" install -y --allowerasing kernel-ml kernel-ml-devel kernel-ml-headers

# install additional dependencies
dnf config-manager --set-enabled powertools
dnf install -y clang llvm gcc libbpf libbpf-devel libxdp xdp-tools bpftool traceroute curl nmap

# setup httpd
dnf install -y httpd
systemctl enable httpd
systemctl start httpd

firewall-cmd --permanent --zone=public --add-service=http --add-service=https
firewall-cmd --reload

systemctl reboot

echo "192.168.56.12 nyatta" >> /etc/hosts
