#!/usr/bin/env bash

# update kernel version
dnf update -y
dnf install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
dnf makecache
dnf --enablerepo="elrepo-kernel" install -y --allowerasing kernel-ml kernel-ml-devel kernel-ml-headers

# install additional dependencies
dnf install -y clang bpftool
systemctl reboot

echo "192.168.56.11 nyako" >> /etc/hosts
echo "192.168.56.12 nyatta" >> /etc/hosts

