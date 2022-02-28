#!/usr/bin/env bash

# update kernel version
dnf update -y

# install additional dependencies
dnf install -y clang vim llvm gcc libbpf libbpf-devel libsodium-devel libcurl-devel libxdp xdp-tools bpftool traceroute curl nmap trace-cmd strace tcpdump glibc-devel.i686

# setup httpd
dnf install -y httpd

echo "<!DOCTYPE html>" >> /var/www/html/index.html
echo "<html>" >> /var/www/html/index.html
echo "        <body>" >> /var/www/html/index.html
echo "                <h1>Web Server</h1>" >> /var/www/html/index.html
echo "        </body>" >> /var/www/html/index.html
echo "</html>" >> /var/www/html/index.html

systemctl enable httpd
systemctl restart httpd

systemctl reboot

echo "192.168.56.12 nyatta" >> /etc/hosts
