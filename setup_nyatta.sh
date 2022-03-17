#!/usr/bin/env bash

# install additional dependencies
dnf update -y
dnf install -y gcc vim libsodium-devel libpcap-devel libcurl-devel libnet-devel traceroute nmap trace-cmd strace tcpdump curl

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

echo "192.168.56.11 nyako" >> /etc/hosts
