#!/bin/bash

apt install python3

apt install python3-pip

pip3 install scapy

apt install libpam-google-authenticator

cp ./sshd /etc/pam.d/sshd
systemctl restart sshd.service
cp ./sshd_config /etc/ssh/sshd_config
google-authenticator
