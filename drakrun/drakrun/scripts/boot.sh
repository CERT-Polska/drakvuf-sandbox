#!/bin/bash

# TODO this will be not included

# Run after system startup
xl sched-credit2 -d 0 -w 512
iptables -t nat -I POSTROUTING -o eno3 -j MASQUERADE
iptables -A INPUT -i xenbr0 -p icmp --icmp-type echo-request -d 10.13.37.1 -j ACCEPT
iptables -A INPUT -i xenbr0 -d 10.13.37.1/32 -p tcp -m multiport --dports 1024:65535 -j ACCEPT
iptables -A INPUT -i xenbr0 -d 10.13.37.0/24 -j DROP
iptables -I FORWARD -d 195.164.49.0/24 -j DROP
iptables -I FORWARD -s 10.13.37.0/24 -d 10.13.37.0/24 -j DROP
mount -t tmpfs -o size=2560m tmpfs /mnt/ramdisk
cp /opt/sandbox/win7.sav /mnt/ramdisk/
