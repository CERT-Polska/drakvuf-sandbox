#!/bin/bash


cat <<EOF >> /etc/apt/sources.list.d/buster-backports.list
deb http://deb.debian.org/debian buster-backports main contrib
deb-src http://deb.debian.org/debian buster-backports main contrib
EOF

cat <<EOF >> /etc/apt/preferences.d/90_zfs
Package: libnvpair1linux libuutil1linux libzfs2linux libzpool2linux spl-dkms zfs-dkms zfs-test zfsutils-linux zfsutils-linux-dev zfs-zed
Pin: release n=buster-backports
Pin-Priority: 990
EOF

apt-get update
apt-get install -y dpkg-dev linux-headers-$(uname -r) linux-image-amd64
apt-get install -y zfs-dkms zfsutils-linux
