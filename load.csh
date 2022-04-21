#!/bin/csh

sudo umount mnt
sudo rmmod ftpfs
make
sudo modprobe dns_resolver
sudo insmod ftpfs.ko
sudo mount -t ftpfs ftpfs mnt/
