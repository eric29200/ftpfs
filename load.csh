#!/bin/csh

sudo umount mnt
sudo rmmod ftpfs
make
sudo insmod ftpfs.ko
sudo mount -t ftpfs ftpfs mnt/
