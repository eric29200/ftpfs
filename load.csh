#!/bin/csh

sudo umount /mnt/ftp
sudo rmmod ftpfs
make
sudo modprobe dns_resolver
sudo insmod ftpfs.ko
sudo mount -t ftpfs ftp.fr.debian.org /mnt/ftp/
#sudo mount -t ftpfs ftp.fr.debian.org -o cache_expires_sec=60,username=anonymous,password=anonymous /mnt/ftp/
