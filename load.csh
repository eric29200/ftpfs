#!/bin/csh

sudo umount /mnt/ftp
sudo rmmod ftpfs
make
sudo modprobe dns_resolver
sudo insmod ftpfs.ko
sudo mount -t ftpfs ftp.fr.debian.org /mnt/ftp/
#sudo mount -t ftpfs ftp.fr.debian.org -o username=anonymous,password=anonymous,cache_timeout_sec=20,nb_connections=2 /mnt/ftp/
