#!/bin/csh

rm -f /var/tmp/a /var/tmp/a.swp ~/.a.swp
./load.csh
vi /mnt/ftp/home/eric/a
