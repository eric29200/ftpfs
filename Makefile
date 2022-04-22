obj-m		+= ftpfs.o
ftpfs-y 	:= ftp.o super.o inode.o namei.o dir.o file.o symlink.o

KERNELDIR 	?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
