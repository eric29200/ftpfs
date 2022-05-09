obj-m		+= ftpfs.o
ftpfs-y 	:= ftp_utils.o ftp_session.o ftp_cmd.o super.o inode.o namei.o dir.o file.o symlink.o dentry.o cache.o

KERNELDIR 	?= /lib/modules/$(shell uname -r)/build

default:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
