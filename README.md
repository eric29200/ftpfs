# Linux Kernel FTP file system

This is a read-only linux kernel implementation of a FTP file system.

Example :
    mount -t ftpfs ftp.fr.debian.org -o username=anonymous,password=anonymous,cache_timeout_sec=10,nb_connections=3 /mnt/ftp/
    
In this file system, inodes are identified by full path.
Read functions (readdir/read) use page cache buffer. Since there is no notification on file change with FTP protocol, the page buffer cache and the inode are revalidated each 10 seconds. Dentries must also be revalidated at each access.

For directory listing and name resolution (readdir/find_entry), the file system uses only one connection (the main connection/session). Because FTP session can't handle parallel requests, the FTP connection/session is locked in these functions.

For regular file, the filesystem uses a pool of FTP connections (number of connections is defined by the parameter nb_connections).
When a process opens a file, the filesystem try to obtain/lock a free FTP connection. On success, this connection will be used to read the file and will be released on file closure. With this exclusive connection, full sequential read of a file (for example copy) can be done with only one FTP request (RETR command).
If no free FTP connection is available, the file uses the main/shared connection. But read will be much slower, since the RETR request will be stopped after each page read.
