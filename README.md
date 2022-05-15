# Linux Kernel FTP file system

This is a linux kernel implementation of a FTP file system.

Example :

    `mount -t ftpfs ftp.fr.debian.org -o username=anonymous,password=anonymous,cache_timeout_sec=10,nb_connections=3 /mnt/ftp/`
    
In this file system, inodes are identified by absolute path.

Regular files use netfs cache facility and directories use page cache buffer.
Since there is no notification on file change with FTP protocol, inodes (and page cache) need to be revalidated after 10 second. The revalidation occurs on next inode access (= on dentry revalidation).

The filesystem is synchronous (sb->s_flags |= SYNCHRONOUS) because we want to push file changes on FTP as soon as possible.

The filesystem uses a pool of FTP sessions and use inactive sessions in priority. If all sessions are active, sessions can be shared between processes but it's much slower because a single FTP session can't handle parallel requests.
For example, if a file copy uses 2 different sessions for files "src" and "dst", ftpfs can achieve real copy with only 2 FTP requests (RETR to read "src" sequentially and STOR to write "dst" sequentially).
But if the file copy shares the same session between read and write, ftpfs will have to stop RETR/STOR request after each read()/write() system call.
