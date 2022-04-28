# Linux Kernel FTP file systems 

Example :
    mount -t ftpfs ftp.fr.debian.org -o username=anonymous,password=anonymous /mnt/ftp/
    
- On each FTP request (for example RETR or LIST), the filesystem connects to the server and executes the request.
- Inodes are identified by absolute path (no inode number).
- When inodes are dropped, associated dentries are released/deleted. This is useful for local/remote synchronization. 
