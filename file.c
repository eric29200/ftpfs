#include "ftpfs.h"

/*
 * Read a file.
 */
ssize_t ftpfs_file_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  return -EPERM;
}

/*
 * FTPFS file operations.
 */
struct file_operations ftpfs_file_fops = {
  .read         = ftpfs_file_read,
};

/*
 * FTPFS file inode operations.
 */
struct inode_operations ftpfs_file_iops = {
  
};
