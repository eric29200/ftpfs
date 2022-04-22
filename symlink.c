#include "ftpfs.h"

/*
 * Read target link.
 */
static int ftpfs_readlink(struct dentry *dentry, char __user *buf, int buf_len)
{
  struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(dentry->d_inode);
  int len;
  
  /* check link */
  if (!S_ISLNK(dentry->d_inode->i_mode) || !ftpfs_inode->i_cache.data)
    return -ENOLINK;

  /* compute link length */
  len = ftpfs_inode->i_cache.len;
  if (len > buf_len)
    len = buf_len;

  /* copy to user buffer */
  if (copy_to_user(buf, ftpfs_inode->i_cache.data, len))
    return -EFAULT;

  return len;
}

/*
 * FTPFS symbolic link inode operations.
 */
struct inode_operations ftpfs_symlink_iops = {
  .readlink       = ftpfs_readlink,
};
