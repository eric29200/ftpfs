#include "ftpfs.h"

/*
 * Get target link.
 */
static const char *ftpfs_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *callback)
{
  /* inode must be a link */
  if (!S_ISLNK(inode->i_mode))
    return ERR_PTR(-ENOLINK);
  
  /* target link is stored in inode cached data */
  return ftpfs_i(inode)->i_cache.data;
}

/*
 * FTPFS symbolic link inode operations.
 */
struct inode_operations ftpfs_symlink_iops = {
  .get_link       = ftpfs_get_link,
};
