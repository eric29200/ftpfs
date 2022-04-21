#include <linux/fs.h>

#include "ftpfs.h"

/*
 * Load inode data (= store directory listing or link target).
 */
int ftpfs_load_inode_data(struct inode *inode, struct ftp_fattr *fattr)
{
  struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
  struct super_block *sb = inode->i_sb;
  size_t link_len;
  int ret = 0;

  /* lock cache */
  mutex_lock(&ftpfs_inode->i_cache_mutex);

  /* data cache already set */
  if (ftpfs_inode->i_cache.data)
    goto out;

  /* symbolic link : load target in cache */
  if (S_ISLNK(inode->i_mode)) {
    link_len = strnlen(fattr->f_link, FTP_MAX_NAMELEN);
    if (link_len > 0) {
      /* allocate inode cache (to store target link) */
      ftpfs_inode->i_cache.data = (char *) kmalloc(link_len + 1, GFP_KERNEL);
      if (!ftpfs_inode->i_cache.data) {
        ret = -ENOMEM;
        goto out;
      }

      /* copy target link to inode cache */
      ftpfs_inode->i_cache.len = link_len;
      ftpfs_inode->i_cache.capacity = link_len + 1;
      memcpy(ftpfs_inode->i_cache.data, fattr->f_link, link_len);
      ftpfs_inode->i_cache.data[link_len] = 0;
    }

    goto out;
  }

  /* directory : load listing in cache */
  if (S_ISDIR(inode->i_mode))
    ret = ftp_list(ftpfs_sb(sb)->s_ftp_server, ftpfs_inode->i_path, &ftpfs_inode->i_cache);

out:
  mutex_unlock(&ftpfs_inode->i_cache_mutex);
  return ret;
}


/*
 * Build full path of a file (concat directory path and file name).
 */
static char *ftpfs_build_full_path(struct inode *dir, struct ftp_fattr *fattr)
{
  size_t name_len, dir_path_len;
  char *path;
  
  /* compute name length */
  name_len = strnlen(fattr->f_name, FTP_MAX_NAMELEN);
  
  /* compute directory full path length */
  dir_path_len = dir ? strlen(ftpfs_i(dir)->i_path) : 0;
  
  /* allocate full path */
  path = (char *) kmalloc(dir_path_len + name_len + 2, GFP_KERNEL);
  if (!path)
    return NULL;
  
  /* start with dir path */
  if (dir)
    memcpy(path, ftpfs_i(dir)->i_path, dir_path_len);
  
  /* add '/' */
  path[dir_path_len] = '/';
  
  /* add file name */
  memcpy(path + dir_path_len + 1, fattr->f_name, name_len);
  
  /* end full path */
  path[dir_path_len + 1 + name_len] = 0;
  
  return path;
}

/*
 * Create a new FTPFS inode.
 */
struct inode *ftpfs_iget(struct super_block *sb, struct inode *dir, struct ftp_fattr *fattr)
{
  struct inode *inode;
  int err = -ENOMEM;
  
  /* allocate a new inode */
  inode = new_inode(sb);
  if (!inode)
    goto err;
  
  /* get next inode number */
  inode->i_ino = get_next_ino();
  
  /* init inode */
  inode_init_owner(&init_user_ns, inode, dir, fattr->f_mode);
  set_nlink(inode, fattr->f_nlinks);
  inode->i_size = fattr->f_size;
  mutex_init(&ftpfs_i(inode)->i_cache_mutex);
  
  /* set time */
  if (fattr->f_time) {
    inode->i_atime.tv_sec = inode->i_mtime.tv_sec = inode->i_ctime.tv_sec = fattr->f_time;
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
  } else {
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
  }
  
  /* build full path */
  ftpfs_i(inode)->i_path = ftpfs_build_full_path(dir, fattr);
  if (!ftpfs_i(inode)->i_path)
    goto err;
  
  /* symbolic link : load inode data = target link */
  if (S_ISLNK(inode->i_mode)) {
    err = ftpfs_load_inode_data(inode, fattr);
    if (err)
      goto err;
  }
  
  /* set inode operations */
  if (S_ISDIR(inode->i_mode)) {
    inode->i_op = &ftpfs_dir_iops;
    inode->i_fop = &ftpfs_dir_fops;
  } else if (S_ISLNK(inode->i_mode)) {
    inode->i_op = &ftpfs_symlink_iops;
  } else {
    inode->i_op = &ftpfs_file_iops;
    inode->i_fop = &ftpfs_file_fops;
  }
  
  return inode;
err:
  if (inode)
    iget_failed(inode);
  return ERR_PTR(err);
}
