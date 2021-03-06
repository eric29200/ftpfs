// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Build full path of a file (concat directory path and file name).
 */
char *ftpfs_build_full_path(struct inode *dir, struct ftp_fattr *fattr)
{
	size_t name_len, dir_path_len;
	char *path;

	/* compute name length */
	name_len = strnlen(fattr->f_name, FTP_MAX_NAMELEN);

	/* compute directory full path length */
	dir_path_len = dir ? strlen(ftpfs_i(dir)->i_path) : 0;

	/* allocate full path */
	path = kmalloc(dir_path_len + name_len + 2, GFP_KERNEL);
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
	int ret = -ENOMEM;

	/* allocate a new inode */
	inode = new_inode(sb);
	if (!inode)
		goto err;

	/* init inode */
	inode->i_ino = get_next_ino();
	inode_init_owner(&init_user_ns, inode, dir, fattr->f_mode);
	set_nlink(inode, fattr->f_nlinks);
	i_size_write(inode, fattr->f_size);
	ftpfs_i(inode)->i_expires = jiffies;

	/* build full path */
	ftpfs_i(inode)->i_path = ftpfs_build_full_path(dir, fattr);
	if (!ftpfs_i(inode)->i_path)
		goto err;

	/* create netfs cache */
	ftpfs_cache_inode_get_cookie(inode);

	/* set time */
	if (fattr->f_time) {
		inode->i_atime.tv_sec = inode->i_mtime.tv_sec = inode->i_ctime.tv_sec = fattr->f_time;
		inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
	}

	/* set inode operations */
	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ftpfs_dir_iops;
		inode->i_fop = &ftpfs_dir_fops;
		inode->i_mapping->a_ops = &ftpfs_dir_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &ftpfs_symlink_iops;
		inode_nohighmem(inode);
	} else {
		inode->i_op = &ftpfs_file_iops;
		inode->i_fop = &ftpfs_file_fops;
		inode->i_mapping->a_ops = &ftpfs_file_aops;
	}

	return inode;
err:
	if (inode)
		iput(inode);
	return ERR_PTR(ret);
}

/*
 * Revalidate inode page cache.
 */
void ftpfs_invalidate_inode_cache(struct inode *inode)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(inode->i_sb);

	invalidate_inode_pages2(inode->i_mapping);
	ftpfs_inode->i_expires = jiffies + msecs_to_jiffies(sbi->s_opt.cache_timeout_sec * 1000);
}

/*
 * Refresh an inode.
 */
int ftpfs_refresh_inode(struct inode *inode, struct inode *dir, struct ftp_fattr *fattr)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);

	/* netfs cache in use (= file opened) : don't refresh inode */
	if (ftpfs_inode->i_fscache && atomic_read(&ftpfs_inode->i_fscache->n_active) > 1)
		return 0;

	/* inode is still valid */
	if (time_before(jiffies, ftpfs_inode->i_expires))
		return 0;

	/* invalidate page cache */
	ftpfs_invalidate_inode_cache(inode);

	/* rebuild full path */
	kfree(ftpfs_inode->i_path);
	ftpfs_inode->i_path = ftpfs_build_full_path(dir, fattr);
	if (!ftpfs_inode->i_path)
		return -ENOMEM;

	/* resize netfs cache */
	if (ftpfs_inode->i_fscache && i_size_read(inode) != fattr->f_size)
		fscache_resize_cookie(ftpfs_inode->i_fscache, fattr->f_size);

	/* update uid, gid, mode, nlinks and size */
	inode_init_owner(&init_user_ns, inode, dir, fattr->f_mode);
	set_nlink(inode, fattr->f_nlinks);
	i_size_write(inode, fattr->f_size);

	/* update time */
	if (fattr->f_time) {
		inode->i_atime.tv_sec = inode->i_mtime.tv_sec = inode->i_ctime.tv_sec = fattr->f_time;
		inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
	}

	return 0;
}

/*
 * Get inode attributes.
 */
int ftpfs_getattr(struct user_namespace *mnt_userns, const struct path *path,
		  struct kstat *stat, u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);

	generic_fillattr(&init_user_ns, inode, stat);

	/* fake number of 512 blocks */
	stat->blksize = 512;
	stat->blocks = (i_size_read(inode) + 512 - 1) >> 9;

	return 0;
}
