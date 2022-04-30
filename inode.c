// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/pagemap.h>

#include "ftpfs.h"

/*
 * Revalidate inode cached pages = invalidate all pages on time out expiration.
 */
int ftpfs_inode_revalidate_mapping(struct inode *inode)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(inode->i_sb);

	/* on expiration, invalidate all inodes pages */
	if (time_after(jiffies, ftpfs_inode->i_mapping_expires)) {
		invalidate_inode_pages2(inode->i_mapping);
		ftpfs_inode->i_mapping_expires = jiffies + msecs_to_jiffies(sbi->s_opt.dir_revalid_sec * 1000);
	}

	return 0;
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
	struct ftpfs_inode_info *ftpfs_inode;
	struct inode *inode;
	int ret = -ENOMEM;

	/* allocate a new inode */
	inode = new_inode(sb);
	if (!inode)
		goto err;

	/* init inode */
	inode->i_ino = 1;
	ftpfs_inode = ftpfs_i(inode);
	inode_init_owner(&init_user_ns, inode, dir, fattr->f_mode);
	set_nlink(inode, fattr->f_nlinks);
	inode->i_size = fattr->f_size;
	ftpfs_inode->i_path = NULL;
	ftpfs_inode->i_mapping_expires = 0;

	/* set time */
	if (fattr->f_time) {
		inode->i_atime.tv_sec = inode->i_mtime.tv_sec = inode->i_ctime.tv_sec = fattr->f_time;
		inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
	} else {
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	}

	/* build full path */
	ftpfs_inode->i_path = ftpfs_build_full_path(dir, fattr);
	if (!ftpfs_inode->i_path)
		goto err;

	/* set inode operations */
	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ftpfs_dir_iops;
		inode->i_fop = &ftpfs_dir_fops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &ftpfs_symlink_iops;
		inode_nohighmem(inode);
	} else {
		inode->i_op = &ftpfs_file_iops;
		inode->i_fop = &ftpfs_file_fops;
	}

	return inode;
err:
	if (inode)
		iget_failed(inode);
	return ERR_PTR(ret);
}
