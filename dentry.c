// SPDX-License-Identifier: GPL-2.0-only
#include <linux/namei.h>

#include "ftpfs.h"

/*
 * Revalidate a dentry.
 */
static int ftpfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ftpfs_sb_info *sbi;
	struct ftp_fattr fattr;
	struct dentry *parent;
	struct inode *dir;
	int ret;

	/*
	 * In rcu-walk mode, d_revalidate can't sleep. Return -ECHILD and d_revalidate
	 * will be called in ref-walk mode (needed because ftpfs_find_entry can sleep) .
	 */
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	/* get parent directory */
	parent = dget_parent(dentry);
	dir = d_inode(parent);
	sbi = ftpfs_sb(dir->i_sb);

	/* root dentry revalidation : just use root_fattr */
	if (dentry == dentry->d_sb->s_root) {
		dir = NULL;
		memcpy(&fattr, &root_fattr, sizeof(struct ftp_fattr));
		goto refresh_inode;
	}

	/* try to find entry */
	ret = ftpfs_find_entry(dir, dentry, &fattr);
	if (ret) {
		dput(parent);
		return 0;
	}

refresh_inode:
	/* refresh inode */
	ret = ftpfs_refresh_inode(dentry->d_inode, dir, &fattr);
	if (ret)
		return 0;

	dput(parent);
	return 1;
}

/*
 * Release inode on dentry remove.
 */
static void ftpfs_d_iput(struct dentry *dentry, struct inode *inode)
{
	iput(inode);
}


/*
 * Returns 1 if a dentry has to be unhashed.
 */
static int ftpfs_d_delete(const struct dentry *dentry)
{
	if (d_really_is_negative(dentry))
		return 1;

	return 0;
}

/*
 * FTPFS dentry operations : do not cache dentries, always check FTP server.
 */
const struct dentry_operations ftpfs_dops = {
	.d_revalidate		= ftpfs_d_revalidate,
	.d_weak_revalidate	= ftpfs_d_revalidate,
	.d_iput			= ftpfs_d_iput,
	.d_delete		= ftpfs_d_delete,
};
