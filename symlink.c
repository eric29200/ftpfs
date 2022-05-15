// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Get a a target link.
 */
static const char *ftpfs_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *done)
{
	struct ftp_fattr fattr;
	int ret, len;
	char *res;

	/* check dentry */
	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* find link entry in parent directory */
	ret = ftpfs_find_entry(dentry->d_parent->d_inode, dentry, &fattr);
	if (ret)
		return ERR_PTR(ret);

	/* check link target */
	len = strnlen(fattr.f_link, FTP_MAX_NAMELEN);
	if (!len)
		return ERR_PTR(-ENOLINK);

	/* allocate target link */
	res = kmalloc(len + 1, GFP_KERNEL);
	if (!res)
		return ERR_PTR(-ENOMEM);

	/* copy target link */
	memcpy(res, fattr.f_link, len);
	res[len] = 0;

	/* delay link deallocation */
	set_delayed_call(done, kfree_link, res);
	return res;
}

/*
 * FTPFS symbolic link inode operations.
 */
const struct inode_operations ftpfs_symlink_iops = {
	.getattr	= ftpfs_getattr,
	.get_link	= ftpfs_get_link,
};
