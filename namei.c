#include "ftpfs.h"

/*
 * Test file names equality.
 */
static inline bool ftpfs_name_match(struct ftp_fattr *fattr, struct dentry *dentry)
{
	if (strnlen(fattr->f_name, FTP_MAX_NAMELEN) != dentry->d_name.len)
		return false;

	return strncmp(fattr->f_name, dentry->d_name.name, dentry->d_name.len) == 0;
}

/*
 * Find an entry in a directory.
 */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	struct socket *sock_data;
	int ret = -ENOENT, n;

	/* start directory listing */
	sock_data = ftp_list_start(ftpfs_sb(dir->i_sb)->s_ftp_server, ftpfs_i(dir)->i_path);
	if (IS_ERR(sock_data))
		return PTR_ERR(sock_data);

	/* for each directory entry */
	for (;;) {
		/* get next directory entry */
		n = ftp_list_next(ftpfs_sb(dir->i_sb)->s_ftp_server, sock_data, fattr_res);
		if (n <= 0)
			break;

		/* check name */
		if (ftpfs_name_match(fattr_res, dentry)) {
			ret = 0;
			break;
		}
	}

	/* end directory listing */
	ftp_list_end(ftpfs_sb(dir->i_sb)->s_ftp_server, sock_data);

	return ret;
}

/*
 * Lookup for a file in a directory.
 */
static struct dentry *ftpfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = NULL;
	struct ftp_fattr fattr;
	int ret;

	/* find entry */
	ret = ftpfs_find_entry(dir, dentry, &fattr);

	/* get inode */
	if (ret == 0)
		inode = ftpfs_iget(dir->i_sb, dir, &fattr);

	return d_splice_alias(inode, dentry);
}

/*
 * FTPFS directory inode operations.
 */
const struct inode_operations ftpfs_dir_iops = {
	.lookup		= ftpfs_lookup,
};
