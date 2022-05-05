// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Read a file.
 */
ssize_t ftpfs_file_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct inode *inode = file_inode(file);
	struct ftp_session *session;
	ssize_t ret;

	/* get main session */
	session = ftp_session_get_and_lock(ftpfs_sb(inode->i_sb)->s_ftp_server, 1);
	if (!session)
		return -EIO;

	/* read from FTP session */
	ret = ftp_read(session, ftpfs_i(inode)->i_path, buf, count, pos);

	ftp_session_unlock(session);
	return ret;
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.read		= ftpfs_file_read,
	.llseek		= generic_file_llseek,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {

};
