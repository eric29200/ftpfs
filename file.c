// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Open a file (try to get an exclusive FTP user session).
 */
static int ftpfs_file_open(struct inode *inode, struct file *file)
{
	struct ftp_session *session;
	int ret;

	/* get and lock a free user session */
	session = ftp_session_get_and_lock_user(ftpfs_sb(inode->i_sb)->s_ftp_server);
	if (!session)
		return 0;

	/* try to open it. if it fails unlock session */
	ret = ftp_session_open(session);
	if (ret == 0)
		file->private_data = session;
	else
		ftp_session_unlock(session);

	return 0;
}

/*
 * Close a file (close FTP user session and unlock it).
 */
static int ftpfs_file_release(struct inode *inode, struct file *file)
{
	struct ftp_session *session;

	if (file->private_data != NULL) {
		session = file->private_data;
		ftp_session_close(session);
		ftp_session_unlock(session);
	}

	return 0;
}

/*
 * Read a file.
 */
static ssize_t ftpfs_file_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct inode *inode = file_inode(file);
	struct ftp_session *session;
	ssize_t ret;

	/* use file session or main session */
	if (file->private_data)
		session = file->private_data;
	else
		session = ftp_session_get_and_lock_main(ftpfs_sb(inode->i_sb)->s_ftp_server);

	/* no session available */
	if (!session)
		return -EIO;

	/* start FTP read */
	ret = ftp_read_start(session, ftpfs_i(inode)->i_path, *pos);
	if (ret)
		goto out;

	/* read next buffer */
	ret = ftp_read_next(session, buf, count);
	if (ret < 0) {
		ftp_read_failed(session);
		goto out;
	}

	/* update file position */
	*pos += ret;

	/* if main session is used, end ftp read */
	if (!file->private_data)
		ftp_read_end(session);
out:
	if (!file->private_data)
		ftp_session_unlock(session);
	return ret;
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.open		= ftpfs_file_open,
	.release	= ftpfs_file_release,
	.llseek		= generic_file_llseek,
	.read		= ftpfs_file_read,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {

};
