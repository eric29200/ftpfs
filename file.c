// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Open a file (try to get an exclusive FTP user session).
 */
static int ftpfs_file_open(struct inode *inode, struct file *file)
{
	struct ftp_session *session;
	int ret;

	/* get and lock a user session */
	session = ftp_session_get_and_lock_user(ftpfs_sb(inode->i_sb)->s_ftp_server);
	if (!session)
		return 0;

	/* try to open it and attach it to the file */
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

	/* close file session */
	if (file->private_data != NULL) {
		session = file->private_data;
		ftp_session_close(session);
		ftp_session_unlock(session);
	}

	return 0;
}

/*
 * Read a file page.
 */
static int ftpfs_file_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct ftp_session *session;
	ssize_t ret;
	char *buf;

	/* reset page */
	buf = kmap(page);
	memset(buf, 0, PAGE_SIZE);

	/* use file session or main session */
	if (file->private_data)
		session = file->private_data;
	else
		session = ftp_session_get_and_lock_main(ftpfs_sb(inode->i_sb)->s_ftp_server);

	/* no session available */
	if (!session)
		goto err_session;

	/* start FTP read */
	ret = ftp_read_start(session, ftpfs_i(inode)->i_path, page_offset(page));
	if (ret)
		goto err;

	/* read next buffer */
	ret = ftp_read_next(session, buf, PAGE_SIZE);
	if (ret < 0)
		goto err;

	/* if main session is used, end ftp read and unlock session */
	if (!file->private_data) {
		ftp_read_end(session, 0);
		ftp_session_unlock(session);
	}

	/* set page up to date */
	SetPageUptodate(page);
	ClearPageError(page);
	kunmap(page);
	unlock_page(page);
	return 0;
err:
	/* end read with failure */
	ftp_read_end(session, ret);

	/* if main session is used, unlock session */
	if (!file->private_data)
		ftp_session_unlock(session);

err_session:
	/* set page error */
	ClearPageUptodate(page);
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	put_page(page);
	return ret;
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.open		= ftpfs_file_open,
	.release	= ftpfs_file_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {

};

/*
 * FTPFS file address space operations.
 */
const struct address_space_operations ftpfs_file_aops = {
	.readpage	= ftpfs_file_readpage,
};
