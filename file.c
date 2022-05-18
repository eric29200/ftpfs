// SPDX-License-Identifier: GPL-2.0-only
#include <linux/swap.h>
#include <linux/backing-dev.h>
#include "ftpfs.h"

/*
 * Issue a read request.
 */
static void ftpfs_req_issue_op(struct netfs_read_subrequest *subreq)
{
	struct netfs_read_request *rreq = subreq->rreq;
	struct ftp_session *session = rreq->netfs_priv;
	ssize_t ret = -EINVAL;
	struct iov_iter iter;
	loff_t pos;
	size_t len;

	/* no FTP session : exit */
	if (!session)
		goto out;

	/* prepare xarray */
	pos = subreq->start + subreq->transferred;
	len = subreq->len - subreq->transferred;
	iov_iter_xarray(&iter, READ, &rreq->mapping->i_pages, pos, len);

	/* read from FTP */
	ftp_session_lock(session);
	ret = ftp_read(session, ftpfs_i(rreq->inode)->i_path, rreq->inode->i_ino, pos, &iter, len);
	ftp_session_unlock(session);

out:
	netfs_subreq_terminated(subreq, ret, false);
}

/*
 * Init a netfs read request (= attach FTP file session to read request).
 */
static void ftpfs_init_rreq(struct netfs_read_request *rreq, struct file *file)
{
	rreq->netfs_priv = file->private_data;
}

/*
 * Check if an inode can be cached.
 */
static bool ftpfs_is_cache_enabled(struct inode *inode)
{
	return fscache_cookie_enabled(ftpfs_i(inode)->i_fscache);
}

/*
 * Cleanup a netfs read request.
 */
static void ftpfs_req_cleanup(struct address_space *mapping, void *priv)
{
}

/*
 * Begin a netfs read request.
 */
static int ftpfs_begin_cache_operation(struct netfs_read_request *rreq)
{
	struct fscache_cookie *cookie = ftpfs_i(rreq->inode)->i_fscache;

	return fscache_begin_read_operation(&rreq->cache_resources, cookie);
}

/*
 * Netfs read request operations.
 */
static const struct netfs_read_request_ops ftpfs_req_ops = {
	.init_rreq		= ftpfs_init_rreq,
	.is_cache_enabled	= ftpfs_is_cache_enabled,
	.begin_cache_operation	= ftpfs_begin_cache_operation,
	.issue_op		= ftpfs_req_issue_op,
	.cleanup		= ftpfs_req_cleanup,
};

/*
 * Read a file page.
 */
static int ftpfs_file_readpage(struct file *file, struct page *page)
{
	struct folio *folio = page_folio(page);

	return netfs_readpage(file, folio, &ftpfs_req_ops, NULL);
}

/*
 * Open a file (try to get an exclusive FTP user session).
 */
static int ftpfs_file_open(struct inode *inode, struct file *file)
{
	/* get a session */
	file->private_data = ftp_session_acquire(ftpfs_sb(inode->i_sb)->s_ftp_server);

	/* mark cookie in use */
	fscache_use_cookie(ftpfs_i(inode)->i_fscache, file->f_mode & FMODE_WRITE);

	return 0;
}

/*
 * Close a file (release FTP user session).
 */
static int ftpfs_file_release(struct inode *inode, struct file *file)
{
	struct ftp_session *session = file->private_data;

	/* mark cookie unused */
	fscache_unuse_cookie(ftpfs_i(inode)->i_fscache, NULL, NULL);

	/* release FTP session */
	if (session)
		ftp_session_release(session);

	return 0;
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.open		= ftpfs_file_open,
	.release	= ftpfs_file_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_mmap,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {
	.getattr		= ftpfs_getattr,
};

/*
 * FTPFS file address space operations.
 */
const struct address_space_operations ftpfs_file_aops = {
	.readpage		= ftpfs_file_readpage,
};
