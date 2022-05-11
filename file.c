// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Issue a read request.
 */
static void ftpfs_req_issue_op(struct netfs_read_subrequest *subreq)
{
	size_t len, page_off, bytes, total = 0, npages, i, req_len;
	struct netfs_read_request *rreq = subreq->rreq;
	struct ftp_session *session;
	ssize_t ret = -EINVAL;
	struct iov_iter iter;
	struct page **pages;
	loff_t pos;
	char *buf;

	/* get pages */
	pos = subreq->start + subreq->transferred;
	len = subreq->len - subreq->transferred;
	iov_iter_xarray(&iter, READ, &rreq->mapping->i_pages, pos, len);
	bytes = iov_iter_get_pages_alloc(&iter, &pages, len, &page_off);
	if (bytes < 0) {
		ret = bytes;
		goto out;
	}

	/* if no session is attached to this request, use main FTP session */
	session = rreq->netfs_priv;
	if (!session)
		session = ftp_session_get_and_lock_main(ftpfs_sb(rreq->inode->i_sb)->s_ftp_server);

	/* no way to get a FTP session : exit */
	if (!session)
		goto out;

	/* start FTP read */
	ret = ftp_read_start(session, ftpfs_i(rreq->inode)->i_path, pos);
	if (ret)
		goto err_ftp;

	/* read each page */
	npages = (bytes + page_off + PAGE_SIZE - 1) / PAGE_SIZE;
	for (i = 0; i < npages; i++) {
		/* read next buffer */
		buf = kmap(pages[i]);
		req_len = min_t(size_t, bytes, PAGE_SIZE - page_off);
		ret = ftp_read_next(session, buf + page_off, req_len);
		kunmap(pages[i]);
		if (ret < 0)
			goto err_ftp;
		if (ret == 0)
			break;

		page_off = 0;
		total += ret;
	}

	/* if main session used, end FTP read and unlock session */
	if (session && session->main) {
		ftp_read_end(session, 0);
		ftp_session_unlock(session);
	}

	ret = total;
	goto out;
err_ftp:
	ftp_read_end(session, ret);

	/* if main session used, unlock it */
	if (session && session->main)
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
