// SPDX-License-Identifier: GPL-2.0-only
#include <linux/swap.h>
#include "ftpfs.h"

/*
 * Issue a read request.
 */
static void ftpfs_req_issue_op(struct netfs_read_subrequest *subreq)
{
	struct netfs_read_request *rreq = subreq->rreq;
	struct ftp_session *session;
	ssize_t ret = -EINVAL;
	struct iov_iter iter;
	loff_t pos;
	size_t len;

	/* if no session is attached to this request, use main FTP session */
	session = rreq->netfs_priv;
	if (!session)
		session = ftp_session_get_and_lock_main(ftpfs_sb(rreq->inode->i_sb)->s_ftp_server);

	/* no way to get a FTP session : exit */
	if (!session)
		goto out;

	/* prepare xarray */
	pos = subreq->start + subreq->transferred;
	len = subreq->len - subreq->transferred;
	iov_iter_xarray(&iter, READ, &rreq->mapping->i_pages, pos, len);

	/* read from FTP */
	ret = ftp_read(session, ftpfs_i(rreq->inode)->i_path, pos, &iter, len);

	/* if main session is used, unlock session */
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
 * Mark a page dirty.
 */
static int ftpfs_file_set_page_dirty(struct page *page)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(page->mapping->host);

	return fscache_set_page_dirty(page, ftpfs_inode->i_fscache);
}

/*
 * Handle error on netfs cache write.
 */
static void ftpfs_file_write_to_cache_done(void *priv, ssize_t transferred_or_error, bool was_async)
{
	struct ftpfs_inode_info *ftpfs_inode = priv;
	int version = 0;

	if (IS_ERR_VALUE(transferred_or_error) && transferred_or_error != -ENOBUFS)
		fscache_invalidate(ftpfs_inode->i_fscache, &version, i_size_read(&ftpfs_inode->vfs_inode), 0);
}

/*
 * Write a page.
 */
static int ftpfs_file_write_folio_locked(struct folio *folio)
{
	struct inode *inode = folio_inode(folio);
	struct ftp_session *session;
	struct iov_iter iter;
	loff_t pos, i_size;
	size_t len;
	int ret;

	/* simultaneous truncate */
	i_size = i_size_read(inode);
	pos = folio_pos(folio);
	len = folio_size(folio);
	if (pos >= i_size)
		return 0;

	/* init xarray */
	len = min_t(loff_t, i_size - pos, len);
	iov_iter_xarray(&iter, WRITE, &folio_mapping(folio)->i_pages, pos, len);

	/* wait for netfs cache */
	folio_wait_fscache(folio);
	folio_start_writeback(folio);

	/* get FTP session attached to folio or use main FTP session */
	session = folio->private;
	if (!session)
		session = ftp_session_get_and_lock_main(ftpfs_sb(inode->i_sb)->s_ftp_server);

	/* write to FTP */
	ret = ftp_write(session, ftpfs_i(inode)->i_path, pos, &iter, len);

	/* if main session is used, unlock it */
	if (session->main)
		ftp_session_unlock(session);

	/* detach session from folio */
	folio->private = NULL;

	/* write to netfs cache */
	if (ret >= 0 && fscache_cookie_enabled(ftpfs_i(inode)->i_fscache)) {
		folio_start_fscache(folio);
		fscache_write_to_cache(ftpfs_i(inode)->i_fscache, folio_mapping(folio), pos, len, i_size,
				       ftpfs_file_write_to_cache_done, ftpfs_i(inode), true);
	}

	folio_end_writeback(folio);
	return ret < 0 ? ret : 0;
}

/*
 * Write a page.
 */
static int ftpfs_file_writepage(struct page *page, struct writeback_control *wbc)
{
	struct folio *folio = page_folio(page);
	int ret;

	ret = ftpfs_file_write_folio_locked(folio);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			folio_redirty_for_writepage(wbc, folio);
			ret = 0;
		} else {
			mapping_set_error(folio_mapping(folio), ret);
		}
	} else {
		ret = 0;
	}

	folio_unlock(folio);
	return ret;
}

/*
 * Start a write request.
 */
static int ftpfs_file_write_begin(struct file *file, struct address_space *mapping, loff_t pos, unsigned int len,
				  unsigned int flags, struct page **pagep, void **fsdata)
{
	struct folio *folio;
	int ret;

	ret = netfs_write_begin(file, mapping, pos, len, flags, &folio, fsdata, &ftpfs_req_ops, NULL);
	if (ret < 0)
		return ret;

	*pagep = &folio->page;
	return ret;
}

/*
 * End a write request.
 */
static int ftpfs_file_write_end(struct file *file, struct address_space *mapping, loff_t pos, unsigned int len,
				unsigned int copied, struct page *page, void *fsdata)
{
	struct folio *folio = page_folio(page);
	struct inode *inode = mapping->host;
	loff_t last_pos = pos + copied;

	/* check if folio is up to date */
	if (!folio_test_uptodate(folio)) {
		if (copied < len) {
			copied = 0;
			goto out;
		}

		folio_mark_uptodate(folio);
	}

	/* update inode size */
	if (last_pos > inode->i_size) {
		inode_add_bytes(inode, last_pos - inode->i_size);
		i_size_write(inode, last_pos);
		fscache_update_cookie(ftpfs_i(inode)->i_fscache, NULL, &last_pos);
	}

	/* attach FTP session to folio */
	folio->private = file->private_data;

	folio_mark_dirty(folio);
out:
	folio_unlock(folio);
	folio_put(folio);
	return copied;
}

/*
 * Release a page.
 */
static int ftpfs_file_releasepage(struct page *page, gfp_t gfp)
{
	struct folio *folio = page_folio(page);

	if (folio_test_private(folio))
		return 0;

	/* wait for netfs cache */
	if (folio_test_fscache(folio)) {
		if (current_is_kswapd() || !(gfp & __GFP_FS))
			return 0;

		folio_wait_fscache(folio);
	}

	/* release page */
	fscache_note_page_release(ftpfs_i(folio_inode(folio))->i_fscache);
	return 1;
}

/*
 * Invalidate a page.
 */
static void ftpfs_file_invalidatepage(struct page *page, unsigned int offset, unsigned int len)
{
	struct folio *folio = page_folio(page);

	folio_wait_fscache(folio);
}

/*
 * Laund a page (write it on disk = to FTP server).
 */
static int ftpfs_file_launder_page(struct page *page)
{
	struct folio *folio = page_folio(page);
	int ret;

	if (folio_clear_dirty_for_io(folio)) {
		ret = ftpfs_file_write_folio_locked(folio);
		if (ret)
			return ret;
	}

	folio_wait_fscache(folio);
	return 0;
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
	if (session) {
		/* try to open it and attach it to the file */
		ret = ftp_session_open(session);
		if (ret == 0)
			file->private_data = session;
		else
			ftp_session_unlock(session);
	}

	/* mark cookie in use */
	fscache_use_cookie(ftpfs_i(inode)->i_fscache, file->f_mode & FMODE_WRITE);

	return 0;
}

/*
 * Close a file (close FTP user session and unlock it).
 */
static int ftpfs_file_release(struct inode *inode, struct file *file)
{
	struct ftp_session *session = file->private_data;
	int version = 0;
	loff_t i_size;

	/* mark cookie unused */
	if (file->f_mode & FMODE_WRITE) {
		/* invalidate inode pages (to write them on disk) */
		invalidate_inode_pages2(inode->i_mapping);

		/* mark cookie unused */
		i_size = i_size_read(inode);
		fscache_unuse_cookie(ftpfs_i(inode)->i_fscache, &version, &i_size);
	} else {
		fscache_unuse_cookie(ftpfs_i(inode)->i_fscache, NULL, NULL);
	}

	/* close file session */
	if (session) {
		ftp_session_close(session);
		ftp_session_unlock(session);
	}

	return 0;
}

/*
 * Synchronize a file.
 */
static int ftpfs_file_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return file_write_and_wait_range(file, start, end);
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.open		= ftpfs_file_open,
	.release	= ftpfs_file_release,
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.fsync		= ftpfs_file_fsync,
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
	.readpage		= ftpfs_file_readpage,
	.set_page_dirty		= ftpfs_file_set_page_dirty,
	.writepage		= ftpfs_file_writepage,
	.write_begin		= ftpfs_file_write_begin,
	.write_end		= ftpfs_file_write_end,
	.releasepage		= ftpfs_file_releasepage,
	.invalidatepage		= ftpfs_file_invalidatepage,
	.launder_page		= ftpfs_file_launder_page,
};
