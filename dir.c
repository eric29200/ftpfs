// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Read a directory page.
 */
static int ftpfs_dir_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct ftp_fattr fattr, *fattrs;
	struct ftp_session *session;
	int ret, i;

	/* reset page */
	fattrs = kmap(page);
	memset(fattrs, 0, PAGE_SIZE);

	/* get FTP session */
	session = (struct ftp_session *) file;
	if (!session)
		goto err;

	/* start directory listing */
	ret = ftp_list_start(session, ftpfs_i(inode)->i_path, page_index(page) * FTPFS_DIR_ENTRIES_PER_PAGE);
	if (ret)
		goto err_list;

	/* for each directory entry */
	for (i = 0; i < FTPFS_DIR_ENTRIES_PER_PAGE; i++) {
		/* get next directory entry */
		ret = ftp_list_next(session, &fattr);
		if (ret < 0)
			goto err_list;
		if (ret == 0)
			goto out;

		/* copy directory entry to page */
		memcpy(&fattrs[i], &fattr, sizeof(struct ftp_fattr));
	}

out:
	/* set page up to date */
	SetPageUptodate(page);
	ClearPageError(page);
	kunmap(page);
	unlock_page(page);
	return 0;
err_list:
	/* end directory listing */
	ftp_list_end(session, ret);
err:
	/* set page error */
	ClearPageUptodate(page);
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	put_page(page);
	return ret;
}

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct ftp_session *session;
	int ret = 0, i, name_len;
	struct ftp_fattr *fattrs;
	struct page *page;
	pgoff_t pg_idx;

	/* emit "." and ".." */
	if (!dir_emit_dots(file, ctx))
		return 0;

	/* get and lock main FTP session */
	session = ftp_session_get_and_lock_main(ftpfs_sb(inode->i_sb)->s_ftp_server);
	if (!session)
		return -EIO;

	/* compute start page */
	pg_idx = (ctx->pos - 2) / FTPFS_DIR_ENTRIES_PER_PAGE;
	i = (ctx->pos - 2) % FTPFS_DIR_ENTRIES_PER_PAGE;

	/* for each page */
	for (;; pg_idx++, i = 0) {
		/* get page */
		page = read_mapping_page(inode->i_mapping, pg_idx, session);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		/* map page */
		fattrs = kmap(page);

		/* get directory entries */
		for (; i < FTPFS_DIR_ENTRIES_PER_PAGE; i++) {
			/* empty file name : end of directory */
			name_len = strnlen(fattrs[i].f_name, FTP_MAX_NAMELEN);
			if (strnlen(fattrs[i].f_name, FTP_MAX_NAMELEN) == 0)
				goto out;

			/* emit file */
			if (!dir_emit(ctx, fattrs[i].f_name, name_len, 1, DT_UNKNOWN))
				goto out;

			/* update context position */
			ctx->pos++;
		}

		/* unlock page */
		kunmap(page);
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

out:
	/* release last page */
	if (page) {
		kunmap(page);
		unlock_page(page);
		put_page(page);
	}

	/* unlock FTP session */
	ftp_list_end(session, ret);
	ftp_session_unlock(session);
	return ret;
}

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared		= ftpfs_readdir,
};

const struct address_space_operations ftpfs_dir_aops = {
	.readpage		= ftpfs_dir_readpage,
};
