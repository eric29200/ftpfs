// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Get or create a page.
 */
static inline struct page *ftpfs_pagecache_create_page(struct inode *inode, pgoff_t index)
{
	return pagecache_get_page(inode->i_mapping, index,
				  FGP_LOCK | FGP_ACCESSED | FGP_CREAT | FGP_NOWAIT,
				  readahead_gfp_mask(inode->i_mapping) & ~__GFP_FS);
}

/*
 * Populate a directory cached page (return number of entries or error code).
 */
static int ftpfs_dir_populate_page(struct inode *inode, pgoff_t pg_idx, struct ftp_session *session)
{
	struct ftp_fattr *fattrs;
	struct page *page;
	int ret = 0, i;

	/* create a new page */
	page = ftpfs_pagecache_create_page(inode, pg_idx);
	if (!page)
		return -ENOMEM;

	/* reset page */
	fattrs = kmap(page);
	memset(fattrs, 0, PAGE_SIZE);

	/* copy directory entries to cache */
	for (i = 0; i < FTPFS_DIR_ENTRIES_PER_PAGE; i++) {
		/* copy next dir entry */
		ret = ftp_list_next(session, &fattrs[i]);
		if (ret < 0)
			goto err;

		/* end of directory */
		if (!ret)
			break;
	}

	SetPageUptodate(page);
	ClearPageError(page);
	kunmap(page);
	unlock_page(page);
	put_page(page);
	return i;
err:
	ClearPageUptodate(page);
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	put_page(page);
	return ret;
}

/*
 * Try to load a directory in page cache.
 */
static int ftpfs_dir_load_into_page_cache(struct inode *inode)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(inode->i_sb);
	struct ftp_session *session;
	pgoff_t pg_idx;
	int ret;

	/* get main session */
	session = ftp_session_get_and_lock_main(sbi->s_ftp_server);
	if (!session)
		return -EIO;

	/* start directory listing */
	ret = ftp_list_start(session, ftpfs_inode->i_path);
	if (ret)
		goto err;

	/* for each directory entry */
	for (pg_idx = 0;; pg_idx++) {
		/* populate page */
		ret = ftpfs_dir_populate_page(inode, pg_idx, session);
		if (ret < 0)
			goto err;

		/* end of directory */
		if (ret < FTPFS_DIR_ENTRIES_PER_PAGE)
			break;
	}

	/* end directory listing */
	ftp_list_end(session);
	ftp_session_unlock(session);

	return 0;
err:
	ftp_list_failed(session);
	ftp_session_unlock(session);
	return ret;
}


/*
 * Revalidate a directory (= clear/reload page cache if needed).
 */
int ftpfs_dir_revalidate_page_cache(struct inode *inode)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(inode->i_sb);
	int ret;

	/* directory still valid */
	if (time_before(jiffies, ftpfs_inode->i_mapping_expires))
		return 0;

	/* invalidate all pages */
	ret = invalidate_inode_pages2(inode->i_mapping);
	if (ret)
		return ret;

	/* load directory listing into page cache */
	ret = ftpfs_dir_load_into_page_cache(inode);
	if (ret)
		return ret;

	/* refresh revalidation expiration */
	ftpfs_inode->i_mapping_expires = jiffies + msecs_to_jiffies(sbi->s_opt.dir_revalid_msec);

	return 0;
}

/*
 * Get directory entries (from page cache).
 */
static int ftpfs_readdir_from_page_cache(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	int ret = 0, i, name_len;
	struct ftp_fattr *fattrs;
	struct page *page;
	pgoff_t pg_idx;

	/* revalidate directory */
	ret = ftpfs_dir_revalidate_page_cache(inode);
	if (ret)
		return ret;

	/* compute start page */
	pg_idx = (ctx->pos - 2) / FTPFS_DIR_ENTRIES_PER_PAGE;
	i = (ctx->pos - 2) % FTPFS_DIR_ENTRIES_PER_PAGE;

	/* for each page */
	for (;; pg_idx++, i = 0) {
		/* get page from cache */
		page = ftpfs_pagecache_get_page(inode, pg_idx);
		if (!page)
			break;

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

	return ret;
}

/*
 * Get directory entries (ask to FTP server).
 */
static int ftpfs_readdir_from_ftp(struct file *file, struct dir_context *ctx)
{
	struct ftpfs_inode_info *ftpfs_dir = ftpfs_i(file->f_inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(file->f_inode->i_sb);
	struct ftp_session *session;
	struct ftp_fattr fattr;
	int ret, i, name_len;

	/* get main session */
	session = ftp_session_get_and_lock_main(sbi->s_ftp_server);
	if (!session)
		return -EIO;

	/* start directory listing */
	ret = ftp_list_start(session, ftpfs_dir->i_path);
	if (ret)
		goto err;

	/* for each directory entry */
	for (i = 0;; i++) {
		/* get next directory entry */
		ret = ftp_list_next(session, &fattr);
		if (ret < 0)
			goto err;

		/* end of directory */
		if (ret == 0)
			break;

		/* skip first entries */
		if (i + 2 < ctx->pos)
			continue;

		/* emit file */
		name_len = strnlen(fattr.f_name, FTP_MAX_NAMELEN);
		if (!dir_emit(ctx, fattr.f_name, name_len, 1, DT_UNKNOWN))
			break;

		/* update dir position */
		ctx->pos++;
	}

	ftp_list_end(session);
	ftp_session_unlock(session);
	return 0;
err:
	ftp_list_failed(session);
	ftp_session_unlock(session);
	return ret;
}

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	/* emit "." and ".." */
	if (!dir_emit_dots(file, ctx))
		return 0;

	/* readdir from page cache first */
	if (ftpfs_readdir_from_page_cache(file, ctx) == 0)
		return 0;

	/* on failure, ask to FTP server */
	return ftpfs_readdir_from_ftp(file, ctx);
}

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared		= ftpfs_readdir,
};
