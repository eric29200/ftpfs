// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pagemap.h>

#include "ftpfs.h"

#define FTPFS_ENTRIES_PER_PAGE		(PAGE_SIZE / sizeof(struct ftp_fattr))

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
 * Populate a directory page :
 *   - sock_data	: data socket used to get FTP dir listing (if NULL, socket will be created)
 *   - ftp_dir_pos	: current FTP dir listing position
 *   - ftp_dir_idx	: asked FTP dir listing position
 */
static int ftpfs_populate_dir_page(struct inode *inode, struct socket **sock_data, struct page *page,
				   unsigned long *ftp_dir_pos, unsigned long ftp_dir_idx)
{
	struct ftp_fattr fattr;
	void *buf;
	int ret, i;

	/* FTP dir position must be before FTP dir index */
	if (*ftp_dir_pos > ftp_dir_idx)
		return -EINVAL;

	/* clear page */
	buf = kmap(page);
	memset(buf, 0, PAGE_SIZE);

	/* start directory listing if needed */
	if (!*sock_data) {
		*sock_data = ftp_list_start(ftpfs_sb(inode->i_sb)->s_ftp_server, ftpfs_i(inode)->i_path);
		if (IS_ERR(*sock_data)) {
			ret = PTR_ERR(*sock_data);
			*sock_data = NULL;
			goto err;
		}
	}

	/* skip directory entries */
	while (*ftp_dir_pos < ftp_dir_idx) {
		/* get next directory entry */
		ret = ftp_list_next(ftpfs_sb(inode->i_sb)->s_ftp_server, *sock_data, &fattr);
		if (ret < 0)
			goto err;

		/* end of dir : break */
		if (!ret)
			goto out;

		/* update FTP dir position */
		*ftp_dir_pos += 1;
	}

	/* copy next directory entries to page */
	for (i = 0; i < FTPFS_ENTRIES_PER_PAGE; i++) {
		/* get next directory entry */
		ret = ftp_list_next(ftpfs_sb(inode->i_sb)->s_ftp_server, *sock_data, &fattr);
		if (ret < 0)
			goto err;

		/* end of dir : break */
		if (!ret)
			goto out;

		/* copy directory entry */
		memcpy(buf + i * sizeof(struct ftp_fattr), &fattr, sizeof(struct ftp_fattr));

		/* update FTP dir position */
		*ftp_dir_pos += 1;
	}

out:
	/* mark page up to date */
	SetPageUptodate(page);
	ClearPageError(page);
	kunmap(page);
	return 0;
err:
	/* mark page erronous */
	ClearPageUptodate(page);
	SetPageError(page);
	kunmap(page);
	return ret;
}

/*
 * Get or create a page.
 */
static inline struct page *ftpfs_pagecache_get_page(struct inode *inode, pgoff_t index)
{
	return pagecache_get_page(inode->i_mapping, index,
				  FGP_LOCK | FGP_ACCESSED | FGP_CREAT | FGP_NOWAIT,
				  readahead_gfp_mask(inode->i_mapping) & ~__GFP_FS);
}

/*
 * Get or create a page and read it if needed.
 */
static struct page *ftpfs_pagecache_read_page(struct inode *inode, pgoff_t pg_idx, struct socket **sock_data,
					      unsigned long *ftp_dir_pos)
{
	struct page *page;
	int ret;

	/* get page from cache */
	page = ftpfs_pagecache_get_page(inode, pg_idx);
	if (!page)
		return NULL;

	/* if page is up to date, just return it */
	if (PageUptodate(page))
		return page;

	/* or populate it */
	ret = ftpfs_populate_dir_page(inode, sock_data, page, ftp_dir_pos, pg_idx * FTPFS_ENTRIES_PER_PAGE);
	if (ret) {
		unlock_page(page);
		put_page(page);
		return NULL;
	}

	return page;
}

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	unsigned long pg_idx, ftp_dir_pos = 0;
	struct socket *sock_data = NULL;
	int ret = 0, i, name_len;
	struct page *page = NULL;
	struct ftp_fattr *fattr;

	/* revalidate inode mapping */
	ftpfs_inode_revalidate_mapping(inode);

	/* emit "." */
	if (ctx->pos == 0) {
		if (ctx->actor(ctx, ".", 1, ctx->pos, 1, DT_DIR))
			return 0;
		ctx->pos = 1;
	}

	/* emit ".." */
	if (ctx->pos == 1) {
		if (ctx->actor(ctx, "..", 2, ctx->pos, 1, DT_DIR))
			return 0;
		ctx->pos = 2;
	}

	/* compute start page */
	pg_idx = (ctx->pos - 2) / FTPFS_ENTRIES_PER_PAGE;
	i = (ctx->pos - 2) % FTPFS_ENTRIES_PER_PAGE;

	/* for each page */
	for (;; pg_idx++, i = 0) {
		/* get page from cache */
		page = ftpfs_pagecache_read_page(inode, pg_idx, &sock_data, &ftp_dir_pos);
		if (!page)
			break;

		/* map page */
		fattr = kmap(page);

		/* get directory entries */
		for (; i < FTPFS_ENTRIES_PER_PAGE; i++) {
			/* empty file name : end of directory */
			name_len = strnlen(fattr[i].f_name, FTP_MAX_NAMELEN);
			if (strnlen(fattr[i].f_name, FTP_MAX_NAMELEN) == 0) {
				kunmap(page);
				goto out;
			}

			/* emit file */
			if (!dir_emit(ctx, fattr[i].f_name, name_len, 1, DT_UNKNOWN)) {
				kunmap(page);
				goto out;
			}

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
		unlock_page(page);
		put_page(page);
	}

	/* end directory listing */
	if (sock_data)
		ftp_list_end(ftpfs_sb(inode->i_sb)->s_ftp_server, sock_data);

	return ret;
}

/*
 * Find an entry in a directory.
 */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	unsigned long pg_idx = 0, ftp_dir_pos = 0;
	struct socket *sock_data = NULL;
	int ret = 0, i, name_len;
	struct page *page = NULL;
	struct ftp_fattr *fattr;

	/* revalidate inode mapping */
	ftpfs_inode_revalidate_mapping(dir);

	/* for each page */
	for (pg_idx = 0;; pg_idx++) {
		/* get page from cache */
		page = ftpfs_pagecache_read_page(dir, pg_idx, &sock_data, &ftp_dir_pos);
		if (!page)
			break;

		/* map page */
		fattr = kmap(page);

		/* get directory entries */
		for (i = 0; i < FTPFS_ENTRIES_PER_PAGE; i++) {
			/* empty file name : end of directory */
			name_len = strnlen(fattr[i].f_name, FTP_MAX_NAMELEN);
			if (strnlen(fattr[i].f_name, FTP_MAX_NAMELEN) == 0) {
				kunmap(page);
				ret = -ENOENT;
				goto out;
			}

			/* name match */
			if (ftpfs_name_match(&fattr[i], dentry)) {
				memcpy(fattr_res, &fattr[i], sizeof(struct ftp_fattr));
				kunmap(page);
				ret = 0;
				goto out;
			}
		}

		/* unlock page */
		kunmap(page);
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	ret = -ENOENT;
out:
	/* release last page */
	if (page) {
		unlock_page(page);
		put_page(page);
	}

	/* end directory listing */
	if (sock_data)
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
	.lookup			= ftpfs_lookup,
};

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared		= ftpfs_readdir,
};

