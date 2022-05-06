// SPDX-License-Identifier: GPL-2.0-only
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
 * Find an entry in a directory (look into page cache).
 */
static int ftpfs_find_entry_from_page_cache(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	int ret = 0, i, name_len;
	struct ftp_fattr *fattrs;
	pgoff_t pg_idx = 0;
	struct page *page;

	/* revalidate directory */
	ret = ftpfs_dir_revalidate_page_cache(dir);
	if (ret)
		return ret;

	/* for each page */
	for (pg_idx = 0;; pg_idx++) {
		/* get page from cache */
		page = ftpfs_pagecache_get_page(dir, pg_idx);
		if (!page)
			break;

		/* map page */
		fattrs = kmap(page);

		/* get directory entries */
		for (i = 0; i < FTPFS_DIR_ENTRIES_PER_PAGE; i++) {
			/* empty file name : end of directory */
			name_len = strnlen(fattrs[i].f_name, FTP_MAX_NAMELEN);
			if (strnlen(fattrs[i].f_name, FTP_MAX_NAMELEN) == 0) {
				ret = -ENOENT;
				goto out;
			}

			/* name match */
			if (ftpfs_name_match(&fattrs[i], dentry)) {
				memcpy(fattr_res, &fattrs[i], sizeof(struct ftp_fattr));
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
		kunmap(page);
		unlock_page(page);
		put_page(page);
	}

	return ret;
}

/*
 * Find an entry in a directory (ask to FTP server).
 */
static int ftpfs_find_entry_from_ftp(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	struct ftpfs_inode_info *ftpfs_dir = ftpfs_i(dir);
	struct ftpfs_sb_info *sbi = ftpfs_sb(dir->i_sb);
	struct ftp_session *session;
	struct ftp_fattr fattr;
	int ret, name_len;

	/* get main session */
	session = ftp_session_get_and_lock_main(sbi->s_ftp_server);
	if (!session)
		return -EIO;

	/* start directory listing */
	ret = ftp_list_start(session, ftpfs_dir->i_path);
	if (ret)
		goto err;

	/* for each directory entry */
	for (;;) {
		/* get next directory entry */
		ret = ftp_list_next(session, &fattr);
		if (ret < 0)
			goto err;

		/* end of directory */
		if (ret == 0)
			break;

		/* name match */
		name_len = strnlen(fattr.f_name, FTP_MAX_NAMELEN);
		if (ftpfs_name_match(&fattr, dentry)) {
			memcpy(fattr_res, &fattr, sizeof(struct ftp_fattr));
			ret = 0;
			goto out;
		}
	}

	ret = -ENOENT;
out:
	ftp_list_end(session);
	ftp_session_unlock(session);
	return ret;
err:
	ftp_list_failed(session);
	ftp_session_unlock(session);
	return ret;
}

/*
 * Find an entry in a directory.
 */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	int ret;

	/* try to find entry in page cache */
	ret = ftpfs_find_entry_from_page_cache(dir, dentry, fattr_res);
	if (ret == 0 || ret == -ENOENT)
		return ret;

	/* on failure ask to FTP server */
	return ftpfs_find_entry_from_ftp(dir, dentry, fattr_res);
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
