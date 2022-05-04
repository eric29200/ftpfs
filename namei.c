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
	struct socket *sock_data;
	struct ftp_fattr fattr;
	int ret, name_len;

	/* start directory listing */
	sock_data = ftp_list_start(sbi->s_ftp_server, ftpfs_dir->i_path);
	if (IS_ERR(sock_data))
		return PTR_ERR(sock_data);

	/* for each directory entry */
	for (;;) {
		/* get next directory entry */
		ret = ftp_list_next(sbi->s_ftp_server, sock_data, &fattr);
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
	ftp_list_end(sbi->s_ftp_server, sock_data);
	return ret;
err:
	ftp_list_failed(sbi->s_ftp_server, sock_data);
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
 * Create a new file.
 */
static int ftpfs_create(struct user_namespace *mnt_userns, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct ftp_fattr fattr;
	struct inode *inode;
	int name_len, ret;
	char *file_path;

	/* get name length */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(&fattr, 0, sizeof(struct ftp_fattr));
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* create file on FTP server */
	ret = ftp_create(ftpfs_sb(dir->i_sb)->s_ftp_server, file_path);
	if (ret)
		goto out;

	/* find newly created entry (reset directory mapping, to lookup on FTP server) */
	ftpfs_i(dir)->i_mapping_expires = jiffies;
	ret = ftpfs_find_entry(dir, dentry, &fattr);
	if (ret)
		goto out;

	/* get inode */
	inode = ftpfs_iget(dir->i_sb, dir, &fattr);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	/* register dentry <-> inode */
	d_instantiate(dentry, inode);
out:
	kfree(file_path);
	return ret;
}

/*
 * Remove a file.
 */
static int ftpfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct ftp_fattr fattr;
	int name_len, ret;
	char *file_path;

	/* get name length */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(fattr.f_name, 0, FTP_MAX_NAMELEN);
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* ask FTP to delete file */
	ret = ftp_rm(ftpfs_sb(dir->i_sb)->s_ftp_server, file_path);
	if (ret)
		goto out;

	/* reset directory buffer page cache */
	ftpfs_i(dir)->i_mapping_expires = jiffies;
out:
	kfree(file_path);
	return ret;
}

/*
 * Create a new directory.
 */
static int ftpfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
		       struct dentry *dentry, umode_t mode)
{
	struct ftp_fattr fattr;
	struct inode *inode;
	int name_len, ret;
	char *file_path;

	/* get name length */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(&fattr, 0, sizeof(struct ftp_fattr));
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* create directory on FTP server */
	ret = ftp_mkdir(ftpfs_sb(dir->i_sb)->s_ftp_server, file_path);
	if (ret)
		goto out;

	/* find newly created entry (reset directory mapping, to lookup on FTP server) */
	ftpfs_i(dir)->i_mapping_expires = jiffies;
	ret = ftpfs_find_entry(dir, dentry, &fattr);
	if (ret)
		goto out;

	/* get inode */
	inode = ftpfs_iget(dir->i_sb, dir, &fattr);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	/* register dentry <-> inode */
	d_instantiate(dentry, inode);
out:
	kfree(file_path);
	return ret;
}

/*
 * Remove a directory.
 */
static int ftpfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct ftp_fattr fattr;
	int name_len, ret;
	char *file_path;

	/* get name length */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(fattr.f_name, 0, FTP_MAX_NAMELEN);
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* ask FTP to delete directory */
	ret = ftp_rmdir(ftpfs_sb(dir->i_sb)->s_ftp_server, file_path);
	if (ret)
		goto out;

	/* reset directory buffer page cache */
	ftpfs_i(dir)->i_mapping_expires = jiffies;
out:
	kfree(file_path);
	return ret;
}

/*
 * Rename a file.
 */
static int ftpfs_rename(struct user_namespace *mnt_userns, struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	char *old_file_path = NULL, *new_file_path = NULL;
	int ret, old_name_len, new_name_len;
	struct ftp_fattr fattr;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	/* get old name length */
	old_name_len = old_dentry->d_name.len;
	if (old_name_len > FTP_MAX_NAMELEN)
		old_name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(fattr.f_name, 0, FTP_MAX_NAMELEN);
	memcpy(fattr.f_name, old_dentry->d_name.name, old_name_len);
	old_file_path = ftpfs_build_full_path(old_dir, &fattr);
	if (!old_file_path) {
		ret = -ENOMEM;
		goto out;
	}

	/* get new name length */
	new_name_len = new_dentry->d_name.len;
	if (new_name_len > FTP_MAX_NAMELEN)
		new_name_len = FTP_MAX_NAMELEN;

	/* build full path */
	memset(fattr.f_name, 0, FTP_MAX_NAMELEN);
	memcpy(fattr.f_name, new_dentry->d_name.name, new_name_len);
	new_file_path = ftpfs_build_full_path(new_dir, &fattr);
	if (!new_file_path) {
		ret = -ENOMEM;
		goto out;
	}

	/* ask FTP server to rename file */
	ret = ftp_rename(ftpfs_sb(old_dir->i_sb)->s_ftp_server, old_file_path, new_file_path);
	if (ret)
		goto out;

	/* reset old and new directories buffer page cache */
	ftpfs_i(old_dir)->i_mapping_expires = jiffies;
	ftpfs_i(new_dir)->i_mapping_expires = jiffies;

	ret = 0;
out:
	kfree(old_file_path);
	kfree(new_file_path);
	return ret;
}

/*
 * FTPFS directory inode operations.
 */
const struct inode_operations ftpfs_dir_iops = {
	.lookup			= ftpfs_lookup,
	.create			= ftpfs_create,
	.unlink			= ftpfs_unlink,
	.mkdir			= ftpfs_mkdir,
	.rmdir			= ftpfs_rmdir,
	.rename			= ftpfs_rename,
};
