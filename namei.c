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
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	struct ftp_session *session;
	struct ftp_fattr *fattrs;
	int ret = 0, i, name_len;
	pgoff_t pg_idx = 0;
	struct page *page;

	/* get and lock a session */
	session = ftp_session_acquire_locked(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session)
		return -EIO;

	/* for each page */
	for (pg_idx = 0;; pg_idx++) {
		/* get page */
		page = read_mapping_page(dir->i_mapping, pg_idx, session);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			page = NULL;
			goto out;
		}

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

	/* unlock FTP session */
	ftp_session_release_unlock(session);
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
 * Create a file.
 */
static int ftpfs_create(struct user_namespace *mnt_userns, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct ftp_session *session;
	struct ftp_fattr fattr;
	struct inode *inode;
	int ret = -EINVAL;
	char *file_path;
	size_t name_len;

	/* truncate file name */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build file path */
	memset(&fattr, 0, sizeof(struct ftp_fattr));
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* get a session */
	session = ftp_session_acquire_locked(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session) {
		ret = -EIO;
		goto out;
	}

	/* create file */
	ret = ftp_create(session, file_path);
	ftp_session_release_unlock(session);
	if (ret)
		goto out;

	/* invalidate directory cache */
	ftpfs_invalidate_inode_cache(dir);

	/* find entry */
	ret = ftpfs_find_entry(dir, dentry, &fattr);
	if (ret)
		goto out;

	/* get inode and set entry */
	inode = ftpfs_iget(dir->i_sb, dir, &fattr);
	if (inode)
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
	struct inode *inode = d_inode(dentry);
	struct ftp_session *session;
	int ret;

	/* get a FTP session */
	session = ftp_session_acquire_locked(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session)
		return -EIO;

	/* delete file */
	ret = ftp_delete(session, ftpfs_i(inode)->i_path);
	ftp_session_release_unlock(session);
	if (ret)
		return ret;

	/* invalidate directory cache */
	ftpfs_invalidate_inode_cache(dir);

	/* update inode */
	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	return ret;
}

/*
 * Create a directory.
 */
static int ftpfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct ftp_session *session;
	struct ftp_fattr fattr;
	struct inode *inode;
	int ret = -EINVAL;
	char *file_path;
	size_t name_len;

	/* truncate file name */
	name_len = dentry->d_name.len;
	if (name_len > FTP_MAX_NAMELEN)
		name_len = FTP_MAX_NAMELEN;

	/* build file path */
	memset(&fattr, 0, sizeof(struct ftp_fattr));
	memcpy(fattr.f_name, dentry->d_name.name, name_len);
	file_path = ftpfs_build_full_path(dir, &fattr);
	if (!file_path)
		return -ENOMEM;

	/* get a FTP session */
	session = ftp_session_acquire_locked(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session) {
		ret = -EIO;
		goto out;
	}

	/* create directory */
	ret = ftp_mkdir(session, file_path);
	ftp_session_release_unlock(session);
	if (ret)
		goto out;

	/* invalidate directory cache */
	ftpfs_invalidate_inode_cache(dir);

	/* find entry */
	ret = ftpfs_find_entry(dir, dentry, &fattr);
	if (ret)
		goto out;

	/* get inode and set entry */
	inode = ftpfs_iget(dir->i_sb, dir, &fattr);
	if (inode)
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
	struct inode *inode = d_inode(dentry);
	struct ftp_session *session;
	int ret;

	/* get a FTP session */
	session = ftp_session_acquire_locked(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session)
		return -EIO;

	/* delete directory */
	ret = ftp_rmdir(session, ftpfs_i(inode)->i_path);
	ftp_session_release_unlock(session);
	if (ret)
		return ret;

	/* invalidate directory cache */
	ftpfs_invalidate_inode_cache(dir);

	/* update inode */
	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	return ret;
}

/*
 * Rename a file.
 */
static int ftpfs_rename(struct user_namespace *mnt_userns, struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct ftp_session *session;
	struct ftp_fattr new_fattr;
	char *new_file_path = NULL;
	size_t new_name_len;
	int ret;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	/* truncate file name */
	new_name_len = new_dentry->d_name.len;
	if (new_name_len > FTP_MAX_NAMELEN)
		new_name_len = FTP_MAX_NAMELEN;

	/* build file path */
	memset(&new_fattr, 0, sizeof(struct ftp_fattr));
	memcpy(new_fattr.f_name, new_dentry->d_name.name, new_name_len);
	new_file_path = ftpfs_build_full_path(new_dir, &new_fattr);
	if (!new_file_path) {
		ret = -ENOMEM;
		goto err;
	}

	/* get a FTP session */
	session = ftp_session_acquire_locked(ftpfs_sb(new_dir->i_sb)->s_ftp_server);
	if (!session) {
		ret = -EIO;
		goto err;
	}

	/* FTP rename */
	ret = ftp_rename(session, ftpfs_i(old_inode)->i_path, new_file_path);
	ftp_session_release_unlock(session);
	if (ret)
		goto err;

	/* invalidate old directory and new directory page cache */
	ftpfs_invalidate_inode_cache(old_dir);
	if (old_dir != new_dir)
		ftpfs_invalidate_inode_cache(new_dir);

	/* invalidate inode cache */
	ftpfs_invalidate_inode_cache(old_inode);

	/* update inode path */
	kfree(ftpfs_i(old_inode)->i_path);
	ftpfs_i(old_inode)->i_path = new_file_path;

	return 0;
err:
	kfree(new_file_path);
	return ret;
}

/*
 * FTPFS directory inode operations.
 */
const struct inode_operations ftpfs_dir_iops = {
	.getattr	= ftpfs_getattr,
	.lookup		= ftpfs_lookup,
	.create		= ftpfs_create,
	.unlink		= ftpfs_unlink,
	.mkdir		= ftpfs_mkdir,
	.rmdir		= ftpfs_rmdir,
	.rename		= ftpfs_rename,
};

