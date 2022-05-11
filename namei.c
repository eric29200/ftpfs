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

	/* get and lock main FTP session */
	session = ftp_session_get_and_lock_main(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session)
		return -EIO;

	/* for each page */
	for (pg_idx = 0;; pg_idx++) {
		/* get page */
		page = read_mapping_page(dir->i_mapping, pg_idx, session);
		if (IS_ERR(page))
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

	/* unlock FTP session */
	ftp_list_end(session, ret);
	ftp_session_unlock(session);
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

	/* create file */
	session = ftp_session_get_and_lock_main(ftpfs_sb(dir->i_sb)->s_ftp_server);
	ret = ftp_create(session, file_path);
	ftp_session_unlock(session);

	/* exit on error */
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

	/* get main session */
	session = ftp_session_get_and_lock_main(ftpfs_sb(dir->i_sb)->s_ftp_server);
	if (!session)
		goto out;

	/* delete file */
	ret = ftp_delete(session, ftpfs_i(inode)->i_path);

	/* on success, invalidate directory cache */
	if (ret == 0)
		ftpfs_i(dir)->i_expires = jiffies;

	/* unlock FTP session */
	ftp_session_unlock(session);

	/* update inode */
	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
out:
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

	/* create directory */
	session = ftp_session_get_and_lock_main(ftpfs_sb(dir->i_sb)->s_ftp_server);
	ret = ftp_mkdir(session, file_path);
	ftp_session_unlock(session);

	/* exit on error */
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
 * FTPFS directory inode operations.
 */
const struct inode_operations ftpfs_dir_iops = {
	.lookup			= ftpfs_lookup,
	.create			= ftpfs_create,
	.unlink			= ftpfs_unlink,
	.mkdir			= ftpfs_mkdir,
};
