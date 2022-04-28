#include <linux/pagemap.h>

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
 * Find an entry in a directory.
 */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
	int name_len, i, ret = -ENOENT;
	struct ftp_fattr *fattr;
	unsigned long pg_idx;
	struct page *page;

	/* for each page */
	for (pg_idx = 0, i = 0;; pg_idx++, i = 0) {
		/* read next page */
		page = read_mapping_page(dir->i_mapping, pg_idx, NULL);
		if (IS_ERR(page))
			goto out;

		/* get directory entries */
		fattr = (struct ftp_fattr *) page_address(page);

		/* for each directory entry in the page */
		for (; i < PAGE_SIZE / sizeof(struct ftp_fattr); i++) {
			/* empty name = end of directory */
			name_len = strnlen(fattr[i].f_name, FTP_MAX_NAMELEN);
			if (!name_len)
				goto out_release_page;

			/* name match */
			if (ftpfs_name_match(&fattr[i], dentry)) {
			    memcpy(fattr_res, &fattr[i], sizeof(struct ftp_fattr));
			    ret = 0;
			    goto out_release_page;
			}
		}

		/* release page */
		kunmap(page);
		put_page(page);
	}

out_release_page:
	kunmap(page);
	put_page(page);
out:
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
	.lookup		= ftpfs_lookup,
};
