// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Get a super block netfs volume.
 */
int ftpfs_cache_super_get_volume(struct super_block *sb, const char *source)
{
	struct ftpfs_sb_info *sbi = ftpfs_sb(sb);
	struct fscache_volume *volume;
	char *name, *p;
	int ret = 0;

	/* set volume name */
	name = kasprintf(GFP_KERNEL, "ftpfs,%s", source);
	if (!name)
		return -ENOMEM;

	/* '/' are not allowed in volume name */
	for (p = name; *p; p++)
		if (*p == '/')
			*p = ';';

	/* get volume */
	volume = fscache_acquire_volume(name, NULL, NULL, 0);
	if (IS_ERR(volume)) {
		ret = PTR_ERR(volume);
		volume = NULL;
	}

	sbi->s_fscache = volume;
	kfree(name);
	return ret;
}

/*
 * Get an inode netfs cookie.
 */
void ftpfs_cache_inode_get_cookie(struct inode *inode)
{
	struct ftpfs_inode_info *ftpfs_inode = ftpfs_i(inode);
	struct ftpfs_sb_info *sbi = ftpfs_sb(inode->i_sb);
	int version = 0;

	/* only implemented on regular files */
	if (!S_ISREG(inode->i_mode))
		return;

	/* get cookie */
	ftpfs_inode->i_fscache = fscache_acquire_cookie(sbi->s_fscache, 0,
							ftpfs_inode->i_path, strlen(ftpfs_inode->i_path),
							&version, sizeof(version),
							i_size_read(inode));
}
