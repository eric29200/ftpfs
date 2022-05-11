/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FTPFS_H_
#define _FTPFS_H_

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/pagemap.h>
#include <linux/fscache.h>

#include "ftp.h"

#define FTPFS_FTP_USER_DEFAULT			"anonymous"
#define FTPFS_FTP_PASSWD_DEFAULT		"anonymous"
#define FTPFS_CACHE_TIMEOUT_SEC			10
#define FTPFS_DIR_ENTRIES_PER_PAGE		(PAGE_SIZE / sizeof(struct ftp_fattr))
#define FTPFS_NB_CONNECTIONS			2

/*
 * FTPFS mount options.
 */
struct ftpfs_mount_opts {
	char				*user;			/* FTP user */
	char				*passwd;		/* FTP passwd */
	unsigned long			cache_timeout_sec;	/* frequency to revalidate buffer cache */
	unsigned long			nb_connections;		/* number of connections/session */
};

/*
 * FTPFS file system context.
 */
struct ftpfs_fs_context {
	struct ftpfs_mount_opts		fs_opt;			/* mount options */
};

/*
 * FTPFS in memory super block.
 */
struct ftpfs_sb_info {
	struct ftp_server		*s_ftp_server;		/* FTP server */
	struct fscache_volume		*s_fscache;		/* netfs cache volume */
	struct ftpfs_mount_opts		s_opt;			/* mount options */
};

/*
 * FTPFS in memory inode.
 */
struct ftpfs_inode_info {
	char				*i_path;		/* inode full path */
	struct fscache_cookie		*i_fscache;		/* netfs cache cookie */
	unsigned long			i_expires;		/* jiffies when inode needs to be revalidated */
	struct inode			vfs_inode;		/* VFS inode */
};

/* root file attributes */
extern struct ftp_fattr root_fattr;

/* FTPFS operations */
extern const struct dentry_operations ftpfs_dops;
extern const struct inode_operations ftpfs_file_iops;
extern const struct inode_operations ftpfs_dir_iops;
extern const struct inode_operations ftpfs_symlink_iops;
extern const struct file_operations ftpfs_file_fops;
extern const struct file_operations ftpfs_dir_fops;
extern const struct address_space_operations ftpfs_file_aops;
extern const struct address_space_operations ftpfs_dir_aops;

/* FTPFS inode protoypes (defined in inode.c) */
struct inode *ftpfs_iget(struct super_block *sb, struct inode *dir, struct ftp_fattr *fattr);
int ftpfs_refresh_inode(struct inode *inode, struct inode *dir, struct ftp_fattr *fattr);
void ftpfs_invalidate_inode_cache(struct inode *inode);
char *ftpfs_build_full_path(struct inode *dir, struct ftp_fattr *fattr);

/* FTPFS name resolution prototypes (defined in namei.c) */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res);

/* FTPFS cache prototypes (defined in cache.c) */
int ftpfs_cache_super_get_volume(struct super_block *sb, const char *source);
void ftpfs_cache_inode_get_cookie(struct inode *inode);

/*
 * Get FTPFS context from generic context.
 */
static inline struct ftpfs_fs_context *ftpfs_ctx(struct fs_context *fc)
{
	return fc->fs_private;
}

/*
 * Get FTPFS in memory super block from generic super block.
 */
static inline struct ftpfs_sb_info *ftpfs_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * Get FTPFS in memory inode from generic inode.
 */
static inline struct ftpfs_inode_info *ftpfs_i(struct inode *inode)
{
	return container_of(inode, struct ftpfs_inode_info, vfs_inode);
}

/*
 * Get an inode page.
 */
static inline struct page *ftpfs_pagecache_get_page(struct inode *inode, pgoff_t index)
{
	return pagecache_get_page(inode->i_mapping, index,
				  FGP_LOCK | FGP_ACCESSED | FGP_NOWAIT,
				  readahead_gfp_mask(inode->i_mapping) & ~__GFP_FS);
}

#endif
