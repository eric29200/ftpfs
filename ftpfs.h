/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FTPFS_H_
#define _FTPFS_H_

#include <linux/fs.h>
#include <linux/fs_context.h>

#include "ftp.h"

#define FTPFS_FTP_USER_DEFAULT		"anonymous"
#define FTPFS_FTP_PASSWD_DEFAULT	"anonymous"
#define FTPFS_DIR_REVALID_SEC		10
#define FTPFS_UNIQUE_INO		1

/*
 * FTPFS mount options.
 */
struct ftpfs_mount_opts {
	char				*user;			/* FTP user */
	char				*passwd;		/* FTP passwd */
	unsigned long			dir_revalid_sec;	/* frequency to revalidate directories (in second) */
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
	struct ftpfs_mount_opts		s_opt;			/* mount options */
};

/*
 * FTPFS in memory inode.
 */
struct ftpfs_inode_info {
	char				*i_path;		/* inode full path */
	unsigned long			i_mapping_expires;	/* jiffies when inode mapping expires */
	struct inode			vfs_inode;		/* VFS inode */
};

/* FTPFS operations */
extern const struct dentry_operations ftpfs_dops;
extern const struct inode_operations ftpfs_file_iops;
extern const struct inode_operations ftpfs_dir_iops;
extern const struct inode_operations ftpfs_symlink_iops;
extern const struct file_operations ftpfs_file_fops;
extern const struct file_operations ftpfs_dir_fops;

/* FTPFS inode protoypes (defined in inode.c) */
struct inode *ftpfs_iget(struct super_block *sb, struct inode *dir, struct ftp_fattr *fattr);
int ftpfs_inode_revalidate_mapping(struct inode *inode);

/* FTPFS directory prototypes (defined in dir.c) */
int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res);

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

#endif
