#ifndef _FTPFS_H_
#define _FTPFS_H_

#include <linux/fs.h>

#include "ftp.h"

#define FTPFS_FTP_USER            "anonymous"
#define FTPFS_FTP_PASSWD          "anonymous"

/*
 * FTPFS in memory super block.
 */
struct ftpfs_sb_info {
  struct ftp_server               *s_ftp_server;        /* FTP server */
};

/*
 * FTPFS in memory inode.
 */
struct ftpfs_inode_info {
  char                            *i_path;              /* inode full path */
  struct ftp_buffer               i_cache;              /* cached data */
  struct inode                    vfs_inode;            /* VFS inode */
};

/* FTPFS operations */
extern struct inode_operations ftpfs_file_iops;
extern struct inode_operations ftpfs_dir_iops;
extern struct inode_operations ftpfs_symlink_iops;
extern struct file_operations ftpfs_file_fops;
extern struct file_operations ftpfs_dir_fops;

/* FTPFS inode protoypes (defined in inode.c) */
struct inode *ftpfs_iget(struct super_block *sb, struct inode *dir, struct ftp_fattr *fattr);
int ftpfs_load_inode_data(struct inode *inode, struct ftp_fattr *fattr);

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
