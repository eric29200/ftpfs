// SPDX-License-Identifier: GPL-2.0-only
#include "ftpfs.h"

/*
 * Read a file.
 */
ssize_t ftpfs_file_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct inode *inode = file_inode(file);

	return ftp_read(ftpfs_sb(inode->i_sb)->s_ftp_server, ftpfs_i(inode)->i_path, buf, count, pos);
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.read		= ftpfs_file_read,
	.llseek		= generic_file_llseek,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {

};
