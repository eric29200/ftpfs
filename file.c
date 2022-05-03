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
 * Write a file.
 */
ssize_t ftpfs_file_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	struct inode *inode = file_inode(file);
	int ret;

	/* lock inode */
	inode_lock(inode);

	/* update inode time */
	file_update_time(file);

	/* handle append mode */
	if (file->f_flags & O_APPEND)
		*pos = i_size_read(inode);
	else
		*pos = file->f_pos;

	/* write on FTP server */
	ret = ftp_write(ftpfs_sb(inode->i_sb)->s_ftp_server, ftpfs_i(inode)->i_path, buf, count, pos);
	if (ret <= 0)
		goto out;

	/* update inode size */
	if (*pos > i_size_read(inode))
		i_size_write(inode, *pos);

out:
	inode_unlock(inode);
	return ret;
}

/*
 * FTPFS file operations.
 */
const struct file_operations ftpfs_file_fops = {
	.read		= ftpfs_file_read,
	.write		= ftpfs_file_write,
	.llseek		= generic_file_llseek,
};

/*
 * FTPFS file inode operations.
 */
const struct inode_operations ftpfs_file_iops = {

};
