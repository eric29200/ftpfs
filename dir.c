#include "ftpfs.h"

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct socket *sock_data;
	struct ftp_fattr fattr;
	loff_t i = 2;
	int n;

	/* emit "." and ".." */
	if (!dir_emit_dots(file, ctx))
		return 0;

	/* start directory listing */
	sock_data = ftp_list_start(ftpfs_sb(file->f_inode->i_sb)->s_ftp_server, ftpfs_i(file->f_inode)->i_path);
	if (IS_ERR(sock_data))
		return PTR_ERR(sock_data);

	/* for each directory entry */
	for (;;) {
		/* get next directory entry */
		n = ftp_list_next(ftpfs_sb(file->f_inode->i_sb)->s_ftp_server, sock_data, &fattr);
		if (n <= 0)
			break;

		/* skip first entries */
		if (i++ < ctx->pos)
			continue;

		/* emit file */
		if (!dir_emit(ctx, fattr.f_name, strnlen(fattr.f_name, FTP_MAX_NAMELEN), 1, DT_UNKNOWN))
			goto out;

		/* update position */
		ctx->pos++;
	}

out:
	/* end directory listing */
	ftp_list_end(ftpfs_sb(file->f_inode->i_sb)->s_ftp_server, sock_data);

	return 0;
}

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared			= ftpfs_readdir,
};
