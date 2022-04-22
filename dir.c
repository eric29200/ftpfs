#include "ftpfs.h"

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	char *start, *end, *line = NULL;
	struct ftp_fattr fattr;
	size_t off, rem;
	loff_t i = 2;
	int ret;

	/* load inode data into cache = directory listing */
	ret = ftpfs_load_inode_data(file->f_inode, NULL);
	if (ret)
		return ret;

	/* emit "." and ".." */
	if (!dir_emit_dots(file, ctx))
		return 0;

	/* acquire cache semaphore */
	down_read(&ftpfs_i(file->f_inode)->i_cache_rw_sem);

	/* parse all directory entries */
	for (off = 0; off < ftpfs_i(file->f_inode)->i_cache.len;) {
		/* compute start line and remaining characters in cache */
		start = ftpfs_i(file->f_inode)->i_cache.data + off;
		rem = ftpfs_i(file->f_inode)->i_cache.len - off;

		/* find end of line or end of buf */
		end = strnchr(start, rem, '\n');
		if (!end)
			end = start + rem;

		/* handle carriage return */
		if (end > start && *(end - 1) == '\r')
			end--;

		/* allocate line */
		line = kmalloc(end - start + 1, GFP_KERNEL);
		if (!line) {
			ret = -ENOMEM;
			goto out;
		}

		/* copy line */
		strncpy(line, start, end - start);
		line[end - start] = 0;

		/* parse line */
		if (ftp_parse_dir_entry(line, end - start, &fattr))
			goto next_line;

		/* skip first entries */
		if (i++ < ctx->pos)
			goto next_line;

		/* emit file */
		if (!dir_emit(ctx, fattr.f_name, strnlen(fattr.f_name, FTP_MAX_NAMELEN), 1, DT_UNKNOWN))
			goto out;

		/* update position */
		ctx->pos++;

next_line:
		/* free line */
		kfree(line);
		line = NULL;

		/* go to next line */
		off = end - ftpfs_i(file->f_inode)->i_cache.data + (*end == '\r' ? 2 : 1);
	}

out:
	/* release cache semaphore */
	up_read(&ftpfs_i(file->f_inode)->i_cache_rw_sem);

	/* free last line */
	kfree(line);

	return ret;
}

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared			= ftpfs_readdir,
};
