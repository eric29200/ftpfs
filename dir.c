#include <linux/pagemap.h>

#include "ftpfs.h"

/*
 * Read a directory page.
 */
static int ftpfs_dir_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct socket *sock_data;
	int ret, pg_off, pg_idx;
	struct ftp_fattr fattr;
	char *buffer;

	/* map page and reset it */
	buffer = kmap(page);
	memset(buffer, 0, PAGE_SIZE);

	/* start directory listing */
	sock_data = ftp_list_start(ftpfs_sb(inode->i_sb)->s_ftp_server, ftpfs_i(inode)->i_path);
	if (IS_ERR(sock_data)) {
		ret = PTR_ERR(sock_data);
		goto err;
	}

	/* for each directory entry */
	for (pg_off = 0, pg_idx = 0;;) {
		/* get next directory entry */
		ret = ftp_list_next(ftpfs_sb(inode->i_sb)->s_ftp_server, sock_data, &fattr);
		if (ret < 0)
			goto err;

		/* end of directory */
		if (ret == 0)
			break;

		/* copy directory entry */
		if (pg_idx == page_index(page))
			memcpy(buffer + pg_off, &fattr, sizeof(struct ftp_fattr));

		/* update page offset and index */
		pg_off += sizeof(struct ftp_fattr);
		if (pg_off + sizeof(struct ftp_fattr) >= PAGE_SIZE) {
			pg_idx++;
			pg_off = 0;
		}

		/* end of page */
		if (pg_idx > page_index(page))
			break;
	}

	/* set page up to date */
	ClearPageError(page);
	SetPageUptodate(page);
	ret = 0;
	goto out;
err:
	ClearPageUptodate(page);
	SetPageError(page);
out:
	if (!IS_ERR(sock_data))
		ftp_list_end(ftpfs_sb(inode->i_sb)->s_ftp_server, sock_data);
	kunmap(page);
	unlock_page(page);
	return ret;
}

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct ftp_fattr *fattr;
	unsigned long pg_idx;
	struct page *page;
	int name_len, i;

	/* emit "." */
	if (ctx->pos == 0) {
		if (ctx->actor(ctx, ".", 1, ctx->pos, 1, DT_DIR))
			return 0;
		ctx->pos = 1;
	}

	/* emit ".." */
	if (ctx->pos == 1) {
		if (ctx->actor(ctx, "..", 2, ctx->pos, 1, DT_DIR))
			return 0;
		ctx->pos = 2;
	}

	/* compute page index and page offset */
	pg_idx = (ctx->pos - 2) / (PAGE_SIZE / sizeof(struct ftp_fattr));
	i = (ctx->pos - 2) % (PAGE_SIZE / sizeof(struct ftp_fattr));

	/* for each page */
	for (;; pg_idx++, i = 0) {
		/* read next page */
		page = read_mapping_page(file->f_inode->i_mapping, pg_idx, NULL);
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

			/* emit file */
			if (!dir_emit(ctx, fattr[i].f_name, name_len, 1, DT_UNKNOWN))
				goto out_release_page;

			/* update context position */
			ctx->pos++;
		}

		/* release page */
		kunmap(page);
		put_page(page);
	}

out_release_page:
	kunmap(page);
	put_page(page);
out:
	return 0;
}

/*
 * FTPFS directory file operations.
 */
const struct file_operations ftpfs_dir_fops = {
	.iterate_shared		= ftpfs_readdir,
};

/*
 * FTPFS directory address space operations.
 */
const struct address_space_operations ftpfs_dir_aops = {
	.readpage	= ftpfs_dir_readpage,
};
