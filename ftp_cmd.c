// SPDX-License-Identifier: GPL-2.0-only
#include <linux/pagemap.h>

#include "ftp.h"

/*
 * FTP months, printed in LIST command
 */
static const char * const ftp_months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * Parse a FTP directory line into file attributes.
 */
static int ftp_parse_dir_entry(char *line, int len, struct ftp_fattr *fattr)
{
	unsigned int year, month, day, hour, min;
	char mode[12], *tok, *link_marker;
	time64_t time_now;
	struct tm tm_now;
	int i;

	/* reset file name and target link */
	memset(fattr->f_name, 0, FTP_MAX_NAMELEN);
	memset(fattr->f_link, 0, FTP_MAX_NAMELEN);

	/* remove ending '\n' */
	if (len <= 0)
		goto err;
	if (line[len - 1] == '\n')
		line[--len] = 0;

	/* remove ending '\r' */
	if (len <= 0)
		goto err;
	if (line[len - 1] == '\r')
		line[--len] = 0;

	/* first field = permissions */
	tok = strsep(&line, " ");
	if (!tok || sscanf(tok, "%11s", mode) != 1)
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = nlinks */
	tok = strsep(&line, " ");
	if (!tok || kstrtouint(tok, 10, &fattr->f_nlinks))
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = user */
	tok = strsep(&line, " ");
	if (!tok)
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = group */
	tok = strsep(&line, " ");
	if (!tok)
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = size */
	tok = strsep(&line, " ");
	if (!tok || kstrtoull(tok, 10, &fattr->f_size))
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = month */
	tok = strsep(&line, " ");
	if (!tok)
		goto err;

	/* parse month */
	for (month = 0; month < 12; month++)
		if (strcmp(ftp_months[month], tok) == 0)
			break;
	if (month == 12)
		goto err;
	month++;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = day */
	tok = strsep(&line, " ");
	if (!tok || kstrtouint(tok, 10, &day))
		goto err;

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* next field = year or hour (if current year) */
	tok = strsep(&line, " ");
	if (!tok)
		goto err;
	if (sscanf(tok, "%u:%u", &hour, &min) == 2) {
		time_now = ktime_get_real_seconds();
		time64_to_tm(time_now, 0, &tm_now);
		year = tm_now.tm_year + 1900;
	} else if (!kstrtouint(tok, 10, &year)) {
		hour = 0;
		min = 0;
	} else {
		goto err;
	}

	/* skip spaces */
	line = line ? skip_spaces(line) : NULL;
	if (!line)
		goto err;

	/* end of line = file name (and maybe link target) */
	link_marker = strstr(line, " -> ");
	if (link_marker) {
		*link_marker = 0;
		strncpy(fattr->f_name, line, FTP_MAX_NAMELEN - 1);
		strncpy(fattr->f_link, link_marker + 4, FTP_MAX_NAMELEN - 1);
	} else {
		strncpy(fattr->f_name, line, FTP_MAX_NAMELEN - 1);
	}

	/* parse mode */
	if (mode[0] == 'd')
		fattr->f_mode = S_IFDIR;
	else if (mode[0] == 'l')
		fattr->f_mode = S_IFLNK;
	else
		fattr->f_mode = S_IFREG;
	for (i = 1; i < 10; i++)
		if (mode[i] != '-')
			fattr->f_mode |= 1 << (9 - i);

	/* make time */
	fattr->f_time = mktime64(year, month, day, hour, min, 0);

	return 0;
err:
	return -ENOSPC;
}

/*
 * Read next buffer.
 */
static ssize_t ftp_read_next(struct ftp_session *session, char *buf, size_t count)
{
	struct msghdr msg;
	struct kvec iov;
	loff_t off;
	int n;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* get data and copy it to output buffer */
	for (off = 0; count > 0;) {
		/* set buffer */
		iov.iov_base = buf + off;
		iov.iov_len = count;

		/* get next buffer */
		n = ftp_recvmsg(session->data_sock, &msg, &iov);
		if (n < 0)
			return n;
		if (n == 0)
			break;

		/* update position */
		session->data_pos += n;
		off += n;
		count -= n;
	}

	/* return number of bytes read */
	return off;
}

/*
 * Write next buffer.
 */
static ssize_t ftp_write_next(struct ftp_session *session, char *buf, size_t count)
{
	struct msghdr msg;
	struct kvec iov;
	loff_t off;
	int n;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = &session->saddr;
	msg.msg_namelen = sizeof(session->saddr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* send data */
	for (off = 0; count > 0;) {
		/* set buffer */
		iov.iov_base = buf + off;
		iov.iov_len = count;

		/* send next buffer */
		n = ftp_sendmsg(session->data_sock, &msg, &iov);
		if (n < 0)
			return n;
		if (n == 0)
			break;

		/* update position */
		session->data_pos += n;
		off += n;
		count -= n;
	}

	/* return number of bytes written */
	return off;
}

/*
 * Get next directory entry.
 */
static ssize_t ftp_list_next(struct ftp_session *session, struct ftp_fattr *fattr_res)
{
	ssize_t n;

	/* reset result */
	memset(fattr_res, 0, sizeof(struct ftp_fattr));

	for (;;) {
		/* get next line */
		n = ftp_getline(session, session->data_sock);
		if (n <= 0)
			break;

		/* parse directory entry (on error, goto next entry) */
		if (ftp_parse_dir_entry(session->buf, n, fattr_res) == 0) {
			session->data_pos++;
			break;
		}
	}

	return n;

}

/*
 * Start a read request.
 */
static int ftp_read_start(struct ftp_session *session, ino_t ino, const char *file_path, loff_t pos)
{
	char nb_buf[64];
	int ret;

	/* session is opened at correct data offset : just return */
	if (ftp_session_is_valid(session, ino, FTP_REQUEST_READ, pos))
		return 0;

	/* a data socket is opened with wrong direction/offset : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		return ret;

	/* open a data socket */
	ret = ftp_open_data_socket(session);
	if (ret)
		return ret;

	/* send restart command */
	if (pos) {
		snprintf(nb_buf, 64, "%lld", pos);
		if (ftp_cmd(session, "REST", nb_buf) != FTP_STATUS_OK_SO_FAR)
			return -ENOSPC;
	}

	/* send retrieve command */
	ret = ftp_cmd(session, "RETR", file_path);

	/* exit on error */
	if (ret != FTP_STATUS_OK_INIT)
		return -ENOSPC;

	session->data_request = FTP_REQUEST_READ;
	session->data_ino = ino;
	session->data_pos = pos;
	return 0;
}

/*
 * Start a write request.
 */
static int ftp_write_start(struct ftp_session *session, ino_t ino, const char *file_path, loff_t pos)
{
	char nb_buf[64];
	int ret;

	/* session is opened at correct data offset : just return */
	if (ftp_session_is_valid(session, ino, FTP_REQUEST_WRITE, pos))
		return 0;

	/* a data socket is opened with wrong direction/offset : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		return ret;

	/* open a data socket */
	ret = ftp_open_data_socket(session);
	if (ret)
		return ret;

	/* send restart command */
	if (pos) {
		snprintf(nb_buf, 64, "%lld", pos);
		if (ftp_cmd(session, "REST", nb_buf) != FTP_STATUS_OK_SO_FAR)
			return -ENOSPC;
	}

	/* send store command */
	ret = ftp_cmd(session, "STOR", file_path);

	/* exit on error */
	if (ret != FTP_STATUS_OK_INIT)
		return -ENOSPC;

	session->data_request = FTP_REQUEST_WRITE;
	session->data_ino = ino;
	session->data_pos = pos;
	return 0;
}

/*
 * Start a directory listing.
 */
static int ftp_list_start(struct ftp_session *session, ino_t ino, const char *file_path, loff_t pos)
{
	struct ftp_fattr fattr;
	int ret, i;

	/* session is opened at correct data offset : just return */
	if (ftp_session_is_valid(session, ino, FTP_REQUEST_LIST, pos))
		return 0;

	/* a data socket is opened with wrong direction/offset : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		return ret;

	/* open a data socket */
	ret = ftp_open_data_socket(session);
	if (ret)
		return ret;

	/* send LIST command */
	ret = ftp_cmd(session, "LIST", file_path);

	/* exit on error */
	if (ret != FTP_STATUS_OK_INIT)
		return -ENOSPC;

	/* skip first entries */
	for (i = 0; i < pos; i++) {
		ret = ftp_list_next(session, &fattr);
		if (ret < 0)
			return ret;
	}

	session->data_request = FTP_REQUEST_LIST;
	session->data_ino = ino;
	session->data_pos = pos;
	return 0;
}

/*
 * Read from FTP.
 */
ssize_t ftp_read(struct ftp_session *session, const char *file_path, ino_t ino,
		 loff_t pos, struct iov_iter *iter, size_t iter_len)
{
	size_t bytes, page_off, npages, req_len, total = 0;
	struct page **pages;
	ssize_t ret;
	char *buf;
	int i;

	/* get pages */
	bytes = iov_iter_get_pages_alloc(iter, &pages, iter_len, &page_off);
	if (bytes < 0)
		return bytes;

	/* get number of pages */
	npages = (bytes + page_off + PAGE_SIZE - 1) / PAGE_SIZE;

	/* start READ request */
	ret = ftp_read_start(session, ino, file_path, pos);
	if (ret)
		goto out;

	/* read each page */
	for (i = 0; i < npages; i++) {
		/* write next buffer */
		buf = kmap(pages[i]);
		req_len = min_t(size_t, bytes, PAGE_SIZE - page_off);
		ret = ftp_read_next(session, buf + page_off, req_len);
		kunmap(pages[i]);
		if (ret < 0)
			goto out;
		if (ret == 0)
			break;

		page_off = 0;
		total += ret;
	}

	ret = total;
out:
	for (i = 0; i < npages; i++)
		put_page(pages[i]);
	return ret;
}

/*
 * Write to FTP.
 */
ssize_t ftp_write(struct ftp_session *session, const char *file_path, ino_t ino,
		  loff_t pos, struct iov_iter *iter, size_t iter_len)
{
	size_t bytes, page_off, npages, req_len, total = 0;
	struct page **pages;
	ssize_t ret;
	char *buf;
	int i;

	/* get pages */
	bytes = iov_iter_get_pages_alloc(iter, &pages, iter_len, &page_off);
	if (bytes < 0)
		return bytes;

	/* get number of pages */
	npages = (bytes + page_off + PAGE_SIZE - 1) / PAGE_SIZE;

	/* start WRITE request */
	ret = ftp_write_start(session, ino, file_path, pos);
	if (ret)
		goto out;

	/* write each page */
	for (i = 0; i < npages; i++) {
		/* write next buffer */
		buf = kmap(pages[i]);
		req_len = min_t(size_t, bytes, PAGE_SIZE - page_off);
		ret = ftp_write_next(session, buf + page_off, req_len);
		kunmap(pages[i]);
		if (ret < 0)
			goto out;
		if (ret == 0)
			break;

		page_off = 0;
		total += ret;
	}

	ret = total;
out:
	for (i = 0; i < npages; i++)
		put_page(pages[i]);
	return ret;
}

/*
 * List an entry in a directory.
 */
ssize_t ftp_list(struct ftp_session *session, const char *file_path, ino_t ino, loff_t pos, struct ftp_fattr *res_fattr)
{
	int ret;

	/* start LIST request */
	ret = ftp_list_start(session, ino, file_path, pos);
	if (ret) {
		ftp_session_close(session);
		return ret;
	}

	/* list next entry */
	return ftp_list_next(session, res_fattr);
}

/*
 * Create a file.
 */
int ftp_create(struct ftp_session *session, const char *file_path)
{
	/* a data socket is opened : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* start write */
	return ftp_write_start(session, -1, file_path, 0);
}

/*
 * Delete a file.
 */
int ftp_delete(struct ftp_session *session, const char *file_path)
{
	int ret;

	/* a data socket is opened : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* send delete command */
	if (ftp_cmd(session, "DELE", file_path) != FTP_STATUS_OK) {
		ret = -ENOSPC;
		goto err;
	}

	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * Create a directory.
 */
int ftp_mkdir(struct ftp_session *session, const char *file_path)
{
	int ret;

	/* a data socket is opened : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* send mkdir command */
	if (ftp_cmd(session, "MKD", file_path) != FTP_STATUS_OK) {
		ret = -ENOSPC;
		goto err;
	}

	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * Delete a directory.
 */
int ftp_rmdir(struct ftp_session *session, const char *file_path)
{
	int ret;

	/* a data socket is opened : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* send rmdir command */
	if (ftp_cmd(session, "RMD", file_path) != FTP_STATUS_OK) {
		ret = -ENOSPC;
		goto err;
	}

	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * Rename file.
 */
int ftp_rename(struct ftp_session *session, const char *old_path, const char *new_path)
{
	int ret;

	/* a data socket is opened : close session */
	if (ftp_session_is_opened_for_data(session))
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* send rename from command */
	if (ftp_cmd(session, "RNFR", old_path) != FTP_STATUS_OK_SO_FAR) {
		ret = -ENOSPC;
		goto err;
	}

	/* send rename to command */
	if (ftp_cmd(session, "RNTO", new_path) != FTP_STATUS_OK) {
		ret = -ENOSPC;
		goto err;
	}

	return 0;
err:
	ftp_session_close(session);
	return ret;
}
