// SPDX-License-Identifier: GPL-2.0-only
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
 * Start a directory listing.
 */
int ftp_list_start(struct ftp_session *session, const char *dir)
{
	int ret;

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* open a data socket */
	ret = ftp_open_data_socket(session);
	if (ret)
		goto err;

	/* send list command */
	if (ftp_cmd(session, "LIST", dir) != FTP_STATUS_OK_INIT) {
		ret = -ENOSPC;
		goto err;
	}

	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * End a directory listing (= close data socket, get server reply and unlock session).
 */
void ftp_list_end(struct ftp_session *session)
{
	/* close data socket */
	session->data_sock->ops->release(session->data_sock);
	session->data_sock = NULL;

	/* get FTP reply and disconnect on error */
	if (ftp_getreply(session) != FTP_STATUS_OK)
		ftp_session_close(session);
}

/*
 * End a directory listing with failure (= close session).
 */
void ftp_list_failed(struct ftp_session *session)
{
	/* close session */
	ftp_session_close(session);
}

/*
 * Get next directory entry (this function must be called between ftp_list_start and ftp_list_end).
 */
int ftp_list_next(struct ftp_session *session, struct ftp_fattr *fattr_res)
{
	int n;

	/* reset result */
	memset(fattr_res, 0, sizeof(struct ftp_fattr));

	for (;;) {
		/* get next line */
		n = ftp_getline(session, session->data_sock);
		if (n <= 0)
			break;

		/* parse directory entry (on error, goto next entry) */
		if (ftp_parse_dir_entry(session->buf, n, fattr_res) == 0)
			break;
	}

	return n;
}

/*
 * Start a FTP read command.
 */
int ftp_read_start(struct ftp_session *session, const char *file_path, loff_t pos)
{
	char nb_buf[64];
	int ret;

	/* session is opened at correct data offset : just return */
	if (ftp_session_is_opened(session) && session->data_sock && pos == session->data_pos)
		return 0;

	/* a data socket is opened at wrong offset : close session */
	if (session->data_sock && pos != session->data_pos)
		ftp_session_close(session);

	/* open session */
	ret = ftp_session_open(session);
	if (ret)
		goto err;

	/* open a data socket */
	ret = ftp_open_data_socket(session);
	if (ret)
		goto err;

	/* send restore command */
	if (pos) {
		snprintf(nb_buf, 64, "%lld", pos);
		if (ftp_cmd(session, "REST", nb_buf) != FTP_STATUS_OK_SO_FAR) {
			ret = -ENOSPC;
			goto err;
		}
	}

	/* send retrieve command */
	if (ftp_cmd(session, "RETR", file_path) != FTP_STATUS_OK_INIT) {
		ret = -ENOSPC;
		goto err;
	}

	session->data_pos = 0;
	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * End with success a read command.
 */
void ftp_read_end(struct ftp_session *session)
{
	/* close data socket */
	session->data_sock->ops->release(session->data_sock);
	session->data_sock = NULL;

	/* get FTP reply and disconnect on error */
	if (ftp_getreply(session) == FTP_STATUS_KO)
		ftp_session_close(session);
}

/*
 * End with failure a read command.
 */
void ftp_read_failed(struct ftp_session *session)
{
	/* close session */
	ftp_session_close(session);
}

/*
 * Read next buffer.
 */
int ftp_read_next(struct ftp_session *session, char __user *buf, size_t count)
{
	struct msghdr msg;
	struct kvec iov;
	loff_t off;
	int ret, n;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* get data and copy it to output buffer */
	for (off = 0; count > 0;) {
		/* set buffer */
		iov.iov_base = session->buf;
		iov.iov_len = count <= PAGE_SIZE ? count : PAGE_SIZE;

		/* get next buffer */
		n = ftp_recvmsg(session->data_sock, &msg, &iov);
		if (n < 0)
			goto err;
		if (n == 0)
			break;

		/* copy to output buffer */
		if (copy_to_user(buf + off, session->buf, n))
			break;

		/* update position */
		session->data_pos += n;
		off += n;
		count -= n;
	}

	/* return number of bytes read */
	return off;
err:
	ftp_session_close(session);
	return ret;
}
