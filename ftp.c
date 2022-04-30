// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/dns_resolver.h>
#include <linux/sunrpc/addr.h>
#include <linux/inet.h>

#include "ftp.h"

/*
 * FTP months, printed in LIST command
 */
static const char * const ftp_months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * Send a message on a socket (on ERESTARTSYS failure, wait 100 ms and retry).
 */
static int ftp_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov)
{
	int ret;

	ret = kernel_sendmsg(sock, msg, iov, 1, iov->iov_len);
	if (ret == -ERESTARTSYS) {
		msleep(100);
		ret = kernel_sendmsg(sock, msg, iov, 1, iov->iov_len);
	}

	return ret;
}

/*
 * Receive a message on a socket (on ERESTARTSYS failure, wait 100 ms and retry).
 */
static int ftp_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov)
{
	int ret;

	ret = kernel_recvmsg(sock, msg, iov, 1, iov->iov_len, 0);
	if (ret == -ERESTARTSYS) {
		msleep(100);
		ret = kernel_recvmsg(sock, msg, iov, 1, iov->iov_len, 0);
	}

	return ret;
}

/*
 * Get a line from a FTP server (returns number of character read).
 */
static int ftp_getline(struct ftp_server *ftp_server, struct socket *sock)
{
	struct msghdr msg;
	struct kvec iov;
	int ret, n = 0;
	char c;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base = &c;
	iov.iov_len = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* get line */
	for (n = 0;;) {
		/* read next character */
		ret = ftp_recvmsg(sock, &msg, &iov);
		if (ret < 0)
			return ret;

		/* end of message */
		if (ret == 0)
			break;

		/* store character */
		if (n < PAGE_SIZE)
			ftp_server->ftp_buf[n++] = c;

		/* end of line */
		if (c == '\n')
			break;
	}

	/* end buf with 0 */
	if (n >= PAGE_SIZE)
		n--;
	ftp_server->ftp_buf[n] = 0;

	return n;
}

/*
 * Get a reply from a FTP server (return FTP status code).
 */
static int ftp_getreply(struct ftp_server *ftp_server)
{
	int n, i, ret;

	for (i = 0;; i++) {
		/* get next line */
		n = ftp_getline(ftp_server, ftp_server->ftp_sock);
		if (n < 0)
			return n;
		if (n == 0)
			return FTP_STATUS_KO;

		/* break on FTP status message */
		if (n < 4)
			continue;
		if (i == 0 && ftp_server->ftp_buf[3] != '-')
			break;
		if (i != 0 && isdigit(ftp_server->ftp_buf[0]) && isdigit(ftp_server->ftp_buf[1])
		    && isdigit(ftp_server->ftp_buf[2]) && ftp_server->ftp_buf[3] == ' ')
			break;
	}

	/* return FTP status code */
	ret = ftp_server->ftp_buf[0] - '0';
	if (ret == FTP_STATUS_KO)
		pr_err("FTPFS : %s", ftp_server->ftp_buf);

	return ret;
}

/*
 * Send a command to a FTP server (return FTP reply status code).
 */
static int ftp_cmd(struct ftp_server *ftp_server, const char *cmd, const char *arg)
{
	struct msghdr msg;
	struct kvec iov;
	int ret, n;

	/* build command */
	if (arg)
		n = snprintf(ftp_server->ftp_buf, PAGE_SIZE, "%s %s\r\n", cmd, arg);
	else
		n = snprintf(ftp_server->ftp_buf, PAGE_SIZE, "%s\r\n", cmd);

	/* check command buffer */
	if (n <= 0)
		return FTP_STATUS_KO;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base = ftp_server->ftp_buf;
	iov.iov_len = n;
	msg.msg_name = &ftp_server->ftp_saddr;
	msg.msg_namelen = sizeof(ftp_server->ftp_saddr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* send message */
	ret = ftp_sendmsg(ftp_server->ftp_sock, &msg, &iov);
	if (ret < 0)
		return ret;
	if (ret != iov.iov_len)
		return FTP_STATUS_KO;

	/* return FTP reply */
	return ftp_getreply(ftp_server);
}

/*
 * Resolve host name.
 */
static int ftp_resolve_host(struct ftp_server *ftp_server)
{
	int ip_len, sa_len, ret = 0;
	char *ip_addr;

	/* check hostname */
	if (!ftp_server->ftp_sname)
		return -EINVAL;

	/* resolve host name */
	ip_len = dns_query(&init_net, NULL, ftp_server->ftp_sname, strlen(ftp_server->ftp_sname),
			   NULL, &ip_addr, NULL, false);
	if (ip_len < 0)
		return -ESRCH;

	/* build ip address */
	sa_len = rpc_pton(&init_net, ip_addr, ip_len, (struct sockaddr *) &ftp_server->ftp_saddr,
			  sizeof(ftp_server->ftp_saddr));
	if (sa_len < 0)
		ret = sa_len;

	kfree(ip_addr);
	return ret;
}

/*
 * Check if a FTP server is connected.
 */
static inline bool ftp_is_connected(struct ftp_server *ftp_server)
{
	return ftp_server->ftp_sock && ftp_server->ftp_sock->ops;
}

/*
 * Disconnect from server.
 */
static void ftp_disconnect(struct ftp_server *ftp_server)
{
	if (ftp_is_connected(ftp_server)) {
		ftp_server->ftp_sock->ops->release(ftp_server->ftp_sock);
		ftp_server->ftp_sock = NULL;
	}
}

/*
 * Connect to a FTP server (server must be locked).
 */
int ftp_connect(struct ftp_server *ftp_server)
{
	int ret;

	/* already connected */
	if (ftp_is_connected(ftp_server))
		return 0;

	/* create socket */
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &ftp_server->ftp_sock);
	if (ret)
		goto err;

	/* resolve host name */
	ret = ftp_resolve_host(ftp_server);
	if (ret)
		goto err;

	/* connect to server */
	ftp_server->ftp_saddr.sin_family = AF_INET;
	ftp_server->ftp_saddr.sin_port = htons(FTP_PORT);
	ret = ftp_server->ftp_sock->ops->connect(ftp_server->ftp_sock, (struct sockaddr *) &ftp_server->ftp_saddr,
						 sizeof(ftp_server->ftp_saddr), O_RDWR);
	if (ret)
		goto err;

	/* get FTP reply */
	ret = -ENOSPC;
	if (ftp_getreply(ftp_server) != FTP_STATUS_OK)
		goto err;

	/* send USER command */
	if (ftp_cmd(ftp_server, "USER", ftp_server->ftp_user) != FTP_STATUS_OK_SO_FAR)
		goto err;

	/* send PASS command */
	if (ftp_cmd(ftp_server, "PASS", ftp_server->ftp_passwd) != FTP_STATUS_OK)
		goto err;

	/* set binary mode */
	if (ftp_cmd(ftp_server, "TYPE", "I") != FTP_STATUS_OK)
		goto err;

	return 0;
err:
	ftp_disconnect(ftp_server);
	return ret;
}

/*
 * Open a data socket.
 */
static struct socket *ftp_open_data_socket(struct ftp_server *ftp_server)
{
	struct socket *sock = NULL;
	struct sockaddr_in sa;
	int ret = -ENOSPC;
	int p[6], i;
	char *s;

	/* request passive mode */
	if (ftp_cmd(ftp_server, "PASV", NULL) != FTP_STATUS_OK)
		goto err;

	/* parse FTP server reply : skip first characters = status code */
	for (i = 0, s = ftp_server->ftp_buf; i < 4 && *s; i++, s++)
		;
	if (!*s)
		goto err;

	/* skip characters until digit */
	for (; *s && !isdigit(*s); s++)
		;

	/* parse FTP server reply */
	if (sscanf(s, "%d,%d,%d,%d,%d,%d", &p[0], &p[1], &p[2], &p[3], &p[4], &p[5]) != 6)
		goto err;

	/* set socket address */
	sa.sin_family = AF_INET;
	for (i = 0; i < 4; i++)
		((unsigned char *) &sa.sin_addr)[i] = p[i];
	sa.sin_port = htons((p[4] << 8) + p[5]);

	/* create a new socket */
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret)
		goto err;

	/* connect to socket */
	ret = sock->ops->connect(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_in), O_RDWR);
	if (ret)
		goto err;

	return sock;
err:
	if (sock)
		sock->ops->release(sock);
	return ERR_PTR(ret);
}

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
 * Create a FTP server.
 */
struct ftp_server *ftp_server_create(const char *ftp_sname, const char *ftp_user, const char *ftp_passwd)
{
	struct ftp_server *ftp_server;

	/* check parameters */
	if (!ftp_sname || !ftp_user || !ftp_passwd)
		return ERR_PTR(-EINVAL);

	/* allocate FTP server */
	ftp_server = kzalloc(sizeof(struct ftp_server), GFP_KERNEL);
	if (!ftp_server)
		return ERR_PTR(-ENOMEM);

	/* init server mutex */
	mutex_init(&ftp_server->ftp_mutex);

	/* set FTP server name, user and password */
	strncpy(ftp_server->ftp_sname, ftp_sname, FTP_SERVER_MAX_LEN - 1);
	strncpy(ftp_server->ftp_user, ftp_user, FTP_USER_MAX_LEN - 1);
	strncpy(ftp_server->ftp_passwd, ftp_passwd, FTP_PASSWD_MAX_LEN - 1);

	/* allocate FTP server buffer */
	ftp_server->ftp_buf = (void *) __get_free_page(GFP_KERNEL);
	if (!ftp_server->ftp_buf)
		goto err;

	return ftp_server;
err:
	ftp_server_free(ftp_server);
	return ERR_PTR(-ENOMEM);
}

/*
 * Free a FTP server.
 */
void ftp_server_free(struct ftp_server *ftp_server)
{
	if (!ftp_server)
		return;

	/* disconnect */
	ftp_disconnect(ftp_server);

	/* free news group buffer */
	if (ftp_server->ftp_buf)
		free_page((unsigned long) ftp_server->ftp_buf);

	kfree(ftp_server);
}

/*
 * Start a directory listing (= lock the server, open a data socket and send LIST command).
 */
struct socket *ftp_list_start(struct ftp_server *ftp_server, const char *dir)
{
	struct socket *sock_data;
	int ret;

	/* lock server */
	mutex_lock(&ftp_server->ftp_mutex);

	/* connect to server */
	ret = ftp_connect(ftp_server);
	if (ret)
		goto err_connect;

	/* open a data socket */
	sock_data = ftp_open_data_socket(ftp_server);
	if (IS_ERR(sock_data)) {
		ret = PTR_ERR(sock_data);
		goto err_sock_data;
	}

	/* send list command */
	if (ftp_cmd(ftp_server, "LIST", dir) != FTP_STATUS_OK_INIT) {
		ret = -ENOSPC;
		goto err_list;
	}

	return sock_data;
err_list:
	sock_data->ops->release(sock_data);
err_sock_data:
	ftp_disconnect(ftp_server);
err_connect:
	mutex_unlock(&ftp_server->ftp_mutex);
	return ERR_PTR(ret);
}

/*
 * End a directory listing (= close data socket, get server reply and unlock server).
 */
void ftp_list_end(struct ftp_server *ftp_server, struct socket *sock_data)
{
	/* close data socket */
	sock_data->ops->release(sock_data);

	/* get FTP reply and disconnect on error */
	if (ftp_getreply(ftp_server) != FTP_STATUS_OK)
		ftp_disconnect(ftp_server);

	/* unlock server */
	mutex_unlock(&ftp_server->ftp_mutex);
}

/*
 * End a directory listing with failure (= close data socket and disconnect from server).
 */
void ftp_list_failed(struct ftp_server *ftp_server, struct socket *sock_data)
{
	/* close data socket */
	sock_data->ops->release(sock_data);

	/* disconnect from server */
	ftp_disconnect(ftp_server);

	/* unlock server */
	mutex_unlock(&ftp_server->ftp_mutex);
}

/*
 * Get next directory entry (this function must be called between ftp_list_start and ftp_list_end).
 */
int ftp_list_next(struct ftp_server *ftp_server, struct socket *sock_data, struct ftp_fattr *fattr_res)
{
	int n;

	/* reset result */
	memset(fattr_res, 0, sizeof(struct ftp_fattr));

next_entry:
	/* get next line */
	n = ftp_getline(ftp_server, sock_data);
	if (n <= 0)
		return n;

	/* parse directory entry (on error, goto next entry) */
	if (ftp_parse_dir_entry(ftp_server->ftp_buf, n, fattr_res))
		goto next_entry;

	return n;
}

/*
 * Read data from a FTP server.
 */
int ftp_read(struct ftp_server *ftp_server, const char *file_path, char __user *buf, size_t count, loff_t *pos)
{
	struct socket *sock_data;
	struct msghdr msg;
	struct kvec iov;
	char nb_buf[64];
	loff_t off;
	int n, ret;

	/* lock server */
	mutex_lock(&ftp_server->ftp_mutex);

	/* connect to server */
	ret = ftp_connect(ftp_server);
	if (ret)
		goto err_connect;

	/* open a data socket */
	sock_data = ftp_open_data_socket(ftp_server);
	if (IS_ERR(sock_data)) {
		ret = PTR_ERR(sock_data);
		goto err_sock_data;
	}

	/* send restore command */
	if (*pos) {
		snprintf(nb_buf, 64, "%lld", *pos);
		if (ftp_cmd(ftp_server, "REST", nb_buf) != FTP_STATUS_OK_SO_FAR) {
			ret = -ENOSPC;
			goto err_rest_retr;
		}
	}

	/* send list command */
	if (ftp_cmd(ftp_server, "RETR", file_path) != FTP_STATUS_OK_INIT) {
		ret = -ENOSPC;
		goto err_rest_retr;
	}

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* get data and copy it to output buffer */
	for (off = 0; count > 0;) {
		/* set buffer */
		iov.iov_base = ftp_server->ftp_buf;
		iov.iov_len = count <= PAGE_SIZE ? count : PAGE_SIZE;

		/* get next buffer */
		n = ftp_recvmsg(sock_data, &msg, &iov);
		if (n <= 0)
			break;

		/* copy to output buffer */
		if (copy_to_user(buf + off, ftp_server->ftp_buf, n))
			break;

		/* update position */
		off += n;
		*pos += n;
		count -= n;
	}

	/* close data socket */
	sock_data->ops->release(sock_data);

	/* get FTP reply and disconnect on error */
	if (n < 0 || ftp_getreply(ftp_server) == FTP_STATUS_KO)
		ftp_disconnect(ftp_server);

	/* unlock server */
	mutex_unlock(&ftp_server->ftp_mutex);

	/* return number of bytes read */
	return off;
err_rest_retr:
	sock_data->ops->release(sock_data);
err_sock_data:
	ftp_disconnect(ftp_server);
err_connect:
	mutex_unlock(&ftp_server->ftp_mutex);
	return ret;
}
