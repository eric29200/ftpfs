// SPDX-License-Identifier: GPL-2.0-only
#include "ftp.h"

/*
 * Send a message on a socket (on ERESTARTSYS failure, wait 100 ms and retry).
 */
int ftp_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov)
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
int ftp_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov)
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
int ftp_getline(struct ftp_session *session, struct socket *sock)
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
			session->buf[n++] = c;

		/* end of line */
		if (c == '\n')
			break;
	}

	/* end buf with 0 */
	if (n >= PAGE_SIZE)
		n--;
	session->buf[n] = 0;

	return n;
}

/*
 * Get a reply from a FTP server (return FTP status code).
 */
int ftp_getreply(struct ftp_session *session)
{
	int n, i, ret;

	for (i = 0;; i++) {
		/* get next line */
		n = ftp_getline(session, session->cmd_sock);
		if (n < 0)
			return n;
		if (n == 0)
			return FTP_STATUS_KO;

		/* break on FTP status message */
		if (n < 4)
			continue;
		if (i == 0 && session->buf[3] != '-')
			break;
		if (i != 0 && isdigit(session->buf[0]) && isdigit(session->buf[1])
		    && isdigit(session->buf[2]) && session->buf[3] == ' ')
			break;
	}

	/* return FTP status code */
	ret = session->buf[0] - '0';
	if (ret == FTP_STATUS_KO)
		pr_err("FTPFS : %s", session->buf);

	return ret;
}

/*
 * Send a command to a FTP server (return FTP reply status code).
 */
int ftp_cmd(struct ftp_session *session, const char *cmd, const char *arg)
{
	struct msghdr msg;
	struct kvec iov;
	int ret, n;

	/* build command */
	if (arg)
		n = snprintf(session->buf, PAGE_SIZE, "%s %s\r\n", cmd, arg);
	else
		n = snprintf(session->buf, PAGE_SIZE, "%s\r\n", cmd);

	/* check command buffer */
	if (n <= 0)
		return FTP_STATUS_KO;

	/* prepare message */
	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base = session->buf;
	iov.iov_len = n;
	msg.msg_name = &session->saddr;
	msg.msg_namelen = sizeof(session->saddr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	/* send message */
	ret = ftp_sendmsg(session->cmd_sock, &msg, &iov);
	if (ret < 0)
		return ret;
	if (ret != iov.iov_len)
		return FTP_STATUS_KO;

	/* return FTP reply */
	return ftp_getreply(session);
}

