// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/dns_resolver.h>
#include <linux/sunrpc/addr.h>
#include <linux/inet.h>

#include "ftp.h"

/*
 * Resolve host name.
 */
static int ftp_resolve_host(struct ftp_server *ftp_server, struct sockaddr_in *saddr)
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
	sa_len = rpc_pton(&init_net, ip_addr, ip_len, (struct sockaddr *) saddr, sizeof(*saddr));
	if (sa_len < 0)
		ret = sa_len;

	kfree(ip_addr);
	return ret;
}

/*
 * Create a FTP session.
 */
static struct ftp_session *ftp_session_create(struct ftp_server *ftp_server, bool main)
{
	struct ftp_session *session = NULL;

	/* allocate a new session */
	session = kzalloc(sizeof(struct ftp_session), GFP_KERNEL);
	if (!session)
		goto err;

	/* allocate session buffer */
	session->buf = (void *) __get_free_page(GFP_KERNEL);
	if (!session->buf)
		goto err;

	/* init session */
	session->server = ftp_server;
	session->main = main;
	mutex_init(&session->mutex);

	return session;
err:
	kfree(session);
	return NULL;
}

/*
 * Free a FTP session.
 */
void ftp_session_free(struct ftp_session *session)
{
	if (!session)
		return;

	/* close session */
	ftp_session_close(session);

	/* free session buffer */
	free_page((unsigned long) session->buf);

	/* free session */
	kfree(session);
}

/*
 * Open a FTP session.
 */
int ftp_session_open(struct ftp_session *session)
{
	int ret;

	/* already connected */
	if (ftp_session_is_opened(session))
		return 0;

	/* create socket */
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &session->cmd_sock);
	if (ret)
		goto err;

	/* resolve host name */
	ret = ftp_resolve_host(session->server, &session->saddr);
	if (ret)
		goto err;

	/* connect to server */
	session->saddr.sin_family = AF_INET;
	session->saddr.sin_port = htons(FTP_PORT);
	ret = session->cmd_sock->ops->connect(session->cmd_sock, (struct sockaddr *) &session->saddr,
					      sizeof(session->saddr), O_RDWR);
	if (ret)
		goto err;

	/* get FTP reply */
	ret = -ENOSPC;
	if (ftp_getreply(session) != FTP_STATUS_OK)
		goto err;

	/* send USER command */
	if (ftp_cmd(session, "USER", session->server->ftp_user) != FTP_STATUS_OK_SO_FAR)
		goto err;

	/* send PASS command */
	if (ftp_cmd(session, "PASS", session->server->ftp_passwd) != FTP_STATUS_OK)
		goto err;

	/* set binary mode */
	if (ftp_cmd(session, "TYPE", "I") != FTP_STATUS_OK)
		goto err;

	session->data_pos = 0;
	return 0;
err:
	ftp_session_close(session);
	return ret;
}

/*
 * Close a session.
 */
void ftp_session_close(struct ftp_session *session)
{
	if (session->data_sock && session->data_sock->ops)
		session->data_sock->ops->release(session->data_sock);

	if (session->cmd_sock && session->cmd_sock->ops)
		session->cmd_sock->ops->release(session->cmd_sock);

	session->data_sock = NULL;
	session->cmd_sock = NULL;
	session->data_pos = 0;
}

/*
 * Create a FTP server.
 */
struct ftp_server *ftp_server_create(const char *ftp_sname, const char *ftp_user,
				     const char *ftp_passwd, unsigned long nb_connections)
{
	struct ftp_server *ftp_server;
	struct ftp_session *session;
	int ret, i;

	/* check parameters */
	if (!ftp_sname || !ftp_user || !ftp_passwd)
		return ERR_PTR(-EINVAL);

	/* allocate FTP server */
	ftp_server = kzalloc(sizeof(struct ftp_server), GFP_KERNEL);
	if (!ftp_server)
		return ERR_PTR(-ENOMEM);

	/* init server */
	strncpy(ftp_server->ftp_sname, ftp_sname, FTP_SERVER_MAX_LEN - 1);
	strncpy(ftp_server->ftp_user, ftp_user, FTP_USER_MAX_LEN - 1);
	strncpy(ftp_server->ftp_passwd, ftp_passwd, FTP_PASSWD_MAX_LEN - 1);
	mutex_init(&ftp_server->ftp_mutex);
	INIT_LIST_HEAD(&ftp_server->ftp_sessions);

	/* create main session */
	ftp_server->ftp_main_session = ftp_session_create(ftp_server, true);
	if (!ftp_server->ftp_main_session) {
		ret = -ENOMEM;
		goto err;
	}

	/* open main session */
	ret = ftp_session_open(ftp_server->ftp_main_session);
	if (ret)
		goto err;

	/* create user sessions */
	for (i = 0; i < nb_connections - 1; i++) {
		/* create session */
		session = ftp_session_create(ftp_server, false);
		if (!session) {
			ret = -ENOMEM;
			goto err;
		}

		/* add session */
		list_add_tail(&session->list, &ftp_server->ftp_sessions);
	}

	return ftp_server;
err:
	ftp_server_free(ftp_server);
	return ERR_PTR(ret);
}

/*
 * Get main FTP session and lock it.
 */
struct ftp_session *ftp_session_get_and_lock_main(struct ftp_server *ftp_server)
{
	mutex_lock(&ftp_server->ftp_main_session->mutex);
	return ftp_server->ftp_main_session;
}

/*
 * Try to get a user FTP session and lock it.
 */
struct ftp_session *ftp_session_get_and_lock_user(struct ftp_server *ftp_server)
{
	struct ftp_session *session;
	struct list_head *pos;

	mutex_lock(&ftp_server->ftp_mutex);

	list_for_each(pos, &ftp_server->ftp_sessions) {
		session = list_entry(pos, struct ftp_session, list);

		if (mutex_trylock(&session->mutex))
			goto found;
	}

	mutex_unlock(&ftp_server->ftp_mutex);
	return NULL;
found:
	mutex_unlock(&ftp_server->ftp_mutex);
	return session;
}

/*
 * Unlock a FTP session.
 */
void ftp_session_unlock(struct ftp_session *session)
{
	mutex_unlock(&session->mutex);
}

/*
 * Free a FTP server.
 */
void ftp_server_free(struct ftp_server *ftp_server)
{
	struct ftp_session *session;
	struct list_head *pos, *n;

	if (ftp_server && ftp_server->ftp_main_session)
		ftp_session_free(ftp_server->ftp_main_session);

	list_for_each_safe(pos, n, &ftp_server->ftp_sessions) {
		session = list_entry(pos, struct ftp_session, list);
		ftp_session_free(session);
	}

	kfree(ftp_server);
}

/*
 * Open a data socket.
 */
int ftp_open_data_socket(struct ftp_session *session)
{
	struct sockaddr_in sa;
	int ret = -ENOSPC;
	int p[6], i;
	char *s;

	/* request passive mode */
	if (ftp_cmd(session, "PASV", NULL) != FTP_STATUS_OK)
		goto err;

	/* parse FTP server reply : skip first characters = status code */
	for (i = 0, s = session->buf; i < 4 && *s; i++, s++)
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
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &session->data_sock);
	if (ret)
		goto err;

	/* connect to socket */
	ret = session->data_sock->ops->connect(session->data_sock, (struct sockaddr *) &sa,
					       sizeof(struct sockaddr_in), O_RDWR);
	if (ret)
		goto err;

	return 0;
err:
	ftp_session_close(session);
	return ret;
}
