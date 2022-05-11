/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FTP_H_
#define _FTP_H_

#include <net/sock.h>

#define FTP_PORT				21

#define FTP_STATUS_OK_INIT			1			/* init command ok */
#define FTP_STATUS_OK				2			/* command ok */
#define FTP_STATUS_OK_SO_FAR			3			/* command of so far, send the rest of it */
#define FTP_STATUS_KO_TMP			4			/* command was not accepted : retry later */
#define FTP_STATUS_KO				5			/* command incorrect */
#define FTP_STATUS_PROTECTED			6			/* command is protected */

#define FTP_SERVER_MAX_LEN			256
#define FTP_USER_MAX_LEN			256
#define FTP_PASSWD_MAX_LEN			256

#define FTP_MAX_NAMELEN				256

/*
 * FTP session.
 */
struct ftp_session {
	struct ftp_server	*server;				/* FTP server */
	struct sockaddr_in	saddr;					/* FTP server address */
	bool			main;					/* is this the main session ? */
	struct socket		*cmd_sock;				/* command socket */
	struct socket		*data_sock;				/* data socket */
	int			data_direction;				/* data direction (READ or WRITE) */
	loff_t			data_pos;				/* data position */
	char			*buf;					/* session buffer (used to receive/send messages) */
	struct mutex		mutex;					/* session mutex */
	struct list_head	list;					/* next session */
};

/*
 * FTP server.
 */
struct ftp_server {
	char			ftp_sname[FTP_SERVER_MAX_LEN];		/* FTP server name */
	char			ftp_user[FTP_USER_MAX_LEN];		/* FTP user */
	char			ftp_passwd[FTP_PASSWD_MAX_LEN];		/* FTP password */
	struct ftp_session	*ftp_main_session;			/* FTP main session */
	struct list_head	ftp_sessions;				/* FTP user sessions */
	struct mutex		ftp_mutex;				/* FTP server mutex */
};

/*
 * FTP buffer.
 */
struct ftp_buffer {
	char			*data;					/* buffer */
	size_t			len;					/* buffer length */
	size_t			capacity;				/* buffer capacity */
};


/*
 * FTP file attribute.
 */
struct ftp_fattr {
	umode_t			f_mode;					/* file mode */
	uint64_t		f_size;					/* file size */
	nlink_t			f_nlinks;				/* number of links to this file */
	time64_t		f_time;					/* file modification time */
	char			f_name[FTP_MAX_NAMELEN];		/* file name */
	char			f_link[FTP_MAX_NAMELEN];		/* target link */
};

/* FTP utils prototypes (defined in ftp_utils.c) */
int ftp_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov);
int ftp_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *iov);
int ftp_getline(struct ftp_session *session, struct socket *sock);
int ftp_getreply(struct ftp_session *session);
int ftp_cmd(struct ftp_session *session, const char *cmd, const char *arg);

/* FTP session prototypes (defined in ftp_session.c) */
struct ftp_server *ftp_server_create(const char *ftp_sname, const char *ftp_user,
				     const char *ftp_passwd, unsigned long nb_connections);
void ftp_server_free(struct ftp_server *ftp_server);
int ftp_session_open(struct ftp_session *session);
void ftp_session_close(struct ftp_session *session);
void ftp_session_free(struct ftp_session *session);
int ftp_open_data_socket(struct ftp_session *session, int direction);
struct ftp_session *ftp_session_get_and_lock_main(struct ftp_server *ftp_server);
struct ftp_session *ftp_session_get_and_lock_user(struct ftp_server *ftp_server);
void ftp_session_unlock(struct ftp_session *session);

/* FTP command prototypes (defined in ftp_cmd.c) */
int ftp_list_start(struct ftp_session *session, const char *dir, loff_t pos);
void ftp_list_end(struct ftp_session *session, int err);
int ftp_list_next(struct ftp_session *session, struct ftp_fattr *fattr_res);
ssize_t ftp_read(struct ftp_session *session, const char *file_path, loff_t pos, struct iov_iter *iter, size_t iter_len);
ssize_t ftp_write(struct ftp_session *session, const char *file_path, loff_t pos, struct iov_iter *iter, size_t iter_len);
int ftp_create(struct ftp_session *session, const char *file_path);
int ftp_delete(struct ftp_session *session, const char *file_path);
int ftp_mkdir(struct ftp_session *session, const char *file_path);

/*
 * Check if a session is opened.
 */
static inline bool ftp_session_is_opened(struct ftp_session *session)
{
	return session && session->cmd_sock && session->cmd_sock->ops;
}

/*
 * Check if a session is opened for data transfert.
 */
static inline bool ftp_session_is_opened_for_data(struct ftp_session *session)
{
	return ftp_session_is_opened(session) && session->data_sock && session->data_sock->ops;
}

/*
 * Check if a session is opened for data READ transfert.
 */
static inline bool ftp_session_is_opened_for_data_read(struct ftp_session *session)
{
	return ftp_session_is_opened_for_data(session) && session->data_direction == READ;
}

/*
 * Check if a session is opened for data WRITE transfert.
 */
static inline bool ftp_session_is_opened_for_data_write(struct ftp_session *session)
{
	return ftp_session_is_opened_for_data(session) && session->data_direction == WRITE;
}

#endif
