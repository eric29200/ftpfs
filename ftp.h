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
	struct ftp_server	*server;				/* ftp server */
	struct socket		*cmd_sock;				/* command socket */
	struct socket		*data_sock;				/* data socket */
	struct sockaddr_in	saddr;					/* FTP server address */
	char			*buf;					/* session buffer (used to receive/send messages) */
	struct mutex		mutex;					/* session mutex */
};

/*
 * FTP server.
 */
struct ftp_server {
	char			ftp_sname[FTP_SERVER_MAX_LEN];		/* FTP server name */
	char			ftp_user[FTP_USER_MAX_LEN];		/* FTP user */
	char			ftp_passwd[FTP_PASSWD_MAX_LEN];		/* FTP password */
	struct ftp_session	*ftp_main_session;			/* FTP main session */
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
struct ftp_server *ftp_server_create(const char *ftp_sname, const char *ftp_user, const char *ftp_passwd);
void ftp_server_free(struct ftp_server *ftp_server);
int ftp_session_open(struct ftp_session *session);
void ftp_session_close(struct ftp_session *session);
void ftp_session_free(struct ftp_session *session);
int ftp_open_data_socket(struct ftp_session *session);
struct ftp_session *ftp_session_get_and_lock(struct ftp_server *ftp_server, int main_session);
void ftp_session_unlock(struct ftp_session *session);

/* FTP command prototypes (defined in ftp_cmd.c) */
int ftp_list_start(struct ftp_session *session, const char *dir);
void ftp_list_end(struct ftp_session *session);
void ftp_list_failed(struct ftp_session *session);
int ftp_list_next(struct ftp_session *session, struct ftp_fattr *fattr_res);
int ftp_read(struct ftp_session *session, const char *file_path, char __user *buf, size_t count, loff_t *pos);

#endif
