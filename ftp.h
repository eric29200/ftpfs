#ifndef _FTP_H_
#define _FTP_H_

#include <net/sock.h>

#define FTP_PORT                21

#define FTP_STATUS_OK_INIT      1                                 /* init command ok */
#define FTP_STATUS_OK           2                                 /* command ok */
#define FTP_STATUS_OK_SO_FAR    3                                 /* command of so far, send the rest of it */
#define FTP_STATUS_KO_TMP       4                                 /* command was not accepted : retry later */
#define FTP_STATUS_KO           5                                 /* command incorrect */
#define FTP_STATUS_PROTECTED    6                                 /* command is protected */

#define FTP_SERVER_MAX_LEN      256
#define FTP_USER_MAX_LEN        256
#define FTP_PASSWD_MAX_LEN      256

#define FTP_MAX_NAMELEN         256

/*
 * FTP server.
 */
struct ftp_server {
  char                ftp_sname[FTP_SERVER_MAX_LEN];              /* FTP server name */
  char                ftp_user[FTP_USER_MAX_LEN];                 /* FTP user */
  char                ftp_passwd[FTP_PASSWD_MAX_LEN];             /* FTP password */
  struct socket       *ftp_sock;                                  /* connected socket */
  struct sockaddr_in  ftp_saddr;                                  /* FTP server address */
  char                *ftp_buf;                                   /* FTP server buffer (used to receive/send messages) */
  spinlock_t          ftp_lock;                                   /* FTP server lock */
};

/*
 * FTP buffer.
 */
struct ftp_buffer {
  char                *data;                                      /* buffer */
  size_t              len;                                        /* buffer length */
  size_t              capacity;                                   /* buffer capacity */
};


/*
 * FTP file attribute.
 */
struct ftp_fattr {
  umode_t             f_mode;                                     /* file mode */
  uint64_t            f_size;                                     /* file size */
  nlink_t             f_nlinks;                                   /* number of links to this file */
  time64_t            f_time;                                     /* file modification time */
  char                f_name[FTP_MAX_NAMELEN];                    /* file name */
  char                f_link[FTP_MAX_NAMELEN];                    /* target link */
};

struct ftp_server *ftp_server_create(const char *ftp_sname, const char *ftp_user, const char *ftp_passwd);
void ftp_server_free(struct ftp_server *ftp_server);
int ftp_connect(struct ftp_server *ftp_server);
int ftp_list(struct ftp_server *ftp_server, const char *dir, struct ftp_buffer *ftp_buf);
int ftp_parse_dir_entry(char *line, int len, struct ftp_fattr *fattr);
int ftp_read(struct ftp_server *ftp_server, const char *file_path, char __user *buf, size_t count, loff_t *pos);

#endif
