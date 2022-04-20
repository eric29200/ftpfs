#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/dns_resolver.h>
#include <linux/sunrpc/addr.h>
#include <linux/inet.h>

#include "ftp.h"

/*
 * FTP months, printed in LIST command */
static const char *ftp_months[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/*
 * Get a line from a FTP server (returns number of character read).
 */
static int ftp_getline(struct ftp_server *ftp_server, struct socket *sock)
{
  struct msghdr msg;
  struct kvec iov;
  int err, n = 0;
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
    err = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
    if (err < 0)
      return err;
    
    /* end of message */
    if (!err)
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
  int n, i;
  
  for (i = 0;; i++) {
    /* get next line */
    n = ftp_getline(ftp_server, ftp_server->ftp_sock);
    if (n <= 0)
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
  return ftp_server->ftp_buf[0] - '0';
}

/*
 * Send a command to a FTP server (return FTP reply status code).
 */
static int ftp_cmd(struct ftp_server *ftp_server, const char *cmd, const char *arg)
{
  struct msghdr msg;
  struct kvec iov;
  int err, n;
  
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
  err = kernel_sendmsg(ftp_server->ftp_sock, &msg, &iov, 1, iov.iov_len);
  if (err != iov.iov_len)
    return FTP_STATUS_KO;
  
  /* return FTP reply */
  return ftp_getreply(ftp_server);
}

/*
 * Resolve host name.
 */
static int ftp_resolve_host(struct ftp_server *ftp_server)
{
  int ip_len, sa_len, err = 0;
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
    err = sa_len;
  
  kfree(ip_addr);
  return err;
}

/*
 * Open a data socket.
 */
static struct socket *ftp_open_data_socket(struct ftp_server *ftp_server)
{
  struct socket *sock = NULL;
  struct sockaddr_in sa;
  char buf[256];
  int err;

  /* get FTP socket control name */
  err = ftp_server->ftp_sock->ops->getname(ftp_server->ftp_sock, (struct sockaddr *) &sa, 0);
  if (err < 0)
    goto err;

  /* create a new socket */
  err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
  if (err)
    goto err;

  /* bind socket (on dynamic port) */
  sa.sin_port = 0;
  err = sock->ops->bind(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_in));
  if (err)
    goto err;

  /* listen on socket */
  err = sock->ops->listen(sock, 0);
  if (err)
    goto err;

  /* get dynamic allocated port */
  err = sock->ops->getname(sock, (struct sockaddr *) &sa, 0);
  if (err < 0)
    goto err;

  /* send EPRT command */
  snprintf(buf, sizeof(buf), "|1|%pI4|%d|", &sa.sin_addr.s_addr, ntohs(sa.sin_port));
  if (ftp_cmd(ftp_server, "EPRT", buf) != FTP_STATUS_OK) {
    err = -ENOSPC;
    goto err;
  }

  return sock;
err:
  if (sock)
    sock->ops->release(sock);
  return ERR_PTR(err);
}

/*
 * Receive data on a socket.
 */
static int ftp_receive_data(struct ftp_server *ftp_server, struct socket *sock_data, struct ftp_buffer *ftp_buf)
{
  struct socket *sock = NULL;
  struct msghdr msg;
  struct kvec iov;
  int ret, n;

  /* create a new socket */
  ret = sock_create_lite(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
  if (ret)
    goto out;

  /* set news socket operations */
  sock->ops = sock_data->ops;

  /* accept connection */
  ret = sock_data->ops->accept(sock_data, sock, 0, 1);
  if (ret)
    goto out;

  /* prepare message */
  memset(&msg, 0, sizeof(struct msghdr));
  iov.iov_base = ftp_server->ftp_buf;
  iov.iov_len = PAGE_SIZE;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;

  /* get data */
  for (;;) {
    /* get next buffer */
    n = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
    if (n < 0) {
      ret = n;
      goto out;
    }

    /* end of data */
    if (!n)
      break;

    /* grow buffer if needed */
    if (ftp_buf->len + n > ftp_buf->capacity) {
      ftp_buf->data = (char *) krealloc(ftp_buf->data, ftp_buf->capacity + PAGE_SIZE, GFP_KERNEL);
      if (!ftp_buf->data) {
        ret = -ENOMEM;
        goto out;
      }

      ftp_buf->capacity += PAGE_SIZE;
    }

    /* copy to ftp buffer */
    memcpy(ftp_buf->data + ftp_buf->len, ftp_server->ftp_buf, n);
    ftp_buf->len += n;
  }

out:
  /* close socket */
  if (sock)
    sock->ops->release(sock);

  return ret;
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
  ftp_server = (struct ftp_server *) kzalloc(sizeof(struct ftp_server), GFP_KERNEL);
  if (!ftp_server)
    return ERR_PTR(-ENOMEM);

  /* init server lock */
  spin_lock_init(&ftp_server->ftp_lock);

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

  /* release socket */
  if (ftp_server->ftp_sock && ftp_server->ftp_sock->ops)
    ftp_server->ftp_sock->ops->release(ftp_server->ftp_sock);

  /* free news group buffer */
  if (ftp_server->ftp_buf)
    free_page((unsigned long) ftp_server->ftp_buf);

  kfree(ftp_server);
}

/*
 * Connect to a FTP server.
 */
int ftp_connect(struct ftp_server *ftp_server)
{
  int err;
  
  /* lock server */
  spin_lock(&ftp_server->ftp_lock);

  /* reset server socket */
  if (ftp_server->ftp_sock && ftp_server->ftp_sock->ops) {
    ftp_server->ftp_sock->ops->release(ftp_server->ftp_sock);
    ftp_server->ftp_sock = NULL;
  }
  
  /* create socket */
  err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &ftp_server->ftp_sock);
  if (err)
    goto err;
  
  /* resolve host name */
  err = ftp_resolve_host(ftp_server);
  if (err)
    goto err;
  
  /* connect to server */
  ftp_server->ftp_saddr.sin_family = AF_INET;
  ftp_server->ftp_saddr.sin_port = htons(FTP_PORT);
  err = ftp_server->ftp_sock->ops->connect(ftp_server->ftp_sock, (struct sockaddr *) &ftp_server->ftp_saddr,
                                           sizeof(ftp_server->ftp_saddr), O_RDWR);
  if (err)
    goto err;
  
  /* get FTP reply */
  err = -ENOSPC;
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
  
  /* release server */
  spin_unlock(&ftp_server->ftp_lock);
  return 0;
err:
  if (ftp_server->ftp_sock && ftp_server->ftp_sock->ops)
    ftp_server->ftp_sock->ops->release(ftp_server->ftp_sock);
  
  /* release server */
  spin_unlock(&ftp_server->ftp_lock);
  return err;
}

/*
 * Parse a FTP directory line into file attributes.
 */
int ftp_parse_dir_entry(char *line, int len, struct ftp_fattr *fattr)
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
  if (line[len - 1] == '\n')
    line[len - 1] = 0;
  
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
  if (!tok || sscanf(tok, "%u", &fattr->f_nlinks) != 1)
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
  if (!tok || sscanf(tok, "%llu", &fattr->f_size) != 1)
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
  if (!tok || sscanf(tok, "%u", &day) != 1)
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
  } else if (sscanf(tok, "%u", &year) == 1) {
    hour = 0;
    min = 0;
  }
  else
    goto err;
  
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
 * List a directory of a FTP server.
 */
int ftp_list(struct ftp_server *ftp_server, const char *dir, struct ftp_buffer *ftp_buf)
{
  struct socket *sock_data;
  int ret = 0;
  
  /* lock server */
  spin_lock(&ftp_server->ftp_lock);

  /* open a data socket */
  sock_data = ftp_open_data_socket(ftp_server);
  if (IS_ERR(sock_data)) {
    ret = PTR_ERR(sock_data);
    sock_data = NULL;
    goto out;
  }
  
  /* send list command */
  if (ftp_cmd(ftp_server, "LIST", dir) != FTP_STATUS_OK_INIT) {
    ret = -ENOSPC;
    goto out;
  }
  
  /* receive data */
  ret = ftp_receive_data(ftp_server, sock_data, ftp_buf);
  if (ret)
    goto out;
  
  /* get FTP reply */
  if (ftp_getreply(ftp_server) != FTP_STATUS_OK) {
    ret = -ENOSPC;
    goto out;
  }
  
out:
  /* close data socket */
  if (sock_data && sock_data->ops)
    sock_data->ops->release(sock_data);
  
  /* release server */
  spin_unlock(&ftp_server->ftp_lock);
  return ret;
}
