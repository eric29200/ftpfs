#include "ftpfs.h"

/*
 * Get directory entries.
 */
static int ftpfs_readdir(struct file *file, struct dir_context *ctx)
{
  char *start, *end, *line = NULL;
  struct ftp_fattr fattr;
  size_t off, rem;
  loff_t i = 2;
  int err;
  
  /* load inode data into cache = directory listing */
  err = ftpfs_load_inode_data(file->f_inode, NULL);
  if (err)
    return err;
  
  /* emit "." and ".." */
  if (!dir_emit_dots(file, ctx))
    return 0;
  
  /* parse all directory entries */
  for (off = 0; off < ftpfs_i(file->f_inode)->i_cache.len;) {
    /* compute start line and remaining characters in cache */
    start = ftpfs_i(file->f_inode)->i_cache.data + off;
    rem = ftpfs_i(file->f_inode)->i_cache.len - off;
    
    /* find end of line or end of buf */
    end = strnchr(start, rem, '\n');
    if (!end)
      end = start + rem;
    
    /* handle carriage return */
    if (end > start && *(end - 1) == '\r')
      end--;
  
    /* allocate line */
    line = (char *) kmalloc(end - start + 1, GFP_KERNEL);
    if (!line)
      return -ENOMEM;
    
    /* copy line */
    strncpy(line, start, end - start);
    line[end - start] = 0;
    
    /* parse line */
    err = ftp_parse_dir_entry(line, end - start, &fattr);
    if (err)
      goto next_line;
    
    /* skip first entries */
    if (i++ < ctx->pos)
      goto next_line;
    
    /* emit file */
    if (!dir_emit(ctx, fattr.f_name, strnlen(fattr.f_name, FTP_MAX_NAMELEN), 1, DT_UNKNOWN))
      break;
    
    /* update position */
    ctx->pos++;
    
next_line:
    /* free line */
    if (line) {
      kfree(line);
      line = NULL;
    }
    
    /* go to next line */
    off = end - ftpfs_i(file->f_inode)->i_cache.data + (*end == '\r' ? 2 : 1);
  }
  
  /* free last line */
  if (line)
    kfree(line);
  
  return 0;
}

/*
 * FTPFS directory file operations.
 */
struct file_operations ftpfs_dir_fops = {
  .iterate_shared       = ftpfs_readdir,
};
