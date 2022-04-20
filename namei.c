#include "ftpfs.h"

/*
 * Test file names equality.
 */
static inline bool ftpfs_name_match(struct ftp_fattr *fattr, struct dentry *dentry)
{
  if (strnlen(fattr->f_name, FTP_MAX_NAMELEN) != dentry->d_name.len)
    return false;
  
  return strncmp(fattr->f_name, dentry->d_name.name, dentry->d_name.len) == 0;
}

/*
 * Find an entry in a directory.
 */
static int ftpfs_find_entry(struct inode *dir, struct dentry *dentry, struct ftp_fattr *fattr_res)
{
  char *start, *end, *line = NULL;
  struct ftp_fattr fattr;
  size_t off, rem;
  int err;
  
  /* load inode data into cache = directory listing */
  err = ftpfs_load_inode_data(dir, NULL);
  if (err)
    return err;
  
  /* parse all directory entries */
  for (off = 0; off < ftpfs_i(dir)->i_cache.len;) {
    /* compute start line and remaining characters in cache */
    start = ftpfs_i(dir)->i_cache.data + off;
    rem = ftpfs_i(dir)->i_cache.len - off;
    
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
    
    /* check file name */
    if (ftpfs_name_match(&fattr, dentry)) {
      memcpy(fattr_res, &fattr, sizeof(struct ftp_fattr));
      break;
    }
    
next_line:
    /* free line */
    if (line) {
      kfree(line);
      line = NULL;
    }
    
    /* go to next line */
    off = end - ftpfs_i(dir)->i_cache.data + (*end == '\r' ? 2 : 1);
  }
  
  /* free last line */
  if (line)
    kfree(line);
  
  return 0;
}

/*
 * Lookup for a file in a directory.
 */
static struct dentry *ftpfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
  struct inode *inode = NULL;
  struct ftp_fattr fattr;
  
  /* find entry in dir */
  if (ftpfs_find_entry(dir, dentry, &fattr) == 0)
    inode = ftpfs_iget(dir->i_sb, dir, &fattr);
  
  return d_splice_alias(inode, dentry);
}

/*
 * FTPFS directory inode operations.
 */
struct inode_operations ftpfs_dir_iops = {
  .lookup         = ftpfs_lookup,
};