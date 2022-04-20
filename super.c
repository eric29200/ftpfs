#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vfs.h>

#include "ftpfs.h"

/* FTPFS inode cache */
static struct kmem_cache *ftpfs_inode_cache;

/*
 * Get FTPFS file system status.
 */
static int ftpfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
  struct super_block *sb = dentry->d_sb;
  
  memset(buf, 0, sizeof(struct kstatfs));
  buf->f_type = sb->s_magic;
  buf->f_bsize = sb->s_blocksize;
  buf->f_blocks = 1;
  
  return 0;
}

/*
 * Kill a FTPFS super block.
 */
static void ftpfs_put_super(struct super_block *sb)
{
  struct ftpfs_sb_info *sbi = ftpfs_sb(sb);
  
  /* free FTP server */
  ftp_server_free(sbi->s_ftp_server);
  
  /* free FTPFS super block */
  kfree(sbi);
}


/*
 * Allocate a new FTPFS inode.
 */
static struct inode *ftpfs_alloc_inode(struct super_block *sb)
{
  struct ftpfs_inode_info *ftpfs_inode;
  
  /* allocate a new inode */
  ftpfs_inode = kmem_cache_alloc(ftpfs_inode_cache, GFP_KERNEL);
  if (!ftpfs_inode)
    return NULL;
  
  /* reset path and cached data */
  ftpfs_inode->i_path = NULL;
  memset(&ftpfs_inode->i_cache, 0, sizeof(struct ftp_buffer));
  
  return &ftpfs_inode->vfs_inode;
}

/*
 * Free a FTPFS inode.
 */
static void ftpfs_free_inode(struct inode *inode)
{
  printk(KERN_ALERT "FREE INODE\n");
  
  /* free cached data */
  if (ftpfs_i(inode)->i_cache.data)
    kfree(ftpfs_i(inode)->i_cache.data);
  
  /* free inode full path */
  if (ftpfs_i(inode)->i_path)
    kfree(ftpfs_i(inode)->i_path);
  
  /* free inode */
  kmem_cache_free(ftpfs_inode_cache, ftpfs_i(inode));
}

/*
 * Init a new inode from cache.
 */
static void init_once(void *foo)
{
  struct ftpfs_inode_info *ftpfs_inode = (struct ftpfs_inode_info *) foo;
  inode_init_once(&ftpfs_inode->vfs_inode);
}

/*
 * Create FTPFS inode cache.
 */
static int __init init_inodecache(void)
{
  ftpfs_inode_cache = kmem_cache_create("ftpfs_inode_cache", sizeof(struct ftpfs_inode_info), 0,
                                        SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_ACCOUNT,
                                        init_once);
  if (!ftpfs_inode_cache)
    return -ENOMEM;
  
  return 0;
}

/*
 * Destroy FTPFS inode cache.
 */
static void destroy_inodecache(void)
{
  rcu_barrier();
  kmem_cache_destroy(ftpfs_inode_cache);
}

/*
 * FTPFS super operations.
 */
static struct super_operations ftpfs_sops = {
  .alloc_inode          = ftpfs_alloc_inode,
  .free_inode           = ftpfs_free_inode,
  .put_super            = ftpfs_put_super,
  .statfs               = ftpfs_statfs,
};

/*
 * Fill in a FTPFS super block.
 */
static int ftpfs_fill_super(struct super_block *sb, void *data, int silent)
{
  struct ftp_fattr root_fattr;
  struct ftpfs_sb_info *sbi;
  struct inode *root_inode;
  int err;
  
  /* allocate FTPFS super block */
  sb->s_fs_info = sbi = (struct ftpfs_sb_info *) kmalloc(sizeof(struct ftpfs_sb_info), GFP_KERNEL);
  if (!sbi)
    return -ENOMEM;
  
  /* create FTP server */
  sbi->s_ftp_server = ftp_server_create(FTPFS_FTP_SERVER, FTPFS_FTP_USER, FTPFS_FTP_PASSWD);
  if (IS_ERR(sbi->s_ftp_server)) {
    err = PTR_ERR(sbi->s_ftp_server);
    goto err_ftp_server_create;
  }
  
  /* connect to FTP server */
  err = ftp_connect(sbi->s_ftp_server);
  if (err)
    goto err_ftp_connect;
  
  /* set super operations */
  sb->s_op = &ftpfs_sops;
  
  /* create root inode */
  memset(&root_fattr, 0, sizeof(struct ftp_fattr));
  root_fattr.f_mode = S_IFDIR | 0755;
  root_inode = ftpfs_iget(sb, NULL, &root_fattr);
  if (IS_ERR(root_inode)) {
    err = PTR_ERR(root_inode);
    goto err_no_root;
  }
  
  /* make root inode */
  sb->s_root = d_make_root(root_inode);
  if (!sb->s_root) {
    err = -ENOMEM;
    goto err_no_root;
  }
  
  return 0;
err_no_root:
  printk("FTPFS : can't get root inode\n");
  goto err_free_ftp_server;
err_ftp_connect:
  printk("FTPFS : can't connect to FTP server\n");
err_free_ftp_server:
  ftp_server_free(sbi->s_ftp_server);
  goto err;
err_ftp_server_create:
  printk("FTPFS : can't create FTP server\n");
err:
  kfree(sbi);
  sb->s_fs_info = NULL;
  return err;
}

/*
 * Mount a FTPFS file system.
 */
static struct dentry *ftpfs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
  return mount_nodev(fs_type, flags, data, ftpfs_fill_super);
}

/*
 * FTPFS file system type.
 */
static struct file_system_type ftpfs_type = {
  .owner          = THIS_MODULE,
  .name           = "ftpfs",
  .mount          = ftpfs_mount,
  .kill_sb        = kill_anon_super,
};

/*
 * Init FTPFS module.
 */
static int __init ftpfs_init(void)
{
  int err;
  
  /* init inode cache */
  err = init_inodecache();
  if (err)
    return err;
  
  /* register FTPFS */
  err = register_filesystem(&ftpfs_type);
  if (err) {
    destroy_inodecache();
    return err;
  }
  
  return 0;

}

/*
 * Exit FTPFS module.
 */
static void __exit ftpfs_exit(void)
{
  unregister_filesystem(&ftpfs_type);
  destroy_inodecache();
}

module_init(ftpfs_init);
module_exit(ftpfs_exit);
MODULE_LICENSE("GPL");
