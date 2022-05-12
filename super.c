// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vfs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>

#include "ftpfs.h"

/* root file attributes */
struct ftp_fattr root_fattr;

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

	/* relinquish netfs volume */
	fscache_relinquish_volume(sbi->s_fscache, NULL, false);

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

	return &ftpfs_inode->vfs_inode;
}

/*
 * Remove an inode from the cache.
 */
static void ftpfs_evict_inode(struct inode *inode)
{
	int version = 0;

	/* truncate inode pages */
	truncate_inode_pages_final(&inode->i_data);

	/* clear inode */
	fscache_clear_inode_writeback(ftpfs_i(inode)->i_fscache, inode, &version);
	clear_inode(inode);
	filemap_fdatawrite(&inode->i_data);

	/* relinquish netfs cookie */
	fscache_relinquish_cookie(ftpfs_i(inode)->i_fscache, false);

	/* clear inode */
	kfree(ftpfs_i(inode)->i_path);
	ftpfs_i(inode)->i_fscache = NULL;
}

/*
 * Free a FTPFS inode.
 */
static void ftpfs_free_inode(struct inode *inode)
{
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
	.alloc_inode		= ftpfs_alloc_inode,
	.free_inode		= ftpfs_free_inode,
	.evict_inode		= ftpfs_evict_inode,
	.put_super		= ftpfs_put_super,
	.statfs			= ftpfs_statfs,
};

/*
 * Fill in a FTPFS super block.
 */
static int ftpfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct ftpfs_fs_context *ctx = ftpfs_ctx(fc);
	struct ftpfs_sb_info *sbi;
	struct inode *root_inode;
	int ret;

	/* allocate FTPFS super block */
	sb->s_fs_info = sbi = kmalloc(sizeof(struct ftpfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	/* create netfs cache volume */
	ret = ftpfs_cache_super_get_volume(sb, fc->source);
	if (ret)
		goto err_cache;

	/* create FTP server */
	sbi->s_ftp_server = ftp_server_create(fc->source, ctx->fs_opt.user, ctx->fs_opt.passwd,
					      ctx->fs_opt.nb_connections);
	if (IS_ERR(sbi->s_ftp_server)) {
		ret = PTR_ERR(sbi->s_ftp_server);
		goto err_ftp_server_create;
	}

	/* set super block */
	sb->s_op = &ftpfs_sops;
	sb->s_d_op = &ftpfs_dops;
	sbi->s_opt = ftpfs_ctx(fc)->fs_opt;

	/* create root inode */
	memset(&root_fattr, 0, sizeof(struct ftp_fattr));
	root_fattr.f_mode = S_IFDIR | 0755;
	root_inode = ftpfs_iget(sb, NULL, &root_fattr);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto err_no_root;
	}

	/* make root inode */
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_no_root;
	}

	return 0;
err_no_root:
	pr_err("FTPFS : can't get root inode\n");
	ftp_server_free(sbi->s_ftp_server);
	goto err_release_cache;
err_ftp_server_create:
	pr_err("FTPFS : can't create FTP server \"%s\"\n", fc->source);
err_release_cache:
	fscache_relinquish_volume(sbi->s_fscache, NULL, false);
	goto err;
err_cache:
	pr_err("FTPFS : can't create netfs cache\n");
err:
	kfree(sbi);
	sb->s_fs_info = NULL;
	return ret;
}

/*
 * FTPFS mount options.
 */
enum {
	Opt_user,
	Opt_passwd,
	Opt_cache_timeout_sec,
	Opt_nb_connections,
};

/*
 * FTPFS parameters.
 */
static struct fs_parameter_spec ftpfs_fs_parameters[] = {
	fsparam_string("username",		Opt_user),
	fsparam_string("password",		Opt_passwd),
	fsparam_u32("cache_timeout_sec",	Opt_cache_timeout_sec),
	fsparam_u32("nb_connections",		Opt_nb_connections),
	{},
};

/*
 * Parse FTPFS parameters.
 */
static int ftpfs_fc_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct ftpfs_fs_context *ctx = ftpfs_ctx(fc);
	struct fs_parse_result res;
	int opt;

	opt = fs_parse(fc, ftpfs_fs_parameters, param, &res);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_user:
		if (!param->string)
			return -EINVAL;

		ctx->fs_opt.user = param->string;
		param->string = NULL;
		break;
	case Opt_passwd:
		if (!param->string)
			return -EINVAL;

		ctx->fs_opt.passwd = param->string;
		param->string = NULL;
		break;
	case Opt_cache_timeout_sec:
		ctx->fs_opt.cache_timeout_sec = res.uint_32;
		break;
	case Opt_nb_connections:
		ctx->fs_opt.nb_connections = res.uint_32;
		break;
	default:
		return -ENOPARAM;
	}

	return 0;
}

/*
 * Get FTPFS tree = mount file system.
 */
static int ftpfs_fc_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, ftpfs_fill_super);
}

/*
 * Free FTPFS context.
 */
static void ftpfs_fc_free(struct fs_context *fc)
{
	struct ftpfs_fs_context *ctx = fc->fs_private;

	kfree(ctx);
}

/*
 * FTPFS context operations.
 */
static struct fs_context_operations ftpfs_context_ops = {
	.parse_param		= ftpfs_fc_parse_param,
	.get_tree		= ftpfs_fc_get_tree,
	.free			= ftpfs_fc_free,
};

/*
 * Init a FTPFS file system context.
 */
int ftpfs_init_fs_context(struct fs_context *fc)
{
	struct ftpfs_fs_context *ctx;

	/* allocate FTPFS context */
	ctx = kzalloc(sizeof(struct ftpfs_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	/* set default options */
	ctx->fs_opt.user = FTPFS_FTP_USER_DEFAULT;
	ctx->fs_opt.passwd = FTPFS_FTP_PASSWD_DEFAULT;
	ctx->fs_opt.cache_timeout_sec = FTPFS_CACHE_TIMEOUT_SEC;
	ctx->fs_opt.nb_connections = FTPFS_NB_CONNECTIONS;

	/* set context */
	fc->fs_private = ctx;
	fc->ops = &ftpfs_context_ops;

	return 0;
}

/*
 * FTPFS file system type.
 */
static struct file_system_type ftpfs_type = {
	.owner			= THIS_MODULE,
	.name			= "ftpfs",
	.init_fs_context	= ftpfs_init_fs_context,
	.kill_sb		= kill_anon_super,
};

/*
 * Init FTPFS module.
 */
static int __init ftpfs_init(void)
{
	int ret;

	/* init inode cache */
	ret = init_inodecache();
	if (ret)
		return ret;

	/* register FTPFS */
	ret = register_filesystem(&ftpfs_type);
	if (ret) {
		destroy_inodecache();
		return ret;
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
