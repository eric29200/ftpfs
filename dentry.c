#include "ftpfs.h"

/*
 * FTPFS dentry operations : do not cache dentries, always check FTP server.
 */
const struct dentry_operations ftpfs_dops = {
	.d_delete		= always_delete_dentry,
};
