
















































struct filename * getname_flags(const char __user *filename, int flags, int *empty)
{
	struct filename *result;
	char *kname;
	int len;

	result = audit_reusename(filename);
	if (result)
		return result;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	
	kname = (char *)result->iname;
	result->name = kname;

	len = strncpy_from_user(kname, filename, EMBEDDED_NAME_MAX);
	if (unlikely(len < 0)) {
		__putname(result);
		return ERR_PTR(len);
	}

	
	if (unlikely(len == EMBEDDED_NAME_MAX)) {
		const size_t size = offsetof(struct filename, iname[1]);
		kname = (char *)result;

		
		result = kzalloc(size, GFP_KERNEL);
		if (unlikely(!result)) {
			__putname(kname);
			return ERR_PTR(-ENOMEM);
		}
		result->name = kname;
		len = strncpy_from_user(kname, filename, PATH_MAX);
		if (unlikely(len < 0)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(len);
		}
		if (unlikely(len == PATH_MAX)) {
			__putname(kname);
			kfree(result);
			return ERR_PTR(-ENAMETOOLONG);
		}
	}

	result->refcnt = 1;
	
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		if (!(flags & LOOKUP_EMPTY)) {
			putname(result);
			return ERR_PTR(-ENOENT);
		}
	}

	result->uptr = filename;
	result->aname = NULL;
	audit_getname(result);
	return result;
}

struct filename * getname(const char __user * filename)
{
	return getname_flags(filename, 0, NULL);
}

struct filename * getname_kernel(const char * filename)
{
	struct filename *result;
	int len = strlen(filename) + 1;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	if (len <= EMBEDDED_NAME_MAX) {
		result->name = (char *)result->iname;
	} else if (len <= PATH_MAX) {
		const size_t size = offsetof(struct filename, iname[1]);
		struct filename *tmp;

		tmp = kmalloc(size, GFP_KERNEL);
		if (unlikely(!tmp)) {
			__putname(result);
			return ERR_PTR(-ENOMEM);
		}
		tmp->name = (char *)result;
		result = tmp;
	} else {
		__putname(result);
		return ERR_PTR(-ENAMETOOLONG);
	}
	memcpy((char *)result->name, filename, len);
	result->uptr = NULL;
	result->aname = NULL;
	result->refcnt = 1;
	audit_getname(result);

	return result;
}

void putname(struct filename *name)
{
	BUG_ON(name->refcnt <= 0);

	if (--name->refcnt > 0)
		return;

	if (name->name != name->iname) {
		__putname(name->name);
		kfree(name);
	} else __putname(name);
}

static int check_acl(struct inode *inode, int mask)
{

	struct posix_acl *acl;

	if (mask & MAY_NOT_BLOCK) {
		acl = get_cached_acl_rcu(inode, ACL_TYPE_ACCESS);
	        if (!acl)
	                return -EAGAIN;
		
		if (is_uncached_acl(acl))
			return -ECHILD;
	        return posix_acl_permission(inode, acl, mask & ~MAY_NOT_BLOCK);
	}

	acl = get_acl(inode, ACL_TYPE_ACCESS);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl) {
	        int error = posix_acl_permission(inode, acl, mask);
	        posix_acl_release(acl);
	        return error;
	}


	return -EAGAIN;
}


static int acl_permission_check(struct inode *inode, int mask)
{
	unsigned int mode = inode->i_mode;

	if (likely(uid_eq(current_fsuid(), inode->i_uid)))
		mode >>= 6;
	else {
		if (IS_POSIXACL(inode) && (mode & S_IRWXG)) {
			int error = check_acl(inode, mask);
			if (error != -EAGAIN)
				return error;
		}

		if (in_group_p(inode->i_gid))
			mode >>= 3;
	}

	
	if ((mask & ~mode & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;
	return -EACCES;
}


int generic_permission(struct inode *inode, int mask)
{
	int ret;

	
	ret = acl_permission_check(inode, mask);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) {
		
		if (!(mask & MAY_WRITE))
			if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
				return 0;
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;
		return -EACCES;
	}

	
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;
	if (mask == MAY_READ)
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
			return 0;
	
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;

	return -EACCES;
}
EXPORT_SYMBOL(generic_permission);


static inline int do_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		
		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	return generic_permission(inode, mask);
}


static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
	if (unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		
		if (sb_rdonly(sb) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}


int inode_permission(struct inode *inode, int mask)
{
	int retval;

	retval = sb_permission(inode->i_sb, inode, mask);
	if (retval)
		return retval;

	if (unlikely(mask & MAY_WRITE)) {
		
		if (IS_IMMUTABLE(inode))
			return -EPERM;

		
		if (HAS_UNMAPPED_ID(inode))
			return -EACCES;
	}

	retval = do_inode_permission(inode, mask);
	if (retval)
		return retval;

	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;

	return security_inode_permission(inode, mask);
}
EXPORT_SYMBOL(inode_permission);


void path_get(const struct path *path)
{
	mntget(path->mnt);
	dget(path->dentry);
}
EXPORT_SYMBOL(path_get);


void path_put(const struct path *path)
{
	dput(path->dentry);
	mntput(path->mnt);
}
EXPORT_SYMBOL(path_put);


struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; 
	unsigned int	flags;
	unsigned	seq, m_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name;
	struct nameidata *saved;
	struct inode	*link_inode;
	unsigned	root_seq;
	int		dfd;
} __randomize_layout;

static void set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	struct nameidata *old = current->nameidata;
	p->stack = p->internal;
	p->dfd = dfd;
	p->name = name;
	p->total_link_count = old ? old->total_link_count : 0;
	p->saved = old;
	current->nameidata = p;
}

static void restore_nameidata(void)
{
	struct nameidata *now = current->nameidata, *old = now->saved;

	current->nameidata = old;
	if (old)
		old->total_link_count = now->total_link_count;
	if (now->stack != now->internal)
		kfree(now->stack);
}

static int __nd_alloc_stack(struct nameidata *nd)
{
	struct saved *p;

	if (nd->flags & LOOKUP_RCU) {
		p= kmalloc_array(MAXSYMLINKS, sizeof(struct saved), GFP_ATOMIC);
		if (unlikely(!p))
			return -ECHILD;
	} else {
		p= kmalloc_array(MAXSYMLINKS, sizeof(struct saved), GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
	}
	memcpy(p, nd->internal, sizeof(nd->internal));
	nd->stack = p;
	return 0;
}


static bool path_connected(const struct path *path)
{
	struct vfsmount *mnt = path->mnt;
	struct super_block *sb = mnt->mnt_sb;

	
	if (!(sb->s_iflags & SB_I_MULTIROOT) && (mnt->mnt_root == sb->s_root))
		return true;

	return is_subdir(path->dentry, mnt->mnt_root);
}

static inline int nd_alloc_stack(struct nameidata *nd)
{
	if (likely(nd->depth != EMBEDDED_LEVELS))
		return 0;
	if (likely(nd->stack != nd->internal))
		return 0;
	return __nd_alloc_stack(nd);
}

static void drop_links(struct nameidata *nd)
{
	int i = nd->depth;
	while (i--) {
		struct saved *last = nd->stack + i;
		do_delayed_call(&last->done);
		clear_delayed_call(&last->done);
	}
}

static void terminate_walk(struct nameidata *nd)
{
	drop_links(nd);
	if (!(nd->flags & LOOKUP_RCU)) {
		int i;
		path_put(&nd->path);
		for (i = 0; i < nd->depth; i++)
			path_put(&nd->stack[i].link);
		if (nd->flags & LOOKUP_ROOT_GRABBED) {
			path_put(&nd->root);
			nd->flags &= ~LOOKUP_ROOT_GRABBED;
		}
	} else {
		nd->flags &= ~LOOKUP_RCU;
		rcu_read_unlock();
	}
	nd->depth = 0;
}


static bool legitimize_path(struct nameidata *nd, struct path *path, unsigned seq)
{
	int res = __legitimize_mnt(path->mnt, nd->m_seq);
	if (unlikely(res)) {
		if (res > 0)
			path->mnt = NULL;
		path->dentry = NULL;
		return false;
	}
	if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
		path->dentry = NULL;
		return false;
	}
	return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static bool legitimize_links(struct nameidata *nd)
{
	int i;
	for (i = 0; i < nd->depth; i++) {
		struct saved *last = nd->stack + i;
		if (unlikely(!legitimize_path(nd, &last->link, last->seq))) {
			drop_links(nd);
			nd->depth = i + 1;
			return false;
		}
	}
	return true;
}

static bool legitimize_root(struct nameidata *nd)
{
	if (!nd->root.mnt || (nd->flags & LOOKUP_ROOT))
		return true;
	nd->flags |= LOOKUP_ROOT_GRABBED;
	return legitimize_path(nd, &nd->root, nd->root_seq);
}




static int unlazy_walk(struct nameidata *nd)
{
	struct dentry *parent = nd->path.dentry;

	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!legitimize_links(nd)))
		goto out1;
	if (unlikely(!legitimize_path(nd, &nd->path, nd->seq)))
		goto out;
	if (unlikely(!legitimize_root(nd)))
		goto out;
	rcu_read_unlock();
	BUG_ON(nd->inode != parent->d_inode);
	return 0;

out1:
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return -ECHILD;
}


static int unlazy_child(struct nameidata *nd, struct dentry *dentry, unsigned seq)
{
	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!legitimize_links(nd)))
		goto out2;
	if (unlikely(!legitimize_mnt(nd->path.mnt, nd->m_seq)))
		goto out2;
	if (unlikely(!lockref_get_not_dead(&nd->path.dentry->d_lockref)))
		goto out1;

	
	if (unlikely(!lockref_get_not_dead(&dentry->d_lockref)))
		goto out;
	if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
		goto out_dput;
	
	if (unlikely(!legitimize_root(nd)))
		goto out_dput;
	rcu_read_unlock();
	return 0;

out2:
	nd->path.mnt = NULL;
out1:
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return -ECHILD;
out_dput:
	rcu_read_unlock();
	dput(dentry);
	return -ECHILD;
}

static inline int d_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
		return dentry->d_op->d_revalidate(dentry, flags);
	else return 1;
}


static int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		if (!(nd->flags & LOOKUP_ROOT))
			nd->root.mnt = NULL;
		if (unlikely(unlazy_walk(nd)))
			return -ECHILD;
	}

	if (likely(!(nd->flags & LOOKUP_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	return status;
}

static void set_root(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;

	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;

		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->root = fs->root;
			nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
		} while (read_seqcount_retry(&fs->seq, seq));
	} else {
		get_fs_root(fs, &nd->root);
		nd->flags |= LOOKUP_ROOT_GRABBED;
	}
}

static void path_put_conditional(struct path *path, struct nameidata *nd)
{
	dput(path->dentry);
	if (path->mnt != nd->path.mnt)
		mntput(path->mnt);
}

static inline void path_to_nameidata(const struct path *path, struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU)) {
		dput(nd->path.dentry);
		if (nd->path.mnt != path->mnt)
			mntput(nd->path.mnt);
	}
	nd->path.mnt = path->mnt;
	nd->path.dentry = path->dentry;
}

static int nd_jump_root(struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		struct dentry *d;
		nd->path = nd->root;
		d = nd->path.dentry;
		nd->inode = d->d_inode;
		nd->seq = nd->root_seq;
		if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
			return -ECHILD;
	} else {
		path_put(&nd->path);
		nd->path = nd->root;
		path_get(&nd->path);
		nd->inode = nd->path.dentry->d_inode;
	}
	nd->flags |= LOOKUP_JUMPED;
	return 0;
}


void nd_jump_link(struct path *path)
{
	struct nameidata *nd = current->nameidata;
	path_put(&nd->path);

	nd->path = *path;
	nd->inode = nd->path.dentry->d_inode;
	nd->flags |= LOOKUP_JUMPED;
}

static inline void put_link(struct nameidata *nd)
{
	struct saved *last = nd->stack + --nd->depth;
	do_delayed_call(&last->done);
	if (!(nd->flags & LOOKUP_RCU))
		path_put(&last->link);
}

int sysctl_protected_symlinks __read_mostly = 0;
int sysctl_protected_hardlinks __read_mostly = 0;
int sysctl_protected_fifos __read_mostly;
int sysctl_protected_regular __read_mostly;


static inline int may_follow_link(struct nameidata *nd)
{
	const struct inode *inode;
	const struct inode *parent;
	kuid_t puid;

	if (!sysctl_protected_symlinks)
		return 0;

	
	inode = nd->link_inode;
	if (uid_eq(current_cred()->fsuid, inode->i_uid))
		return 0;

	
	parent = nd->inode;
	if ((parent->i_mode & (S_ISVTX|S_IWOTH)) != (S_ISVTX|S_IWOTH))
		return 0;

	
	puid = parent->i_uid;
	if (uid_valid(puid) && uid_eq(puid, inode->i_uid))
		return 0;

	if (nd->flags & LOOKUP_RCU)
		return -ECHILD;

	audit_inode(nd->name, nd->stack[0].link.dentry, 0);
	audit_log_path_denied(AUDIT_ANOM_LINK, "follow_link");
	return -EACCES;
}


static bool safe_hardlink_source(struct inode *inode)
{
	umode_t mode = inode->i_mode;

	
	if (!S_ISREG(mode))
		return false;

	
	if (mode & S_ISUID)
		return false;

	
	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
		return false;

	
	if (inode_permission(inode, MAY_READ | MAY_WRITE))
		return false;

	return true;
}


static int may_linkat(struct path *link)
{
	struct inode *inode = link->dentry->d_inode;

	
	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	if (!sysctl_protected_hardlinks)
		return 0;

	
	if (safe_hardlink_source(inode) || inode_owner_or_capable(inode))
		return 0;

	audit_log_path_denied(AUDIT_ANOM_LINK, "linkat");
	return -EPERM;
}


static int may_create_in_sticky(struct dentry * const dir, struct inode * const inode)
{
	if ((!sysctl_protected_fifos && S_ISFIFO(inode->i_mode)) || (!sysctl_protected_regular && S_ISREG(inode->i_mode)) || likely(!(dir->d_inode->i_mode & S_ISVTX)) || uid_eq(inode->i_uid, dir->d_inode->i_uid) || uid_eq(current_fsuid(), inode->i_uid))



		return 0;

	if (likely(dir->d_inode->i_mode & 0002) || (dir->d_inode->i_mode & 0020 && ((sysctl_protected_fifos >= 2 && S_ISFIFO(inode->i_mode)) || (sysctl_protected_regular >= 2 && S_ISREG(inode->i_mode))))) {


		const char *operation = S_ISFIFO(inode->i_mode) ? "sticky_create_fifo" :
					"sticky_create_regular";
		audit_log_path_denied(AUDIT_ANOM_CREAT, operation);
		return -EACCES;
	}
	return 0;
}

static __always_inline const char *get_link(struct nameidata *nd)
{
	struct saved *last = nd->stack + nd->depth - 1;
	struct dentry *dentry = last->link.dentry;
	struct inode *inode = nd->link_inode;
	int error;
	const char *res;

	if (!(nd->flags & LOOKUP_RCU)) {
		touch_atime(&last->link);
		cond_resched();
	} else if (atime_needs_update(&last->link, inode)) {
		if (unlikely(unlazy_walk(nd)))
			return ERR_PTR(-ECHILD);
		touch_atime(&last->link);
	}

	error = security_inode_follow_link(dentry, inode, nd->flags & LOOKUP_RCU);
	if (unlikely(error))
		return ERR_PTR(error);

	nd->last_type = LAST_BIND;
	res = READ_ONCE(inode->i_link);
	if (!res) {
		const char * (*get)(struct dentry *, struct inode *, struct delayed_call *);
		get = inode->i_op->get_link;
		if (nd->flags & LOOKUP_RCU) {
			res = get(NULL, inode, &last->done);
			if (res == ERR_PTR(-ECHILD)) {
				if (unlikely(unlazy_walk(nd)))
					return ERR_PTR(-ECHILD);
				res = get(dentry, inode, &last->done);
			}
		} else {
			res = get(dentry, inode, &last->done);
		}
		if (IS_ERR_OR_NULL(res))
			return res;
	}
	if (*res == '/') {
		if (!nd->root.mnt)
			set_root(nd);
		if (unlikely(nd_jump_root(nd)))
			return ERR_PTR(-ECHILD);
		while (unlikely(*++res == '/'))
			;
	}
	if (!*res)
		res = NULL;
	return res;
}


int follow_up(struct path *path)
{
	struct mount *mnt = real_mount(path->mnt);
	struct mount *parent;
	struct dentry *mountpoint;

	read_seqlock_excl(&mount_lock);
	parent = mnt->mnt_parent;
	if (parent == mnt) {
		read_sequnlock_excl(&mount_lock);
		return 0;
	}
	mntget(&parent->mnt);
	mountpoint = dget(mnt->mnt_mountpoint);
	read_sequnlock_excl(&mount_lock);
	dput(path->dentry);
	path->dentry = mountpoint;
	mntput(path->mnt);
	path->mnt = &parent->mnt;
	return 1;
}
EXPORT_SYMBOL(follow_up);


static int follow_automount(struct path *path, struct nameidata *nd, bool *need_mntput)
{
	struct vfsmount *mnt;
	int err;

	if (!path->dentry->d_op || !path->dentry->d_op->d_automount)
		return -EREMOTE;

	
	if (!(nd->flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY | LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) && path->dentry->d_inode)

		return -EISDIR;

	nd->total_link_count++;
	if (nd->total_link_count >= 40)
		return -ELOOP;

	mnt = path->dentry->d_op->d_automount(path);
	if (IS_ERR(mnt)) {
		
		if (PTR_ERR(mnt) == -EISDIR && (nd->flags & LOOKUP_PARENT))
			return -EREMOTE;
		return PTR_ERR(mnt);
	}

	if (!mnt) 
		return 0;

	if (!*need_mntput) {
		
		mntget(path->mnt);
		*need_mntput = true;
	}
	err = finish_automount(mnt, path);

	switch (err) {
	case -EBUSY:
		
		return 0;
	case 0:
		path_put(path);
		path->mnt = mnt;
		path->dentry = dget(mnt->mnt_root);
		return 0;
	default:
		return err;
	}

}


static int follow_managed(struct path *path, struct nameidata *nd)
{
	struct vfsmount *mnt = path->mnt; 
	unsigned flags;
	bool need_mntput = false;
	int ret = 0;

	
	while (flags = smp_load_acquire(&path->dentry->d_flags), unlikely(flags & DCACHE_MANAGED_DENTRY)) {
		
		if (flags & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path, false);
			flags = smp_load_acquire(&path->dentry->d_flags);
			if (ret < 0)
				break;
		}

		
		if (flags & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				need_mntput = true;
				continue;
			}

			
		}

		
		if (flags & DCACHE_NEED_AUTOMOUNT) {
			ret = follow_automount(path, nd, &need_mntput);
			if (ret < 0)
				break;
			continue;
		}

		
		break;
	}

	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (need_mntput)
		nd->flags |= LOOKUP_JUMPED;
	if (ret == -EISDIR || !ret)
		ret = 1;
	if (ret > 0 && unlikely(d_flags_negative(flags)))
		ret = -ENOENT;
	if (unlikely(ret < 0))
		path_put_conditional(path, nd);
	return ret;
}

int follow_down_one(struct path *path)
{
	struct vfsmount *mounted;

	mounted = lookup_mnt(path);
	if (mounted) {
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down_one);

static inline int managed_dentry_rcu(const struct path *path)
{
	return (path->dentry->d_flags & DCACHE_MANAGE_TRANSIT) ? path->dentry->d_op->d_manage(path, true) : 0;
}


static bool __follow_mount_rcu(struct nameidata *nd, struct path *path, struct inode **inode, unsigned *seqp)
{
	for (;;) {
		struct mount *mounted;
		
		switch (managed_dentry_rcu(path)) {
		case -ECHILD:
		default:
			return false;
		case -EISDIR:
			return true;
		case 0:
			break;
		}

		if (!d_mountpoint(path->dentry))
			return !(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);

		mounted = __lookup_mnt(path->mnt, path->dentry);
		if (!mounted)
			break;
		path->mnt = &mounted->mnt;
		path->dentry = mounted->mnt.mnt_root;
		nd->flags |= LOOKUP_JUMPED;
		*seqp = read_seqcount_begin(&path->dentry->d_seq);
		
		*inode = path->dentry->d_inode;
	}
	return !read_seqretry(&mount_lock, nd->m_seq) && !(path->dentry->d_flags & DCACHE_NEED_AUTOMOUNT);
}

static int follow_dotdot_rcu(struct nameidata *nd)
{
	struct inode *inode = nd->inode;

	while (1) {
		if (path_equal(&nd->path, &nd->root))
			break;
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			struct dentry *old = nd->path.dentry;
			struct dentry *parent = old->d_parent;
			unsigned seq;

			inode = parent->d_inode;
			seq = read_seqcount_begin(&parent->d_seq);
			if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
				return -ECHILD;
			nd->path.dentry = parent;
			nd->seq = seq;
			if (unlikely(!path_connected(&nd->path)))
				return -ENOENT;
			break;
		} else {
			struct mount *mnt = real_mount(nd->path.mnt);
			struct mount *mparent = mnt->mnt_parent;
			struct dentry *mountpoint = mnt->mnt_mountpoint;
			struct inode *inode2 = mountpoint->d_inode;
			unsigned seq = read_seqcount_begin(&mountpoint->d_seq);
			if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
				return -ECHILD;
			if (&mparent->mnt == nd->path.mnt)
				break;
			
			nd->path.dentry = mountpoint;
			nd->path.mnt = &mparent->mnt;
			inode = inode2;
			nd->seq = seq;
		}
	}
	while (unlikely(d_mountpoint(nd->path.dentry))) {
		struct mount *mounted;
		mounted = __lookup_mnt(nd->path.mnt, nd->path.dentry);
		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
			return -ECHILD;
		if (!mounted)
			break;
		nd->path.mnt = &mounted->mnt;
		nd->path.dentry = mounted->mnt.mnt_root;
		inode = nd->path.dentry->d_inode;
		nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
	}
	nd->inode = inode;
	return 0;
}


int follow_down(struct path *path)
{
	unsigned managed;
	int ret;

	while (managed = READ_ONCE(path->dentry->d_flags), unlikely(managed & DCACHE_MANAGED_DENTRY)) {
		
		if (managed & DCACHE_MANAGE_TRANSIT) {
			BUG_ON(!path->dentry->d_op);
			BUG_ON(!path->dentry->d_op->d_manage);
			ret = path->dentry->d_op->d_manage(path, false);
			if (ret < 0)
				return ret == -EISDIR ? 0 : ret;
		}

		
		if (managed & DCACHE_MOUNTED) {
			struct vfsmount *mounted = lookup_mnt(path);
			if (!mounted)
				break;
			dput(path->dentry);
			mntput(path->mnt);
			path->mnt = mounted;
			path->dentry = dget(mounted->mnt_root);
			continue;
		}

		
		break;
	}
	return 0;
}
EXPORT_SYMBOL(follow_down);


static void follow_mount(struct path *path)
{
	while (d_mountpoint(path->dentry)) {
		struct vfsmount *mounted = lookup_mnt(path);
		if (!mounted)
			break;
		dput(path->dentry);
		mntput(path->mnt);
		path->mnt = mounted;
		path->dentry = dget(mounted->mnt_root);
	}
}

static int path_parent_directory(struct path *path)
{
	struct dentry *old = path->dentry;
	
	path->dentry = dget_parent(path->dentry);
	dput(old);
	if (unlikely(!path_connected(path)))
		return -ENOENT;
	return 0;
}

static int follow_dotdot(struct nameidata *nd)
{
	while(1) {
		if (path_equal(&nd->path, &nd->root))
			break;
		if (nd->path.dentry != nd->path.mnt->mnt_root) {
			int ret = path_parent_directory(&nd->path);
			if (ret)
				return ret;
			break;
		}
		if (!follow_up(&nd->path))
			break;
	}
	follow_mount(&nd->path);
	nd->inode = nd->path.dentry->d_inode;
	return 0;
}


static struct dentry *lookup_dcache(const struct qstr *name, struct dentry *dir, unsigned int flags)

{
	struct dentry *dentry = d_lookup(dir, name);
	if (dentry) {
		int error = d_revalidate(dentry, flags);
		if (unlikely(error <= 0)) {
			if (!error)
				d_invalidate(dentry);
			dput(dentry);
			return ERR_PTR(error);
		}
	}
	return dentry;
}


static struct dentry *__lookup_hash(const struct qstr *name, struct dentry *base, unsigned int flags)
{
	struct dentry *dentry = lookup_dcache(name, base, flags);
	struct dentry *old;
	struct inode *dir = base->d_inode;

	if (dentry)
		return dentry;

	
	if (unlikely(IS_DEADDIR(dir)))
		return ERR_PTR(-ENOENT);

	dentry = d_alloc(base, name);
	if (unlikely(!dentry))
		return ERR_PTR(-ENOMEM);

	old = dir->i_op->lookup(dir, dentry, flags);
	if (unlikely(old)) {
		dput(dentry);
		dentry = old;
	}
	return dentry;
}

static int lookup_fast(struct nameidata *nd, struct path *path, struct inode **inode, unsigned *seqp)

{
	struct vfsmount *mnt = nd->path.mnt;
	struct dentry *dentry, *parent = nd->path.dentry;
	int status = 1;
	int err;

	
	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;
		bool negative;
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
		if (unlikely(!dentry)) {
			if (unlazy_walk(nd))
				return -ECHILD;
			return 0;
		}

		
		*inode = d_backing_inode(dentry);
		negative = d_is_negative(dentry);
		if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
			return -ECHILD;

		
		if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
			return -ECHILD;

		*seqp = seq;
		status = d_revalidate(dentry, nd->flags);
		if (likely(status > 0)) {
			
			if (unlikely(negative))
				return -ENOENT;
			path->mnt = mnt;
			path->dentry = dentry;
			if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
				return 1;
		}
		if (unlazy_child(nd, dentry, seq))
			return -ECHILD;
		if (unlikely(status == -ECHILD))
			
			status = d_revalidate(dentry, nd->flags);
	} else {
		dentry = __d_lookup(parent, &nd->last);
		if (unlikely(!dentry))
			return 0;
		status = d_revalidate(dentry, nd->flags);
	}
	if (unlikely(status <= 0)) {
		if (!status)
			d_invalidate(dentry);
		dput(dentry);
		return status;
	}

	path->mnt = mnt;
	path->dentry = dentry;
	err = follow_managed(path, nd);
	if (likely(err > 0))
		*inode = d_backing_inode(path->dentry);
	return err;
}


static struct dentry *__lookup_slow(const struct qstr *name, struct dentry *dir, unsigned int flags)

{
	struct dentry *dentry, *old;
	struct inode *inode = dir->d_inode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	
	if (unlikely(IS_DEADDIR(inode)))
		return ERR_PTR(-ENOENT);
again:
	dentry = d_alloc_parallel(dir, name, &wq);
	if (IS_ERR(dentry))
		return dentry;
	if (unlikely(!d_in_lookup(dentry))) {
		int error = d_revalidate(dentry, flags);
		if (unlikely(error <= 0)) {
			if (!error) {
				d_invalidate(dentry);
				dput(dentry);
				goto again;
			}
			dput(dentry);
			dentry = ERR_PTR(error);
		}
	} else {
		old = inode->i_op->lookup(inode, dentry, flags);
		d_lookup_done(dentry);
		if (unlikely(old)) {
			dput(dentry);
			dentry = old;
		}
	}
	return dentry;
}

static struct dentry *lookup_slow(const struct qstr *name, struct dentry *dir, unsigned int flags)

{
	struct inode *inode = dir->d_inode;
	struct dentry *res;
	inode_lock_shared(inode);
	res = __lookup_slow(name, dir, flags);
	inode_unlock_shared(inode);
	return res;
}

static inline int may_lookup(struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		int err = inode_permission(nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
		if (err != -ECHILD)
			return err;
		if (unlazy_walk(nd))
			return -ECHILD;
	}
	return inode_permission(nd->inode, MAY_EXEC);
}

static inline int handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) {
		if (!nd->root.mnt)
			set_root(nd);
		if (nd->flags & LOOKUP_RCU) {
			return follow_dotdot_rcu(nd);
		} else return follow_dotdot(nd);
	}
	return 0;
}

static int pick_link(struct nameidata *nd, struct path *link, struct inode *inode, unsigned seq)
{
	int error;
	struct saved *last;
	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS)) {
		path_to_nameidata(link, nd);
		return -ELOOP;
	}
	if (!(nd->flags & LOOKUP_RCU)) {
		if (link->mnt == nd->path.mnt)
			mntget(link->mnt);
	}
	error = nd_alloc_stack(nd);
	if (unlikely(error)) {
		if (error == -ECHILD) {
			if (unlikely(!legitimize_path(nd, link, seq))) {
				drop_links(nd);
				nd->depth = 0;
				nd->flags &= ~LOOKUP_RCU;
				nd->path.mnt = NULL;
				nd->path.dentry = NULL;
				rcu_read_unlock();
			} else if (likely(unlazy_walk(nd)) == 0)
				error = nd_alloc_stack(nd);
		}
		if (error) {
			path_put(link);
			return error;
		}
	}

	last = nd->stack + nd->depth++;
	last->link = *link;
	clear_delayed_call(&last->done);
	nd->link_inode = inode;
	last->seq = seq;
	return 1;
}

enum {WALK_FOLLOW = 1, WALK_MORE = 2};


static inline int step_into(struct nameidata *nd, struct path *path, int flags, struct inode *inode, unsigned seq)
{
	if (!(flags & WALK_MORE) && nd->depth)
		put_link(nd);
	if (likely(!d_is_symlink(path->dentry)) || !(flags & WALK_FOLLOW || nd->flags & LOOKUP_FOLLOW)) {
		
		path_to_nameidata(path, nd);
		nd->inode = inode;
		nd->seq = seq;
		return 0;
	}
	
	if (nd->flags & LOOKUP_RCU) {
		if (read_seqcount_retry(&path->dentry->d_seq, seq))
			return -ECHILD;
	}
	return pick_link(nd, path, inode, seq);
}

static int walk_component(struct nameidata *nd, int flags)
{
	struct path path;
	struct inode *inode;
	unsigned seq;
	int err;
	
	if (unlikely(nd->last_type != LAST_NORM)) {
		err = handle_dots(nd, nd->last_type);
		if (!(flags & WALK_MORE) && nd->depth)
			put_link(nd);
		return err;
	}
	err = lookup_fast(nd, &path, &inode, &seq);
	if (unlikely(err <= 0)) {
		if (err < 0)
			return err;
		path.dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
		if (IS_ERR(path.dentry))
			return PTR_ERR(path.dentry);

		path.mnt = nd->path.mnt;
		err = follow_managed(&path, nd);
		if (unlikely(err < 0))
			return err;

		seq = 0;	
		inode = d_backing_inode(path.dentry);
	}

	return step_into(nd, &path, flags, inode, seq);
}


















static inline unsigned int fold_hash(unsigned long x, unsigned long y)
{
	y ^= x * GOLDEN_RATIO_64;
	y *= GOLDEN_RATIO_64;
	return y >> 32;
}









static inline unsigned int fold_hash(unsigned long x, unsigned long y)
{
	
	return __hash_32(y ^ __hash_32(x));
}




unsigned int full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long a, x = 0, y = (unsigned long)salt;

	for (;;) {
		if (!len)
			goto done;
		a = load_unaligned_zeropad(name);
		if (len < sizeof(unsigned long))
			break;
		HASH_MIX(x, y, a);
		name += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}
	x ^= a & bytemask_from_count(len);
done:
	return fold_hash(x, y);
}
EXPORT_SYMBOL(full_name_hash);


u64 hashlen_string(const void *salt, const char *name)
{
	unsigned long a = 0, x = 0, y = (unsigned long)salt;
	unsigned long adata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
	} while (!has_zero(a, &adata, &constants));

	adata = prep_zero_mask(a, adata, &constants);
	mask = create_zero_mask(adata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(fold_hash(x, y), len + find_zero(mask));
}
EXPORT_SYMBOL(hashlen_string);


static inline u64 hash_name(const void *salt, const char *name)
{
	unsigned long a = 0, b, x = 0, y = (unsigned long)salt;
	unsigned long adata, bdata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);
	mask = create_zero_mask(adata | bdata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(fold_hash(x, y), len + find_zero(mask));
}




unsigned int full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long hash = init_name_hash(salt);
	while (len--)
		hash = partial_name_hash((unsigned char)*name++, hash);
	return end_name_hash(hash);
}
EXPORT_SYMBOL(full_name_hash);


u64 hashlen_string(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	while (c) {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	}
	return hashlen_create(end_name_hash(hash), len);
}
EXPORT_SYMBOL(hashlen_string);


static inline u64 hash_name(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	return hashlen_create(end_name_hash(hash), len);
}




static int link_path_walk(const char *name, struct nameidata *nd)
{
	int err;

	if (IS_ERR(name))
		return PTR_ERR(name);
	while (*name=='/')
		name++;
	if (!*name)
		return 0;

	
	for(;;) {
		u64 hash_len;
		int type;

		err = may_lookup(nd);
		if (err)
			return err;

		hash_len = hash_name(nd->path.dentry, name);

		type = LAST_NORM;
		if (name[0] == '.') switch (hashlen_len(hash_len)) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					return err;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		name += hashlen_len(hash_len);
		if (!*name)
			goto OK;
		
		do {
			name++;
		} while (unlikely(*name == '/'));
		if (unlikely(!*name)) {
OK:
			
			if (!nd->depth)
				return 0;
			name = nd->stack[nd->depth - 1].name;
			
			if (!name)
				return 0;
			
			err = walk_component(nd, WALK_FOLLOW);
		} else {
			
			err = walk_component(nd, WALK_FOLLOW | WALK_MORE);
		}
		if (err < 0)
			return err;

		if (err) {
			const char *s = get_link(nd);

			if (IS_ERR(s))
				return PTR_ERR(s);
			err = 0;
			if (unlikely(!s)) {
				
				put_link(nd);
			} else {
				nd->stack[nd->depth - 1].name = name;
				name = s;
				continue;
			}
		}
		if (unlikely(!d_can_lookup(nd->path.dentry))) {
			if (nd->flags & LOOKUP_RCU) {
				if (unlazy_walk(nd))
					return -ECHILD;
			}
			return -ENOTDIR;
		}
	}
}


static const char *path_init(struct nameidata *nd, unsigned flags)
{
	const char *s = nd->name->name;

	if (!*s)
		flags &= ~LOOKUP_RCU;
	if (flags & LOOKUP_RCU)
		rcu_read_lock();

	nd->last_type = LAST_ROOT; 
	nd->flags = flags | LOOKUP_JUMPED | LOOKUP_PARENT;
	nd->depth = 0;
	if (flags & LOOKUP_ROOT) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*s && unlikely(!d_can_lookup(root)))
			return ERR_PTR(-ENOTDIR);
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->root_seq = nd->seq;
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			path_get(&nd->path);
		}
		return s;
	}

	nd->root.mnt = NULL;
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;

	nd->m_seq = read_seqbegin(&mount_lock);
	if (*s == '/') {
		set_root(nd);
		if (likely(!nd_jump_root(nd)))
			return s;
		return ERR_PTR(-ECHILD);
	} else if (nd->dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->inode = nd->path.dentry->d_inode;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(current->fs, &nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		return s;
	} else {
		
		struct fd f = fdget_raw(nd->dfd);
		struct dentry *dentry;

		if (!f.file)
			return ERR_PTR(-EBADF);

		dentry = f.file->f_path.dentry;

		if (*s && unlikely(!d_can_lookup(dentry))) {
			fdput(f);
			return ERR_PTR(-ENOTDIR);
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			nd->inode = nd->path.dentry->d_inode;
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
		} else {
			path_get(&nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		fdput(f);
		return s;
	}
}

static const char *trailing_symlink(struct nameidata *nd)
{
	const char *s;
	int error = may_follow_link(nd);
	if (unlikely(error))
		return ERR_PTR(error);
	nd->flags |= LOOKUP_PARENT;
	nd->stack[0].name = NULL;
	s = get_link(nd);
	return s ? s : "";
}

static inline int lookup_last(struct nameidata *nd)
{
	if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
		nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

	nd->flags &= ~LOOKUP_PARENT;
	return walk_component(nd, 0);
}

static int handle_lookup_down(struct nameidata *nd)
{
	struct path path = nd->path;
	struct inode *inode = nd->inode;
	unsigned seq = nd->seq;
	int err;

	if (nd->flags & LOOKUP_RCU) {
		
		if (unlikely(!__follow_mount_rcu(nd, &path, &inode, &seq)))
			return -ECHILD;
	} else {
		dget(path.dentry);
		err = follow_managed(&path, nd);
		if (unlikely(err < 0))
			return err;
		inode = d_backing_inode(path.dentry);
		seq = 0;
	}
	path_to_nameidata(&path, nd);
	nd->inode = inode;
	nd->seq = seq;
	return 0;
}


static int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
	const char *s = path_init(nd, flags);
	int err;

	if (unlikely(flags & LOOKUP_DOWN) && !IS_ERR(s)) {
		err = handle_lookup_down(nd);
		if (unlikely(err < 0))
			s = ERR_PTR(err);
	}

	while (!(err = link_path_walk(s, nd))
		&& ((err = lookup_last(nd)) > 0)) {
		s = trailing_symlink(nd);
	}
	if (!err)
		err = complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY)
		if (!d_can_lookup(nd->path.dentry))
			err = -ENOTDIR;
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

int filename_lookup(int dfd, struct filename *name, unsigned flags, struct path *path, struct path *root)
{
	int retval;
	struct nameidata nd;
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (unlikely(root)) {
		nd.root = *root;
		flags |= LOOKUP_ROOT;
	}
	set_nameidata(&nd, dfd, name);
	retval = path_lookupat(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(&nd, flags, path);
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(&nd, flags | LOOKUP_REVAL, path);

	if (likely(!retval))
		audit_inode(name, path->dentry, 0);
	restore_nameidata();
	putname(name);
	return retval;
}


static int path_parentat(struct nameidata *nd, unsigned flags, struct path *parent)
{
	const char *s = path_init(nd, flags);
	int err = link_path_walk(s, nd);
	if (!err)
		err = complete_walk(nd);
	if (!err) {
		*parent = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

static struct filename *filename_parentat(int dfd, struct filename *name, unsigned int flags, struct path *parent, struct qstr *last, int *type)

{
	int retval;
	struct nameidata nd;

	if (IS_ERR(name))
		return name;
	set_nameidata(&nd, dfd, name);
	retval = path_parentat(&nd, flags | LOOKUP_RCU, parent);
	if (unlikely(retval == -ECHILD))
		retval = path_parentat(&nd, flags, parent);
	if (unlikely(retval == -ESTALE))
		retval = path_parentat(&nd, flags | LOOKUP_REVAL, parent);
	if (likely(!retval)) {
		*last = nd.last;
		*type = nd.last_type;
		audit_inode(name, parent->dentry, AUDIT_INODE_PARENT);
	} else {
		putname(name);
		name = ERR_PTR(retval);
	}
	restore_nameidata();
	return name;
}


struct dentry *kern_path_locked(const char *name, struct path *path)
{
	struct filename *filename;
	struct dentry *d;
	struct qstr last;
	int type;

	filename = filename_parentat(AT_FDCWD, getname_kernel(name), 0, path, &last, &type);
	if (IS_ERR(filename))
		return ERR_CAST(filename);
	if (unlikely(type != LAST_NORM)) {
		path_put(path);
		putname(filename);
		return ERR_PTR(-EINVAL);
	}
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	d = __lookup_hash(&last, path->dentry, 0);
	if (IS_ERR(d)) {
		inode_unlock(path->dentry->d_inode);
		path_put(path);
	}
	putname(filename);
	return d;
}

int kern_path(const char *name, unsigned int flags, struct path *path)
{
	return filename_lookup(AT_FDCWD, getname_kernel(name), flags, path, NULL);
}
EXPORT_SYMBOL(kern_path);


int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt, const char *name, unsigned int flags, struct path *path)

{
	struct path root = {.mnt = mnt, .dentry = dentry};
	
	return filename_lookup(AT_FDCWD, getname_kernel(name), flags , path, &root);
}
EXPORT_SYMBOL(vfs_path_lookup);

static int lookup_one_len_common(const char *name, struct dentry *base, int len, struct qstr *this)
{
	this->name = name;
	this->len = len;
	this->hash = full_name_hash(base, name, len);
	if (!len)
		return -EACCES;

	if (unlikely(name[0] == '.')) {
		if (len < 2 || (len == 2 && name[1] == '.'))
			return -EACCES;
	}

	while (len--) {
		unsigned int c = *(const unsigned char *)name++;
		if (c == '/' || c == '\0')
			return -EACCES;
	}
	
	if (base->d_flags & DCACHE_OP_HASH) {
		int err = base->d_op->d_hash(base, this);
		if (err < 0)
			return err;
	}

	return inode_permission(base->d_inode, MAY_EXEC);
}


struct dentry *try_lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct qstr this;
	int err;

	WARN_ON_ONCE(!inode_is_locked(base->d_inode));

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	return lookup_dcache(&this, base, 0);
}
EXPORT_SYMBOL(try_lookup_one_len);


struct dentry *lookup_one_len(const char *name, struct dentry *base, int len)
{
	struct dentry *dentry;
	struct qstr this;
	int err;

	WARN_ON_ONCE(!inode_is_locked(base->d_inode));

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	dentry = lookup_dcache(&this, base, 0);
	return dentry ? dentry : __lookup_slow(&this, base, 0);
}
EXPORT_SYMBOL(lookup_one_len);


struct dentry *lookup_one_len_unlocked(const char *name, struct dentry *base, int len)
{
	struct qstr this;
	int err;
	struct dentry *ret;

	err = lookup_one_len_common(name, base, len, &this);
	if (err)
		return ERR_PTR(err);

	ret = lookup_dcache(&this, base, 0);
	if (!ret)
		ret = lookup_slow(&this, base, 0);
	return ret;
}
EXPORT_SYMBOL(lookup_one_len_unlocked);


struct dentry *lookup_positive_unlocked(const char *name, struct dentry *base, int len)
{
	struct dentry *ret = lookup_one_len_unlocked(name, base, len);
	if (!IS_ERR(ret) && d_flags_negative(smp_load_acquire(&ret->d_flags))) {
		dput(ret);
		ret = ERR_PTR(-ENOENT);
	}
	return ret;
}
EXPORT_SYMBOL(lookup_positive_unlocked);


int path_pts(struct path *path)
{
	
	struct dentry *child, *parent;
	struct qstr this;
	int ret;

	ret = path_parent_directory(path);
	if (ret)
		return ret;

	parent = path->dentry;
	this.name = "pts";
	this.len = 3;
	child = d_hash_and_lookup(parent, &this);
	if (!child)
		return -ENOENT;

	path->dentry = child;
	dput(parent);
	follow_mount(path);
	return 0;
}


int user_path_at_empty(int dfd, const char __user *name, unsigned flags, struct path *path, int *empty)
{
	return filename_lookup(dfd, getname_flags(name, flags, empty), flags, path, NULL);
}
EXPORT_SYMBOL(user_path_at_empty);


static int path_mountpoint(struct nameidata *nd, unsigned flags, struct path *path)
{
	const char *s = path_init(nd, flags);
	int err;

	while (!(err = link_path_walk(s, nd)) && (err = lookup_last(nd)) > 0) {
		s = trailing_symlink(nd);
	}
	if (!err && (nd->flags & LOOKUP_RCU))
		err = unlazy_walk(nd);
	if (!err)
		err = handle_lookup_down(nd);
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	terminate_walk(nd);
	return err;
}

static int filename_mountpoint(int dfd, struct filename *name, struct path *path, unsigned int flags)

{
	struct nameidata nd;
	int error;
	if (IS_ERR(name))
		return PTR_ERR(name);
	set_nameidata(&nd, dfd, name);
	error = path_mountpoint(&nd, flags | LOOKUP_RCU, path);
	if (unlikely(error == -ECHILD))
		error = path_mountpoint(&nd, flags, path);
	if (unlikely(error == -ESTALE))
		error = path_mountpoint(&nd, flags | LOOKUP_REVAL, path);
	if (likely(!error))
		audit_inode(name, path->dentry, AUDIT_INODE_NOEVAL);
	restore_nameidata();
	putname(name);
	return error;
}


int user_path_mountpoint_at(int dfd, const char __user *name, unsigned int flags, struct path *path)

{
	return filename_mountpoint(dfd, getname(name), path, flags);
}

int kern_path_mountpoint(int dfd, const char *name, struct path *path, unsigned int flags)

{
	return filename_mountpoint(dfd, getname_kernel(name), path, flags);
}
EXPORT_SYMBOL(kern_path_mountpoint);

int __check_sticky(struct inode *dir, struct inode *inode)
{
	kuid_t fsuid = current_fsuid();

	if (uid_eq(inode->i_uid, fsuid))
		return 0;
	if (uid_eq(dir->i_uid, fsuid))
		return 0;
	return !capable_wrt_inode_uidgid(inode, CAP_FOWNER);
}
EXPORT_SYMBOL(__check_sticky);


static int may_delete(struct inode *dir, struct dentry *victim, bool isdir)
{
	struct inode *inode = d_backing_inode(victim);
	int error;

	if (d_is_negative(victim))
		return -ENOENT;
	BUG_ON(!inode);

	BUG_ON(victim->d_parent->d_inode != dir);

	
	if (!uid_valid(inode->i_uid) || !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	audit_inode_child(dir, victim, AUDIT_TYPE_CHILD_DELETE);

	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;
	if (IS_APPEND(dir))
		return -EPERM;

	if (check_sticky(dir, inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode) || IS_SWAPFILE(inode) || HAS_UNMAPPED_ID(inode))
		return -EPERM;
	if (isdir) {
		if (!d_is_dir(victim))
			return -ENOTDIR;
		if (IS_ROOT(victim))
			return -EBUSY;
	} else if (d_is_dir(victim))
		return -EISDIR;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	if (victim->d_flags & DCACHE_NFSFS_RENAMED)
		return -EBUSY;
	return 0;
}


static inline int may_create(struct inode *dir, struct dentry *child)
{
	struct user_namespace *s_user_ns;
	audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);
	if (child->d_inode)
		return -EEXIST;
	if (IS_DEADDIR(dir))
		return -ENOENT;
	s_user_ns = dir->i_sb->s_user_ns;
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) || !kgid_has_mapping(s_user_ns, current_fsgid()))
		return -EOVERFLOW;
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}


struct dentry *lock_rename(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	if (p1 == p2) {
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		return NULL;
	}

	mutex_lock(&p1->d_sb->s_vfs_rename_mutex);

	p = d_ancestor(p2, p1);
	if (p) {
		inode_lock_nested(p2->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p1->d_inode, I_MUTEX_CHILD);
		return p;
	}

	p = d_ancestor(p1, p2);
	if (p) {
		inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
		inode_lock_nested(p2->d_inode, I_MUTEX_CHILD);
		return p;
	}

	inode_lock_nested(p1->d_inode, I_MUTEX_PARENT);
	inode_lock_nested(p2->d_inode, I_MUTEX_PARENT2);
	return NULL;
}
EXPORT_SYMBOL(lock_rename);

void unlock_rename(struct dentry *p1, struct dentry *p2)
{
	inode_unlock(p1->d_inode);
	if (p1 != p2) {
		inode_unlock(p2->d_inode);
		mutex_unlock(&p1->d_sb->s_vfs_rename_mutex);
	}
}
EXPORT_SYMBOL(unlock_rename);

int vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool want_excl)
{
	int error = may_create(dir, dentry);
	if (error)
		return error;

	if (!dir->i_op->create)
		return -EACCES;	
	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = dir->i_op->create(dir, dentry, mode, want_excl);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_create);

int vfs_mkobj(struct dentry *dentry, umode_t mode, int (*f)(struct dentry *, umode_t, void *), void *arg)

{
	struct inode *dir = dentry->d_parent->d_inode;
	int error = may_create(dir, dentry);
	if (error)
		return error;

	mode &= S_IALLUGO;
	mode |= S_IFREG;
	error = security_inode_create(dir, dentry, mode);
	if (error)
		return error;
	error = f(dentry, mode, arg);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mkobj);

bool may_open_dev(const struct path *path)
{
	return !(path->mnt->mnt_flags & MNT_NODEV) && !(path->mnt->mnt_sb->s_iflags & SB_I_NODEV);
}

static int may_open(const struct path *path, int acc_mode, int flag)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode)
		return -ENOENT;

	switch (inode->i_mode & S_IFMT) {
	case S_IFLNK:
		return -ELOOP;
	case S_IFDIR:
		if (acc_mode & MAY_WRITE)
			return -EISDIR;
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (!may_open_dev(path))
			return -EACCES;
		
	case S_IFIFO:
	case S_IFSOCK:
		flag &= ~O_TRUNC;
		break;
	}

	error = inode_permission(inode, MAY_OPEN | acc_mode);
	if (error)
		return error;

	
	if (IS_APPEND(inode)) {
		if  ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
			return -EPERM;
		if (flag & O_TRUNC)
			return -EPERM;
	}

	
	if (flag & O_NOATIME && !inode_owner_or_capable(inode))
		return -EPERM;

	return 0;
}

static int handle_truncate(struct file *filp)
{
	const struct path *path = &filp->f_path;
	struct inode *inode = path->dentry->d_inode;
	int error = get_write_access(inode);
	if (error)
		return error;
	
	error = locks_verify_locked(filp);
	if (!error)
		error = security_path_truncate(path);
	if (!error) {
		error = do_truncate(path->dentry, 0, ATTR_MTIME|ATTR_CTIME|ATTR_OPEN, filp);

	}
	put_write_access(inode);
	return error;
}

static inline int open_to_namei_flags(int flag)
{
	if ((flag & O_ACCMODE) == 3)
		flag--;
	return flag;
}

static int may_o_create(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct user_namespace *s_user_ns;
	int error = security_path_mknod(dir, dentry, mode, 0);
	if (error)
		return error;

	s_user_ns = dir->dentry->d_sb->s_user_ns;
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) || !kgid_has_mapping(s_user_ns, current_fsgid()))
		return -EOVERFLOW;

	error = inode_permission(dir->dentry->d_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	return security_inode_create(dir->dentry->d_inode, dentry, mode);
}


static int atomic_open(struct nameidata *nd, struct dentry *dentry, struct path *path, struct file *file, const struct open_flags *op, int open_flag, umode_t mode)


{
	struct dentry *const DENTRY_NOT_SET = (void *) -1UL;
	struct inode *dir =  nd->path.dentry->d_inode;
	int error;

	if (!(~open_flag & (O_EXCL | O_CREAT)))	
		open_flag &= ~O_TRUNC;

	if (nd->flags & LOOKUP_DIRECTORY)
		open_flag |= O_DIRECTORY;

	file->f_path.dentry = DENTRY_NOT_SET;
	file->f_path.mnt = nd->path.mnt;
	error = dir->i_op->atomic_open(dir, dentry, file, open_to_namei_flags(open_flag), mode);
	d_lookup_done(dentry);
	if (!error) {
		if (file->f_mode & FMODE_OPENED) {
			
			int acc_mode = op->acc_mode;
			if (file->f_mode & FMODE_CREATED) {
				WARN_ON(!(open_flag & O_CREAT));
				fsnotify_create(dir, dentry);
				acc_mode = 0;
			}
			error = may_open(&file->f_path, acc_mode, open_flag);
			if (WARN_ON(error > 0))
				error = -EINVAL;
		} else if (WARN_ON(file->f_path.dentry == DENTRY_NOT_SET)) {
			error = -EIO;
		} else {
			if (file->f_path.dentry) {
				dput(dentry);
				dentry = file->f_path.dentry;
			}
			if (file->f_mode & FMODE_CREATED)
				fsnotify_create(dir, dentry);
			if (unlikely(d_is_negative(dentry))) {
				error = -ENOENT;
			} else {
				path->dentry = dentry;
				path->mnt = nd->path.mnt;
				return 0;
			}
		}
	}
	dput(dentry);
	return error;
}


static int lookup_open(struct nameidata *nd, struct path *path, struct file *file, const struct open_flags *op, bool got_write)


{
	struct dentry *dir = nd->path.dentry;
	struct inode *dir_inode = dir->d_inode;
	int open_flag = op->open_flag;
	struct dentry *dentry;
	int error, create_error = 0;
	umode_t mode = op->mode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	if (unlikely(IS_DEADDIR(dir_inode)))
		return -ENOENT;

	file->f_mode &= ~FMODE_CREATED;
	dentry = d_lookup(dir, &nd->last);
	for (;;) {
		if (!dentry) {
			dentry = d_alloc_parallel(dir, &nd->last, &wq);
			if (IS_ERR(dentry))
				return PTR_ERR(dentry);
		}
		if (d_in_lookup(dentry))
			break;

		error = d_revalidate(dentry, nd->flags);
		if (likely(error > 0))
			break;
		if (error)
			goto out_dput;
		d_invalidate(dentry);
		dput(dentry);
		dentry = NULL;
	}
	if (dentry->d_inode) {
		
		goto out_no_open;
	}

	
	if (open_flag & O_CREAT) {
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current_umask();
		if (unlikely(!got_write)) {
			create_error = -EROFS;
			open_flag &= ~O_CREAT;
			if (open_flag & (O_EXCL | O_TRUNC))
				goto no_open;
			
		} else {
			create_error = may_o_create(&nd->path, dentry, mode);
			if (create_error) {
				open_flag &= ~O_CREAT;
				if (open_flag & O_EXCL)
					goto no_open;
			}
		}
	} else if ((open_flag & (O_TRUNC|O_WRONLY|O_RDWR)) && unlikely(!got_write)) {
		
		goto no_open;
	}

	if (dir_inode->i_op->atomic_open) {
		error = atomic_open(nd, dentry, path, file, op, open_flag, mode);
		if (unlikely(error == -ENOENT) && create_error)
			error = create_error;
		return error;
	}

no_open:
	if (d_in_lookup(dentry)) {
		struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry, nd->flags);
		d_lookup_done(dentry);
		if (unlikely(res)) {
			if (IS_ERR(res)) {
				error = PTR_ERR(res);
				goto out_dput;
			}
			dput(dentry);
			dentry = res;
		}
	}

	
	if (!dentry->d_inode && (open_flag & O_CREAT)) {
		file->f_mode |= FMODE_CREATED;
		audit_inode_child(dir_inode, dentry, AUDIT_TYPE_CHILD_CREATE);
		if (!dir_inode->i_op->create) {
			error = -EACCES;
			goto out_dput;
		}
		error = dir_inode->i_op->create(dir_inode, dentry, mode, open_flag & O_EXCL);
		if (error)
			goto out_dput;
		fsnotify_create(dir_inode, dentry);
	}
	if (unlikely(create_error) && !dentry->d_inode) {
		error = create_error;
		goto out_dput;
	}
out_no_open:
	path->dentry = dentry;
	path->mnt = nd->path.mnt;
	return 0;

out_dput:
	dput(dentry);
	return error;
}


static int do_last(struct nameidata *nd, struct file *file, const struct open_flags *op)
{
	struct dentry *dir = nd->path.dentry;
	int open_flag = op->open_flag;
	bool will_truncate = (open_flag & O_TRUNC) != 0;
	bool got_write = false;
	int acc_mode = op->acc_mode;
	unsigned seq;
	struct inode *inode;
	struct path path;
	int error;

	nd->flags &= ~LOOKUP_PARENT;
	nd->flags |= op->intent;

	if (nd->last_type != LAST_NORM) {
		error = handle_dots(nd, nd->last_type);
		if (unlikely(error))
			return error;
		goto finish_open;
	}

	if (!(open_flag & O_CREAT)) {
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		
		error = lookup_fast(nd, &path, &inode, &seq);
		if (likely(error > 0))
			goto finish_lookup;

		if (error < 0)
			return error;

		BUG_ON(nd->inode != dir->d_inode);
		BUG_ON(nd->flags & LOOKUP_RCU);
	} else {
		
		
		error = complete_walk(nd);
		if (error)
			return error;

		audit_inode(nd->name, dir, AUDIT_INODE_PARENT);
		
		if (unlikely(nd->last.name[nd->last.len]))
			return -EISDIR;
	}

	if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
		error = mnt_want_write(nd->path.mnt);
		if (!error)
			got_write = true;
		
	}
	if (open_flag & O_CREAT)
		inode_lock(dir->d_inode);
	else inode_lock_shared(dir->d_inode);
	error = lookup_open(nd, &path, file, op, got_write);
	if (open_flag & O_CREAT)
		inode_unlock(dir->d_inode);
	else inode_unlock_shared(dir->d_inode);

	if (error)
		goto out;

	if (file->f_mode & FMODE_OPENED) {
		if ((file->f_mode & FMODE_CREATED) || !S_ISREG(file_inode(file)->i_mode))
			will_truncate = false;

		audit_inode(nd->name, file->f_path.dentry, 0);
		goto opened;
	}

	if (file->f_mode & FMODE_CREATED) {
		
		open_flag &= ~O_TRUNC;
		will_truncate = false;
		acc_mode = 0;
		path_to_nameidata(&path, nd);
		goto finish_open_created;
	}

	
	if (got_write) {
		mnt_drop_write(nd->path.mnt);
		got_write = false;
	}

	error = follow_managed(&path, nd);
	if (unlikely(error < 0))
		return error;

	
	audit_inode(nd->name, path.dentry, 0);

	if (unlikely((open_flag & (O_EXCL | O_CREAT)) == (O_EXCL | O_CREAT))) {
		path_to_nameidata(&path, nd);
		return -EEXIST;
	}

	seq = 0;	
	inode = d_backing_inode(path.dentry);
finish_lookup:
	error = step_into(nd, &path, 0, inode, seq);
	if (unlikely(error))
		return error;
finish_open:
	
	error = complete_walk(nd);
	if (error)
		return error;
	audit_inode(nd->name, nd->path.dentry, 0);
	if (open_flag & O_CREAT) {
		error = -EISDIR;
		if (d_is_dir(nd->path.dentry))
			goto out;
		error = may_create_in_sticky(dir, d_backing_inode(nd->path.dentry));
		if (unlikely(error))
			goto out;
	}
	error = -ENOTDIR;
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		goto out;
	if (!d_is_reg(nd->path.dentry))
		will_truncate = false;

	if (will_truncate) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			goto out;
		got_write = true;
	}
finish_open_created:
	error = may_open(&nd->path, acc_mode, open_flag);
	if (error)
		goto out;
	BUG_ON(file->f_mode & FMODE_OPENED); 
	error = vfs_open(&nd->path, file);
	if (error)
		goto out;
opened:
	error = ima_file_check(file, op->acc_mode);
	if (!error && will_truncate)
		error = handle_truncate(file);
out:
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (got_write)
		mnt_drop_write(nd->path.mnt);
	return error;
}

struct dentry *vfs_tmpfile(struct dentry *dentry, umode_t mode, int open_flag)
{
	struct dentry *child = NULL;
	struct inode *dir = dentry->d_inode;
	struct inode *inode;
	int error;

	
	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_err;
	error = -EOPNOTSUPP;
	if (!dir->i_op->tmpfile)
		goto out_err;
	error = -ENOMEM;
	child = d_alloc(dentry, &slash_name);
	if (unlikely(!child))
		goto out_err;
	error = dir->i_op->tmpfile(dir, child, mode);
	if (error)
		goto out_err;
	error = -ENOENT;
	inode = child->d_inode;
	if (unlikely(!inode))
		goto out_err;
	if (!(open_flag & O_EXCL)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	ima_post_create_tmpfile(inode);
	return child;

out_err:
	dput(child);
	return ERR_PTR(error);
}
EXPORT_SYMBOL(vfs_tmpfile);

static int do_tmpfile(struct nameidata *nd, unsigned flags, const struct open_flags *op, struct file *file)

{
	struct dentry *child;
	struct path path;
	int error = path_lookupat(nd, flags | LOOKUP_DIRECTORY, &path);
	if (unlikely(error))
		return error;
	error = mnt_want_write(path.mnt);
	if (unlikely(error))
		goto out;
	child = vfs_tmpfile(path.dentry, op->mode, op->open_flag);
	error = PTR_ERR(child);
	if (IS_ERR(child))
		goto out2;
	dput(path.dentry);
	path.dentry = child;
	audit_inode(nd->name, child, 0);
	
	error = may_open(&path, 0, op->open_flag);
	if (error)
		goto out2;
	file->f_path.mnt = path.mnt;
	error = finish_open(file, child, NULL);
out2:
	mnt_drop_write(path.mnt);
out:
	path_put(&path);
	return error;
}

static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)
{
	struct path path;
	int error = path_lookupat(nd, flags, &path);
	if (!error) {
		audit_inode(nd->name, path.dentry, 0);
		error = vfs_open(&path, file);
		path_put(&path);
	}
	return error;
}

static struct file *path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags)
{
	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		const char *s = path_init(nd, flags);
		while (!(error = link_path_walk(s, nd)) && (error = do_last(nd, file, op)) > 0) {
			nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
			s = trailing_symlink(nd);
		}
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else error = -ESTALE;
	}
	return ERR_PTR(error);
}

struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}

struct file *do_file_open_root(struct dentry *dentry, struct vfsmount *mnt, const char *name, const struct open_flags *op)
{
	struct nameidata nd;
	struct file *file;
	struct filename *filename;
	int flags = op->lookup_flags | LOOKUP_ROOT;

	nd.root.mnt = mnt;
	nd.root.dentry = dentry;

	if (d_is_symlink(dentry) && op->intent & LOOKUP_OPEN)
		return ERR_PTR(-ELOOP);

	filename = getname_kernel(name);
	if (IS_ERR(filename))
		return ERR_CAST(filename);

	set_nameidata(&nd, -1, filename);
	file = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(file == ERR_PTR(-ECHILD)))
		file = path_openat(&nd, op, flags);
	if (unlikely(file == ERR_PTR(-ESTALE)))
		file = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	putname(filename);
	return file;
}

static struct dentry *filename_create(int dfd, struct filename *name, struct path *path, unsigned int lookup_flags)
{
	struct dentry *dentry = ERR_PTR(-EEXIST);
	struct qstr last;
	int type;
	int err2;
	int error;
	bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

	
	lookup_flags &= LOOKUP_REVAL;

	name = filename_parentat(dfd, name, lookup_flags, path, &last, &type);
	if (IS_ERR(name))
		return ERR_CAST(name);

	
	if (unlikely(type != LAST_NORM))
		goto out;

	
	err2 = mnt_want_write(path->mnt);
	
	lookup_flags |= LOOKUP_CREATE | LOOKUP_EXCL;
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path->dentry, lookup_flags);
	if (IS_ERR(dentry))
		goto unlock;

	error = -EEXIST;
	if (d_is_positive(dentry))
		goto fail;

	
	if (unlikely(!is_dir && last.name[last.len])) {
		error = -ENOENT;
		goto fail;
	}
	if (unlikely(err2)) {
		error = err2;
		goto fail;
	}
	putname(name);
	return dentry;
fail:
	dput(dentry);
	dentry = ERR_PTR(error);
unlock:
	inode_unlock(path->dentry->d_inode);
	if (!err2)
		mnt_drop_write(path->mnt);
out:
	path_put(path);
	putname(name);
	return dentry;
}

struct dentry *kern_path_create(int dfd, const char *pathname, struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname_kernel(pathname), path, lookup_flags);
}
EXPORT_SYMBOL(kern_path_create);

void done_path_create(struct path *path, struct dentry *dentry)
{
	dput(dentry);
	inode_unlock(path->dentry->d_inode);
	mnt_drop_write(path->mnt);
	path_put(path);
}
EXPORT_SYMBOL(done_path_create);

inline struct dentry *user_path_create(int dfd, const char __user *pathname, struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname(pathname), path, lookup_flags);
}
EXPORT_SYMBOL(user_path_create);

int vfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if ((S_ISCHR(mode) || S_ISBLK(mode)) && !capable(CAP_MKNOD))
		return -EPERM;

	if (!dir->i_op->mknod)
		return -EPERM;

	error = devcgroup_inode_mknod(mode, dev);
	if (error)
		return error;

	error = security_inode_mknod(dir, dentry, mode, dev);
	if (error)
		return error;

	error = dir->i_op->mknod(dir, dentry, mode, dev);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mknod);

static int may_mknod(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
	case 0: 
		return 0;
	case S_IFDIR:
		return -EPERM;
	default:
		return -EINVAL;
	}
}

long do_mknodat(int dfd, const char __user *filename, umode_t mode, unsigned int dev)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = 0;

	error = may_mknod(mode);
	if (error)
		return error;
retry:
	dentry = user_path_create(dfd, filename, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mknod(&path, dentry, mode, dev);
	if (error)
		goto out;
	switch (mode & S_IFMT) {
		case 0: case S_IFREG:
			error = vfs_create(path.dentry->d_inode,dentry,mode,true);
			if (!error)
				ima_post_path_mknod(dentry);
			break;
		case S_IFCHR: case S_IFBLK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode, new_decode_dev(dev));
			break;
		case S_IFIFO: case S_IFSOCK:
			error = vfs_mknod(path.dentry->d_inode,dentry,mode,0);
			break;
	}
out:
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE4(mknodat, int, dfd, const char __user *, filename, umode_t, mode, unsigned int, dev)
{
	return do_mknodat(dfd, filename, mode, dev);
}

SYSCALL_DEFINE3(mknod, const char __user *, filename, umode_t, mode, unsigned, dev)
{
	return do_mknodat(AT_FDCWD, filename, mode, dev);
}

int vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int error = may_create(dir, dentry);
	unsigned max_links = dir->i_sb->s_max_links;

	if (error)
		return error;

	if (!dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	if (max_links && dir->i_nlink >= max_links)
		return -EMLINK;

	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error)
		fsnotify_mkdir(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_mkdir);

long do_mkdirat(int dfd, const char __user *pathname, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
{
	return do_mkdirat(dfd, pathname, mode);
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	return do_mkdirat(AT_FDCWD, pathname, mode);
}

int vfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error = may_delete(dir, dentry, 1);

	if (error)
		return error;

	if (!dir->i_op->rmdir)
		return -EPERM;

	dget(dentry);
	inode_lock(dentry->d_inode);

	error = -EBUSY;
	if (is_local_mountpoint(dentry))
		goto out;

	error = security_inode_rmdir(dir, dentry);
	if (error)
		goto out;

	error = dir->i_op->rmdir(dir, dentry);
	if (error)
		goto out;

	shrink_dcache_parent(dentry);
	dentry->d_inode->i_flags |= S_DEAD;
	dont_mount(dentry);
	detach_mounts(dentry);
	fsnotify_rmdir(dir, dentry);

out:
	inode_unlock(dentry->d_inode);
	dput(dentry);
	if (!error)
		d_delete(dentry);
	return error;
}
EXPORT_SYMBOL(vfs_rmdir);

long do_rmdir(int dfd, const char __user *pathname)
{
	int error = 0;
	struct filename *name;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	unsigned int lookup_flags = 0;
retry:
	name = filename_parentat(dfd, getname(pathname), lookup_flags, &path, &last, &type);
	if (IS_ERR(name))
		return PTR_ERR(name);

	switch (type) {
	case LAST_DOTDOT:
		error = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		error = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		error = -EBUSY;
		goto exit1;
	}

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;

	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto exit2;
	if (!dentry->d_inode) {
		error = -ENOENT;
		goto exit3;
	}
	error = security_path_rmdir(&path, dentry);
	if (error)
		goto exit3;
	error = vfs_rmdir(path.dentry->d_inode, dentry);
exit3:
	dput(dentry);
exit2:
	inode_unlock(path.dentry->d_inode);
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	putname(name);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	return do_rmdir(AT_FDCWD, pathname);
}


int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
{
	struct inode *target = dentry->d_inode;
	int error = may_delete(dir, dentry, 0);

	if (error)
		return error;

	if (!dir->i_op->unlink)
		return -EPERM;

	inode_lock(target);
	if (is_local_mountpoint(dentry))
		error = -EBUSY;
	else {
		error = security_inode_unlink(dir, dentry);
		if (!error) {
			error = try_break_deleg(target, delegated_inode);
			if (error)
				goto out;
			error = dir->i_op->unlink(dir, dentry);
			if (!error) {
				dont_mount(dentry);
				detach_mounts(dentry);
				fsnotify_unlink(dir, dentry);
			}
		}
	}
out:
	inode_unlock(target);

	
	if (!error && !(dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		fsnotify_link_count(target);
		d_delete(dentry);
	}

	return error;
}
EXPORT_SYMBOL(vfs_unlink);


long do_unlinkat(int dfd, struct filename *name)
{
	int error;
	struct dentry *dentry;
	struct path path;
	struct qstr last;
	int type;
	struct inode *inode = NULL;
	struct inode *delegated_inode = NULL;
	unsigned int lookup_flags = 0;
retry:
	name = filename_parentat(dfd, name, lookup_flags, &path, &last, &type);
	if (IS_ERR(name))
		return PTR_ERR(name);

	error = -EISDIR;
	if (type != LAST_NORM)
		goto exit1;

	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;
retry_deleg:
	inode_lock_nested(path.dentry->d_inode, I_MUTEX_PARENT);
	dentry = __lookup_hash(&last, path.dentry, lookup_flags);
	error = PTR_ERR(dentry);
	if (!IS_ERR(dentry)) {
		
		if (last.name[last.len])
			goto slashes;
		inode = dentry->d_inode;
		if (d_is_negative(dentry))
			goto slashes;
		ihold(inode);
		error = security_path_unlink(&path, dentry);
		if (error)
			goto exit2;
		error = vfs_unlink(path.dentry->d_inode, dentry, &delegated_inode);
exit2:
		dput(dentry);
	}
	inode_unlock(path.dentry->d_inode);
	if (inode)
		iput(inode);	
	inode = NULL;
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(path.mnt);
exit1:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		inode = NULL;
		goto retry;
	}
	putname(name);
	return error;

slashes:
	if (d_is_negative(dentry))
		error = -ENOENT;
	else if (d_is_dir(dentry))
		error = -EISDIR;
	else error = -ENOTDIR;
	goto exit2;
}

SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	if ((flag & ~AT_REMOVEDIR) != 0)
		return -EINVAL;

	if (flag & AT_REMOVEDIR)
		return do_rmdir(dfd, pathname);

	return do_unlinkat(dfd, getname(pathname));
}

SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	return do_unlinkat(AT_FDCWD, getname(pathname));
}

int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname)
{
	int error = may_create(dir, dentry);

	if (error)
		return error;

	if (!dir->i_op->symlink)
		return -EPERM;

	error = security_inode_symlink(dir, dentry, oldname);
	if (error)
		return error;

	error = dir->i_op->symlink(dir, dentry, oldname);
	if (!error)
		fsnotify_create(dir, dentry);
	return error;
}
EXPORT_SYMBOL(vfs_symlink);

long do_symlinkat(const char __user *oldname, int newdfd, const char __user *newname)
{
	int error;
	struct filename *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	from = getname(oldname);
	if (IS_ERR(from))
		return PTR_ERR(from);
retry:
	dentry = user_path_create(newdfd, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

	error = security_path_symlink(&path, dentry, from->name);
	if (!error)
		error = vfs_symlink(path.dentry->d_inode, dentry, from->name);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out_putname:
	putname(from);
	return error;
}

SYSCALL_DEFINE3(symlinkat, const char __user *, oldname, int, newdfd, const char __user *, newname)
{
	return do_symlinkat(oldname, newdfd, newname);
}

SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
{
	return do_symlinkat(oldname, AT_FDCWD, newname);
}


int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry, struct inode **delegated_inode)
{
	struct inode *inode = old_dentry->d_inode;
	unsigned max_links = dir->i_sb->s_max_links;
	int error;

	if (!inode)
		return -ENOENT;

	error = may_create(dir, new_dentry);
	if (error)
		return error;

	if (dir->i_sb != inode->i_sb)
		return -EXDEV;

	
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;
	
	if (HAS_UNMAPPED_ID(inode))
		return -EPERM;
	if (!dir->i_op->link)
		return -EPERM;
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = security_inode_link(old_dentry, dir, new_dentry);
	if (error)
		return error;

	inode_lock(inode);
	
	if (inode->i_nlink == 0 && !(inode->i_state & I_LINKABLE))
		error =  -ENOENT;
	else if (max_links && inode->i_nlink >= max_links)
		error = -EMLINK;
	else {
		error = try_break_deleg(inode, delegated_inode);
		if (!error)
			error = dir->i_op->link(old_dentry, dir, new_dentry);
	}

	if (!error && (inode->i_state & I_LINKABLE)) {
		spin_lock(&inode->i_lock);
		inode->i_state &= ~I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	inode_unlock(inode);
	if (!error)
		fsnotify_link(dir, inode, new_dentry);
	return error;
}
EXPORT_SYMBOL(vfs_link);


int do_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
{
	struct dentry *new_dentry;
	struct path old_path, new_path;
	struct inode *delegated_inode = NULL;
	int how = 0;
	int error;

	if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	
	if (flags & AT_EMPTY_PATH) {
		if (!capable(CAP_DAC_READ_SEARCH))
			return -ENOENT;
		how = LOOKUP_EMPTY;
	}

	if (flags & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;
retry:
	error = user_path_at(olddfd, oldname, how, &old_path);
	if (error)
		return error;

	new_dentry = user_path_create(newdfd, newname, &new_path, (how & LOOKUP_REVAL));
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto out_dput;
	error = may_linkat(&old_path);
	if (unlikely(error))
		goto out_dput;
	error = security_path_link(old_path.dentry, &new_path, new_dentry);
	if (error)
		goto out_dput;
	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry, &delegated_inode);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error) {
			path_put(&old_path);
			goto retry;
		}
	}
	if (retry_estale(error, how)) {
		path_put(&old_path);
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);

	return error;
}

SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, int, flags)
{
	return do_linkat(olddfd, oldname, newdfd, newname, flags);
}

SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
{
	return do_linkat(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}


int vfs_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, struct inode **delegated_inode, unsigned int flags)

{
	int error;
	bool is_dir = d_is_dir(old_dentry);
	struct inode *source = old_dentry->d_inode;
	struct inode *target = new_dentry->d_inode;
	bool new_is_dir = false;
	unsigned max_links = new_dir->i_sb->s_max_links;
	struct name_snapshot old_name;

	if (source == target)
		return 0;

	error = may_delete(old_dir, old_dentry, is_dir);
	if (error)
		return error;

	if (!target) {
		error = may_create(new_dir, new_dentry);
	} else {
		new_is_dir = d_is_dir(new_dentry);

		if (!(flags & RENAME_EXCHANGE))
			error = may_delete(new_dir, new_dentry, is_dir);
		else error = may_delete(new_dir, new_dentry, new_is_dir);
	}
	if (error)
		return error;

	if (!old_dir->i_op->rename)
		return -EPERM;

	
	if (new_dir != old_dir) {
		if (is_dir) {
			error = inode_permission(source, MAY_WRITE);
			if (error)
				return error;
		}
		if ((flags & RENAME_EXCHANGE) && new_is_dir) {
			error = inode_permission(target, MAY_WRITE);
			if (error)
				return error;
		}
	}

	error = security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
	if (error)
		return error;

	take_dentry_name_snapshot(&old_name, old_dentry);
	dget(new_dentry);
	if (!is_dir || (flags & RENAME_EXCHANGE))
		lock_two_nondirectories(source, target);
	else if (target)
		inode_lock(target);

	error = -EBUSY;
	if (is_local_mountpoint(old_dentry) || is_local_mountpoint(new_dentry))
		goto out;

	if (max_links && new_dir != old_dir) {
		error = -EMLINK;
		if (is_dir && !new_is_dir && new_dir->i_nlink >= max_links)
			goto out;
		if ((flags & RENAME_EXCHANGE) && !is_dir && new_is_dir && old_dir->i_nlink >= max_links)
			goto out;
	}
	if (!is_dir) {
		error = try_break_deleg(source, delegated_inode);
		if (error)
			goto out;
	}
	if (target && !new_is_dir) {
		error = try_break_deleg(target, delegated_inode);
		if (error)
			goto out;
	}
	error = old_dir->i_op->rename(old_dir, old_dentry, new_dir, new_dentry, flags);
	if (error)
		goto out;

	if (!(flags & RENAME_EXCHANGE) && target) {
		if (is_dir) {
			shrink_dcache_parent(new_dentry);
			target->i_flags |= S_DEAD;
		}
		dont_mount(new_dentry);
		detach_mounts(new_dentry);
	}
	if (!(old_dir->i_sb->s_type->fs_flags & FS_RENAME_DOES_D_MOVE)) {
		if (!(flags & RENAME_EXCHANGE))
			d_move(old_dentry, new_dentry);
		else d_exchange(old_dentry, new_dentry);
	}
out:
	if (!is_dir || (flags & RENAME_EXCHANGE))
		unlock_two_nondirectories(source, target);
	else if (target)
		inode_unlock(target);
	dput(new_dentry);
	if (!error) {
		fsnotify_move(old_dir, new_dir, &old_name.name, is_dir, !(flags & RENAME_EXCHANGE) ? target : NULL, old_dentry);
		if (flags & RENAME_EXCHANGE) {
			fsnotify_move(new_dir, old_dir, &old_dentry->d_name, new_is_dir, NULL, new_dentry);
		}
	}
	release_dentry_name_snapshot(&old_name);

	return error;
}
EXPORT_SYMBOL(vfs_rename);

static int do_renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags)
{
	struct dentry *old_dentry, *new_dentry;
	struct dentry *trap;
	struct path old_path, new_path;
	struct qstr old_last, new_last;
	int old_type, new_type;
	struct inode *delegated_inode = NULL;
	struct filename *from;
	struct filename *to;
	unsigned int lookup_flags = 0, target_flags = LOOKUP_RENAME_TARGET;
	bool should_retry = false;
	int error;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	if ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) && (flags & RENAME_EXCHANGE))
		return -EINVAL;

	if ((flags & RENAME_WHITEOUT) && !capable(CAP_MKNOD))
		return -EPERM;

	if (flags & RENAME_EXCHANGE)
		target_flags = 0;

retry:
	from = filename_parentat(olddfd, getname(oldname), lookup_flags, &old_path, &old_last, &old_type);
	if (IS_ERR(from)) {
		error = PTR_ERR(from);
		goto exit;
	}

	to = filename_parentat(newdfd, getname(newname), lookup_flags, &new_path, &new_last, &new_type);
	if (IS_ERR(to)) {
		error = PTR_ERR(to);
		goto exit1;
	}

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto exit2;

	error = -EBUSY;
	if (old_type != LAST_NORM)
		goto exit2;

	if (flags & RENAME_NOREPLACE)
		error = -EEXIST;
	if (new_type != LAST_NORM)
		goto exit2;

	error = mnt_want_write(old_path.mnt);
	if (error)
		goto exit2;

retry_deleg:
	trap = lock_rename(new_path.dentry, old_path.dentry);

	old_dentry = __lookup_hash(&old_last, old_path.dentry, lookup_flags);
	error = PTR_ERR(old_dentry);
	if (IS_ERR(old_dentry))
		goto exit3;
	
	error = -ENOENT;
	if (d_is_negative(old_dentry))
		goto exit4;
	new_dentry = __lookup_hash(&new_last, new_path.dentry, lookup_flags | target_flags);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto exit4;
	error = -EEXIST;
	if ((flags & RENAME_NOREPLACE) && d_is_positive(new_dentry))
		goto exit5;
	if (flags & RENAME_EXCHANGE) {
		error = -ENOENT;
		if (d_is_negative(new_dentry))
			goto exit5;

		if (!d_is_dir(new_dentry)) {
			error = -ENOTDIR;
			if (new_last.name[new_last.len])
				goto exit5;
		}
	}
	
	if (!d_is_dir(old_dentry)) {
		error = -ENOTDIR;
		if (old_last.name[old_last.len])
			goto exit5;
		if (!(flags & RENAME_EXCHANGE) && new_last.name[new_last.len])
			goto exit5;
	}
	
	error = -EINVAL;
	if (old_dentry == trap)
		goto exit5;
	
	if (!(flags & RENAME_EXCHANGE))
		error = -ENOTEMPTY;
	if (new_dentry == trap)
		goto exit5;

	error = security_path_rename(&old_path, old_dentry, &new_path, new_dentry, flags);
	if (error)
		goto exit5;
	error = vfs_rename(old_path.dentry->d_inode, old_dentry, new_path.dentry->d_inode, new_dentry, &delegated_inode, flags);

exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_path.dentry, old_path.dentry);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(old_path.mnt);
exit2:
	if (retry_estale(error, lookup_flags))
		should_retry = true;
	path_put(&new_path);
	putname(to);
exit1:
	path_put(&old_path);
	putname(from);
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
exit:
	return error;
}

SYSCALL_DEFINE5(renameat2, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname, unsigned int, flags)
{
	return do_renameat2(olddfd, oldname, newdfd, newname, flags);
}

SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname, int, newdfd, const char __user *, newname)
{
	return do_renameat2(olddfd, oldname, newdfd, newname, 0);
}

SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname)
{
	return do_renameat2(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
}

int vfs_whiteout(struct inode *dir, struct dentry *dentry)
{
	int error = may_create(dir, dentry);
	if (error)
		return error;

	if (!dir->i_op->mknod)
		return -EPERM;

	return dir->i_op->mknod(dir, dentry, S_IFCHR | WHITEOUT_MODE, WHITEOUT_DEV);
}
EXPORT_SYMBOL(vfs_whiteout);

int readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}


int vfs_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = d_inode(dentry);
	DEFINE_DELAYED_CALL(done);
	const char *link;
	int res;

	if (unlikely(!(inode->i_opflags & IOP_DEFAULT_READLINK))) {
		if (unlikely(inode->i_op->readlink))
			return inode->i_op->readlink(dentry, buffer, buflen);

		if (!d_is_symlink(dentry))
			return -EINVAL;

		spin_lock(&inode->i_lock);
		inode->i_opflags |= IOP_DEFAULT_READLINK;
		spin_unlock(&inode->i_lock);
	}

	link = READ_ONCE(inode->i_link);
	if (!link) {
		link = inode->i_op->get_link(dentry, inode, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	res = readlink_copy(buffer, buflen, link);
	do_delayed_call(&done);
	return res;
}
EXPORT_SYMBOL(vfs_readlink);


const char *vfs_get_link(struct dentry *dentry, struct delayed_call *done)
{
	const char *res = ERR_PTR(-EINVAL);
	struct inode *inode = d_inode(dentry);

	if (d_is_symlink(dentry)) {
		res = ERR_PTR(security_inode_readlink(dentry));
		if (!res)
			res = inode->i_op->get_link(dentry, inode, done);
	}
	return res;
}
EXPORT_SYMBOL(vfs_get_link);


const char *page_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *callback)
{
	char *kaddr;
	struct page *page;
	struct address_space *mapping = inode->i_mapping;

	if (!dentry) {
		page = find_get_page(mapping, 0);
		if (!page)
			return ERR_PTR(-ECHILD);
		if (!PageUptodate(page)) {
			put_page(page);
			return ERR_PTR(-ECHILD);
		}
	} else {
		page = read_mapping_page(mapping, 0, NULL);
		if (IS_ERR(page))
			return (char*)page;
	}
	set_delayed_call(callback, page_put_link, page);
	BUG_ON(mapping_gfp_mask(mapping) & __GFP_HIGHMEM);
	kaddr = page_address(page);
	nd_terminate_link(kaddr, inode->i_size, PAGE_SIZE - 1);
	return kaddr;
}

EXPORT_SYMBOL(page_get_link);

void page_put_link(void *arg)
{
	put_page(arg);
}
EXPORT_SYMBOL(page_put_link);

int page_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	DEFINE_DELAYED_CALL(done);
	int res = readlink_copy(buffer, buflen, page_get_link(dentry, d_inode(dentry), &done));

	do_delayed_call(&done);
	return res;
}
EXPORT_SYMBOL(page_readlink);


int __page_symlink(struct inode *inode, const char *symname, int len, int nofs)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;
	unsigned int flags = 0;
	if (nofs)
		flags |= AOP_FLAG_NOFS;

retry:
	err = pagecache_write_begin(NULL, mapping, 0, len-1, flags, &page, &fsdata);
	if (err)
		goto fail;

	memcpy(page_address(page), symname, len-1);

	err = pagecache_write_end(NULL, mapping, 0, len-1, len-1, page, fsdata);
	if (err < 0)
		goto fail;
	if (err < len-1)
		goto retry;

	mark_inode_dirty(inode);
	return 0;
fail:
	return err;
}
EXPORT_SYMBOL(__page_symlink);

int page_symlink(struct inode *inode, const char *symname, int len)
{
	return __page_symlink(inode, symname, len, !mapping_gfp_constraint(inode->i_mapping, __GFP_FS));
}
EXPORT_SYMBOL(page_symlink);

const struct inode_operations page_symlink_inode_operations = {
	.get_link	= page_get_link, };
EXPORT_SYMBOL(page_symlink_inode_operations);
