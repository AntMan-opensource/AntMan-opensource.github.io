
































bool vt_dont_switch;

static inline bool vt_in_use(unsigned int i)
{
	const struct vc_data *vc = vc_cons[i].d;

	
	WARN_CONSOLE_UNLOCKED();

	return vc && kref_read(&vc->port.kref) > 1;
}

static inline bool vt_busy(int i)
{
	if (vt_in_use(i))
		return true;
	if (i == fg_console)
		return true;
	if (vc_is_sel(vc_cons[i].d))
		return true;

	return false;
}







static void complete_change_console(struct vc_data *vc);



struct vt_event_wait {
	struct list_head list;
	struct vt_event event;
	int done;
};

static LIST_HEAD(vt_events);
static DEFINE_SPINLOCK(vt_event_lock);
static DECLARE_WAIT_QUEUE_HEAD(vt_event_waitqueue);



void vt_event_post(unsigned int event, unsigned int old, unsigned int new)
{
	struct list_head *pos, *head;
	unsigned long flags;
	int wake = 0;

	spin_lock_irqsave(&vt_event_lock, flags);
	head = &vt_events;

	list_for_each(pos, head) {
		struct vt_event_wait *ve = list_entry(pos, struct vt_event_wait, list);
		if (!(ve->event.event & event))
			continue;
		ve->event.event = event;
		
		ve->event.oldev = old + 1;
		ve->event.newev = new + 1;
		wake = 1;
		ve->done = 1;
	}
	spin_unlock_irqrestore(&vt_event_lock, flags);
	if (wake)
		wake_up_interruptible(&vt_event_waitqueue);
}

static void __vt_event_queue(struct vt_event_wait *vw)
{
	unsigned long flags;
	
	INIT_LIST_HEAD(&vw->list);
	vw->done = 0;
	
	spin_lock_irqsave(&vt_event_lock, flags);
	list_add(&vw->list, &vt_events);
	spin_unlock_irqrestore(&vt_event_lock, flags);
}

static void __vt_event_wait(struct vt_event_wait *vw)
{
	
	wait_event_interruptible(vt_event_waitqueue, vw->done);
}

static void __vt_event_dequeue(struct vt_event_wait *vw)
{
	unsigned long flags;

	
	spin_lock_irqsave(&vt_event_lock, flags);
	list_del(&vw->list);
	spin_unlock_irqrestore(&vt_event_lock, flags);
}



static void vt_event_wait(struct vt_event_wait *vw)
{
	__vt_event_queue(vw);
	__vt_event_wait(vw);
	__vt_event_dequeue(vw);
}



static int vt_event_wait_ioctl(struct vt_event __user *event)
{
	struct vt_event_wait vw;

	if (copy_from_user(&vw.event, event, sizeof(struct vt_event)))
		return -EFAULT;
	
	if (vw.event.event & ~VT_MAX_EVENT)
		return -EINVAL;

	vt_event_wait(&vw);
	
	if (vw.done) {
		if (copy_to_user(event, &vw.event, sizeof(struct vt_event)))
			return -EFAULT;
		return 0;
	}
	return -EINTR;
}



int vt_waitactive(int n)
{
	struct vt_event_wait vw;
	do {
		vw.event.event = VT_EVENT_SWITCH;
		__vt_event_queue(&vw);
		if (n == fg_console + 1) {
			__vt_event_dequeue(&vw);
			break;
		}
		__vt_event_wait(&vw);
		__vt_event_dequeue(&vw);
		if (vw.done == 0)
			return -EINTR;
	} while (vw.event.newev != n);
	return 0;
}







static int vt_kdsetmode(struct vc_data *vc, unsigned long mode)
{
	switch (mode) {
	case KD_GRAPHICS:
		break;
	case KD_TEXT0:
	case KD_TEXT1:
		mode = KD_TEXT;
		fallthrough;
	case KD_TEXT:
		break;
	default:
		return -EINVAL;
	}

	
	if (vc->vc_mode == mode)
		return 0;

	vc->vc_mode = mode;
	if (vc->vc_num != fg_console)
		return 0;

	
	console_lock();
	if (mode == KD_TEXT)
		do_unblank_screen(1);
	else do_blank_screen(1);
	console_unlock();

	return 0;
}

static int vt_k_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg, bool perm)
{
	struct vc_data *vc = tty->driver_data;
	void __user *up = (void __user *)arg;
	unsigned int console = vc->vc_num;
	int ret;

	switch (cmd) {
	case KIOCSOUND:
		if (!perm)
			return -EPERM;
		
		if (arg)
			arg = PIT_TICK_RATE / arg;
		kd_mksound(arg, 0);
		break;

	case KDMKTONE:
		if (!perm)
			return -EPERM;
	{
		unsigned int ticks, count;

		
		ticks = msecs_to_jiffies((arg >> 16) & 0xffff);
		count = ticks ? (arg & 0xffff) : 0;
		if (count)
			count = PIT_TICK_RATE / count;
		kd_mksound(count, ticks);
		break;
	}

	case KDGKBTYPE:
		
		return put_user(KB_101, (char __user *)arg);

		

	case KDADDIO:
	case KDDELIO:
		
		if (arg < GPFIRST || arg > GPLAST)
			return -EINVAL;

		return ksys_ioperm(arg, 1, (cmd == KDADDIO)) ? -ENXIO : 0;

	case KDENABIO:
	case KDDISABIO:
		return ksys_ioperm(GPFIRST, GPNUM, (cmd == KDENABIO)) ? -ENXIO : 0;


	

	case KDKBDREP:
	{
		struct kbd_repeat kbrep;

		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;

		if (copy_from_user(&kbrep, up, sizeof(struct kbd_repeat)))
			return -EFAULT;

		ret = kbd_rate(&kbrep);
		if (ret)
			return ret;
		if (copy_to_user(up, &kbrep, sizeof(struct kbd_repeat)))
			return -EFAULT;
		break;
	}

	case KDSETMODE:
		if (!perm)
			return -EPERM;

		return vt_kdsetmode(vc, arg);

	case KDGETMODE:
		return put_user(vc->vc_mode, (int __user *)arg);

	case KDMAPDISP:
	case KDUNMAPDISP:
		
		return -EINVAL;

	case KDSKBMODE:
		if (!perm)
			return -EPERM;
		ret = vt_do_kdskbmode(console, arg);
		if (ret)
			return ret;
		tty_ldisc_flush(tty);
		break;

	case KDGKBMODE:
		return put_user(vt_do_kdgkbmode(console), (int __user *)arg);

	
	case KDSKBMETA:
		return vt_do_kdskbmeta(console, arg);

	case KDGKBMETA:
		
		return put_user(vt_do_kdgkbmeta(console), (int __user *)arg);

	case KDGETKEYCODE:
	case KDSETKEYCODE:
		if(!capable(CAP_SYS_TTY_CONFIG))
			perm = 0;
		return vt_do_kbkeycode_ioctl(cmd, up, perm);

	case KDGKBENT:
	case KDSKBENT:
		return vt_do_kdsk_ioctl(cmd, up, perm, console);

	case KDGKBSENT:
	case KDSKBSENT:
		return vt_do_kdgkb_ioctl(cmd, up, perm);

	
	case KDGKBDIACR:
	case KDGKBDIACRUC:
	case KDSKBDIACR:
	case KDSKBDIACRUC:
		return vt_do_diacrit(cmd, up, perm);

	
	
	case KDGKBLED:
	case KDSKBLED:
	case KDGETLED:
	case KDSETLED:
		return vt_do_kdskled(console, cmd, arg, perm);

	
	case KDSIGACCEPT:
		if (!perm || !capable(CAP_KILL))
			return -EPERM;
		if (!valid_signal(arg) || arg < 1 || arg == SIGKILL)
			return -EINVAL;

		spin_lock_irq(&vt_spawn_con.lock);
		put_pid(vt_spawn_con.pid);
		vt_spawn_con.pid = get_pid(task_pid(current));
		vt_spawn_con.sig = arg;
		spin_unlock_irq(&vt_spawn_con.lock);
		break;

	case KDFONTOP: {
		struct console_font_op op;

		if (copy_from_user(&op, up, sizeof(op)))
			return -EFAULT;
		if (!perm && op.op != KD_FONT_OP_GET)
			return -EPERM;
		ret = con_font_op(vc, &op);
		if (ret)
			return ret;
		if (copy_to_user(up, &op, sizeof(op)))
			return -EFAULT;
		break;
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static inline int do_unimap_ioctl(int cmd, struct unimapdesc __user *user_ud, bool perm, struct vc_data *vc)
{
	struct unimapdesc tmp;

	if (copy_from_user(&tmp, user_ud, sizeof tmp))
		return -EFAULT;
	switch (cmd) {
	case PIO_UNIMAP:
		if (!perm)
			return -EPERM;
		return con_set_unimap(vc, tmp.entry_ct, tmp.entries);
	case GIO_UNIMAP:
		if (!perm && fg_console != vc->vc_num)
			return -EPERM;
		return con_get_unimap(vc, tmp.entry_ct, &(user_ud->entry_ct), tmp.entries);
	}
	return 0;
}

static int vt_io_ioctl(struct vc_data *vc, unsigned int cmd, void __user *up, bool perm)
{
	switch (cmd) {
	case PIO_CMAP:
		if (!perm)
			return -EPERM;
		return con_set_cmap(up);

	case GIO_CMAP:
		return con_get_cmap(up);

	case PIO_SCRNMAP:
		if (!perm)
			return -EPERM;
		return con_set_trans_old(up);

	case GIO_SCRNMAP:
		return con_get_trans_old(up);

	case PIO_UNISCRNMAP:
		if (!perm)
			return -EPERM;
		return con_set_trans_new(up);

	case GIO_UNISCRNMAP:
		return con_get_trans_new(up);

	case PIO_UNIMAPCLR:
		if (!perm)
			return -EPERM;
		con_clear_unimap(vc);
		break;

	case PIO_UNIMAP:
	case GIO_UNIMAP:
		return do_unimap_ioctl(cmd, up, perm, vc);

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int vt_reldisp(struct vc_data *vc, unsigned int swtch)
{
	int newvt, ret;

	if (vc->vt_mode.mode != VT_PROCESS)
		return -EINVAL;

	
	if (vc->vt_newvt < 0) {
		 
		return swtch == VT_ACKACQ ? 0 : -EINVAL;
	}

	
	if (swtch == 0) {
		
		vc->vt_newvt = -1;
		return 0;
	}

	
	newvt = vc->vt_newvt;
	vc->vt_newvt = -1;
	ret = vc_allocate(newvt);
	if (ret)
		return ret;

	
	complete_change_console(vc_cons[newvt].d);

	return 0;
}

static int vt_setactivate(struct vt_setactivate __user *sa)
{
	struct vt_setactivate vsa;
	struct vc_data *nvc;
	int ret;

	if (copy_from_user(&vsa, sa, sizeof(vsa)))
		return -EFAULT;
	if (vsa.console == 0 || vsa.console > MAX_NR_CONSOLES)
		return -ENXIO;

	vsa.console = array_index_nospec(vsa.console, MAX_NR_CONSOLES + 1);
	vsa.console--;
	console_lock();
	ret = vc_allocate(vsa.console);
	if (ret) {
		console_unlock();
		return ret;
	}

	
	nvc = vc_cons[vsa.console].d;
	nvc->vt_mode = vsa.mode;
	nvc->vt_mode.frsig = 0;
	put_pid(nvc->vt_pid);
	nvc->vt_pid = get_pid(task_pid(current));
	console_unlock();

	
	
	set_console(vsa.console);

	return 0;
}


static int vt_disallocate(unsigned int vc_num)
{
	struct vc_data *vc = NULL;
	int ret = 0;

	console_lock();
	if (vt_busy(vc_num))
		ret = -EBUSY;
	else if (vc_num)
		vc = vc_deallocate(vc_num);
	console_unlock();

	if (vc && vc_num >= MIN_NR_CONSOLES)
		tty_port_put(&vc->port);

	return ret;
}


static void vt_disallocate_all(void)
{
	struct vc_data *vc[MAX_NR_CONSOLES];
	int i;

	console_lock();
	for (i = 1; i < MAX_NR_CONSOLES; i++)
		if (!vt_busy(i))
			vc[i] = vc_deallocate(i);
		else vc[i] = NULL;
	console_unlock();

	for (i = 1; i < MAX_NR_CONSOLES; i++) {
		if (vc[i] && i >= MIN_NR_CONSOLES)
			tty_port_put(&vc[i]->port);
	}
}

static int vt_resizex(struct vc_data *vc, struct vt_consize __user *cs)
{
	struct vt_consize v;
	int i;

	if (copy_from_user(&v, cs, sizeof(struct vt_consize)))
		return -EFAULT;

	
	if (!v.v_vlin)
		v.v_vlin = vc->vc_scan_lines;

	if (v.v_clin) {
		int rows = v.v_vlin / v.v_clin;
		if (v.v_rows != rows) {
			if (v.v_rows) 
				return -EINVAL;
			v.v_rows = rows;
		}
	}

	if (v.v_vcol && v.v_ccol) {
		int cols = v.v_vcol / v.v_ccol;
		if (v.v_cols != cols) {
			if (v.v_cols)
				return -EINVAL;
			v.v_cols = cols;
		}
	}

	if (v.v_clin > 32)
		return -EINVAL;

	for (i = 0; i < MAX_NR_CONSOLES; i++) {
		struct vc_data *vcp;

		if (!vc_cons[i].d)
			continue;
		console_lock();
		vcp = vc_cons[i].d;
		if (vcp) {
			int ret;
			int save_scan_lines = vcp->vc_scan_lines;
			int save_cell_height = vcp->vc_cell_height;

			if (v.v_vlin)
				vcp->vc_scan_lines = v.v_vlin;
			if (v.v_clin)
				vcp->vc_cell_height = v.v_clin;
			vcp->vc_resize_user = 1;
			ret = vc_resize(vcp, v.v_cols, v.v_rows);
			if (ret) {
				vcp->vc_scan_lines = save_scan_lines;
				vcp->vc_cell_height = save_cell_height;
				console_unlock();
				return ret;
			}
		}
		console_unlock();
	}

	return 0;
}


int vt_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
	struct vc_data *vc = tty->driver_data;
	void __user *up = (void __user *)arg;
	int i, perm;
	int ret;

	
	perm = 0;
	if (current->signal->tty == tty || capable(CAP_SYS_TTY_CONFIG))
		perm = 1;

	ret = vt_k_ioctl(tty, cmd, arg, perm);
	if (ret != -ENOIOCTLCMD)
		return ret;

	ret = vt_io_ioctl(vc, cmd, up, perm);
	if (ret != -ENOIOCTLCMD)
		return ret;

	switch (cmd) {
	case TIOCLINUX:
		return tioclinux(tty, arg);
	case VT_SETMODE:
	{
		struct vt_mode tmp;

		if (!perm)
			return -EPERM;
		if (copy_from_user(&tmp, up, sizeof(struct vt_mode)))
			return -EFAULT;
		if (tmp.mode != VT_AUTO && tmp.mode != VT_PROCESS)
			return -EINVAL;

		console_lock();
		vc->vt_mode = tmp;
		
		vc->vt_mode.frsig = 0;
		put_pid(vc->vt_pid);
		vc->vt_pid = get_pid(task_pid(current));
		
		vc->vt_newvt = -1;
		console_unlock();
		break;
	}

	case VT_GETMODE:
	{
		struct vt_mode tmp;
		int rc;

		console_lock();
		memcpy(&tmp, &vc->vt_mode, sizeof(struct vt_mode));
		console_unlock();

		rc = copy_to_user(up, &tmp, sizeof(struct vt_mode));
		if (rc)
			return -EFAULT;
		break;
	}

	
	case VT_GETSTATE:
	{
		struct vt_stat __user *vtstat = up;
		unsigned short state, mask;

		if (put_user(fg_console + 1, &vtstat->v_active))
			return -EFAULT;

		state = 1;	
		console_lock(); 
		for (i = 0, mask = 2; i < MAX_NR_CONSOLES && mask;
				++i, mask <<= 1)
			if (vt_in_use(i))
				state |= mask;
		console_unlock();
		return put_user(state, &vtstat->v_state);
	}

	
	case VT_OPENQRY:
		console_lock(); 
		for (i = 0; i < MAX_NR_CONSOLES; ++i)
			if (!vt_in_use(i))
				break;
		console_unlock();
		i = i < MAX_NR_CONSOLES ? (i+1) : -1;
		return put_user(i, (int __user *)arg);

	
	case VT_ACTIVATE:
		if (!perm)
			return -EPERM;
		if (arg == 0 || arg > MAX_NR_CONSOLES)
			return -ENXIO;

		arg--;
		console_lock();
		ret = vc_allocate(arg);
		console_unlock();
		if (ret)
			return ret;
		set_console(arg);
		break;

	case VT_SETACTIVATE:
		if (!perm)
			return -EPERM;

		return vt_setactivate(up);

	
	case VT_WAITACTIVE:
		if (!perm)
			return -EPERM;
		if (arg == 0 || arg > MAX_NR_CONSOLES)
			return -ENXIO;
		return vt_waitactive(arg);

	
	case VT_RELDISP:
		if (!perm)
			return -EPERM;

		console_lock();
		ret = vt_reldisp(vc, arg);
		console_unlock();

		return ret;


	 
	 case VT_DISALLOCATE:
		if (arg > MAX_NR_CONSOLES)
			return -ENXIO;

		if (arg == 0)
			vt_disallocate_all();
		else return vt_disallocate(--arg);
		break;

	case VT_RESIZE:
	{
		struct vt_sizes __user *vtsizes = up;
		struct vc_data *vc;
		ushort ll,cc;

		if (!perm)
			return -EPERM;
		if (get_user(ll, &vtsizes->v_rows) || get_user(cc, &vtsizes->v_cols))
			return -EFAULT;

		console_lock();
		for (i = 0; i < MAX_NR_CONSOLES; i++) {
			vc = vc_cons[i].d;

			if (vc) {
				vc->vc_resize_user = 1;
				
				vc_resize(vc_cons[i].d, cc, ll);
			}
		}
		console_unlock();
		break;
	}

	case VT_RESIZEX:
		if (!perm)
			return -EPERM;

		return vt_resizex(vc, up);

	case VT_LOCKSWITCH:
		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;
		vt_dont_switch = true;
		break;
	case VT_UNLOCKSWITCH:
		if (!capable(CAP_SYS_TTY_CONFIG))
			return -EPERM;
		vt_dont_switch = false;
		break;
	case VT_GETHIFONTMASK:
		return put_user(vc->vc_hi_font_mask, (unsigned short __user *)arg);
	case VT_WAITEVENT:
		return vt_event_wait_ioctl((struct vt_event __user *)arg);
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

void reset_vc(struct vc_data *vc)
{
	vc->vc_mode = KD_TEXT;
	vt_reset_unicode(vc->vc_num);
	vc->vt_mode.mode = VT_AUTO;
	vc->vt_mode.waitv = 0;
	vc->vt_mode.relsig = 0;
	vc->vt_mode.acqsig = 0;
	vc->vt_mode.frsig = 0;
	put_pid(vc->vt_pid);
	vc->vt_pid = NULL;
	vc->vt_newvt = -1;
	reset_palette(vc);
}

void vc_SAK(struct work_struct *work)
{
	struct vc *vc_con = container_of(work, struct vc, SAK_work);
	struct vc_data *vc;
	struct tty_struct *tty;

	console_lock();
	vc = vc_con->d;
	if (vc) {
		
		tty = vc->port.tty;
		
		if (tty)
			__do_SAK(tty);
		reset_vc(vc);
	}
	console_unlock();
}



struct compat_console_font_op {
	compat_uint_t op;        
	compat_uint_t flags;     
	compat_uint_t width, height;     
	compat_uint_t charcount;
	compat_caddr_t data;    
};

static inline int compat_kdfontop_ioctl(struct compat_console_font_op __user *fontop, int perm, struct console_font_op *op, struct vc_data *vc)

{
	int i;

	if (copy_from_user(op, fontop, sizeof(struct compat_console_font_op)))
		return -EFAULT;
	if (!perm && op->op != KD_FONT_OP_GET)
		return -EPERM;
	op->data = compat_ptr(((struct compat_console_font_op *)op)->data);
	i = con_font_op(vc, op);
	if (i)
		return i;
	((struct compat_console_font_op *)op)->data = (unsigned long)op->data;
	if (copy_to_user(fontop, op, sizeof(struct compat_console_font_op)))
		return -EFAULT;
	return 0;
}

struct compat_unimapdesc {
	unsigned short entry_ct;
	compat_caddr_t entries;
};

static inline int compat_unimap_ioctl(unsigned int cmd, struct compat_unimapdesc __user *user_ud, int perm, struct vc_data *vc)

{
	struct compat_unimapdesc tmp;
	struct unipair __user *tmp_entries;

	if (copy_from_user(&tmp, user_ud, sizeof tmp))
		return -EFAULT;
	tmp_entries = compat_ptr(tmp.entries);
	switch (cmd) {
	case PIO_UNIMAP:
		if (!perm)
			return -EPERM;
		return con_set_unimap(vc, tmp.entry_ct, tmp_entries);
	case GIO_UNIMAP:
		if (!perm && fg_console != vc->vc_num)
			return -EPERM;
		return con_get_unimap(vc, tmp.entry_ct, &(user_ud->entry_ct), tmp_entries);
	}
	return 0;
}

long vt_compat_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
	struct vc_data *vc = tty->driver_data;
	struct console_font_op op;	
	void __user *up = compat_ptr(arg);
	int perm;

	
	perm = 0;
	if (current->signal->tty == tty || capable(CAP_SYS_TTY_CONFIG))
		perm = 1;

	switch (cmd) {
	

	case KDFONTOP:
		return compat_kdfontop_ioctl(up, perm, &op, vc);

	case PIO_UNIMAP:
	case GIO_UNIMAP:
		return compat_unimap_ioctl(cmd, up, perm, vc);

	
	case KIOCSOUND:
	case KDMKTONE:

	case KDADDIO:
	case KDDELIO:

	case KDSETMODE:
	case KDMAPDISP:
	case KDUNMAPDISP:
	case KDSKBMODE:
	case KDSKBMETA:
	case KDSKBLED:
	case KDSETLED:
	case KDSIGACCEPT:
	case VT_ACTIVATE:
	case VT_WAITACTIVE:
	case VT_RELDISP:
	case VT_DISALLOCATE:
	case VT_RESIZE:
	case VT_RESIZEX:
		return vt_ioctl(tty, cmd, arg);

	
	default:
		return vt_ioctl(tty, cmd, (unsigned long)up);
	}
}






static void complete_change_console(struct vc_data *vc)
{
	unsigned char old_vc_mode;
	int old = fg_console;

	last_console = fg_console;

	
	old_vc_mode = vc_cons[fg_console].d->vc_mode;
	switch_screen(vc);

	
	if (old_vc_mode != vc->vc_mode) {
		if (vc->vc_mode == KD_TEXT)
			do_unblank_screen(1);
		else do_blank_screen(1);
	}

	
	if (vc->vt_mode.mode == VT_PROCESS) {
		
		if (kill_pid(vc->vt_pid, vc->vt_mode.acqsig, 1) != 0) {
		
			reset_vc(vc);

			if (old_vc_mode != vc->vc_mode) {
				if (vc->vc_mode == KD_TEXT)
					do_unblank_screen(1);
				else do_blank_screen(1);
			}
		}
	}

	
	vt_event_post(VT_EVENT_SWITCH, old, vc->vc_num);
	return;
}


void change_console(struct vc_data *new_vc)
{
	struct vc_data *vc;

	if (!new_vc || new_vc->vc_num == fg_console || vt_dont_switch)
		return;

	
	vc = vc_cons[fg_console].d;
	if (vc->vt_mode.mode == VT_PROCESS) {
		
		vc->vt_newvt = new_vc->vc_num;
		if (kill_pid(vc->vt_pid, vc->vt_mode.relsig, 1) == 0) {
			
			return;
		}

		
		reset_vc(vc);

		
	}

	
	if (vc->vc_mode == KD_GRAPHICS)
		return;

	complete_change_console(new_vc);
}



static int disable_vt_switch;

int vt_move_to_console(unsigned int vt, int alloc)
{
	int prev;

	console_lock();
	
	if (disable_vt_switch) {
		console_unlock();
		return 0;
	}
	prev = fg_console;

	if (alloc && vc_allocate(vt)) {
		
		console_unlock();
		return -ENOSPC;
	}

	if (set_console(vt)) {
		
		console_unlock();
		return -EIO;
	}
	console_unlock();
	if (vt_waitactive(vt + 1)) {
		pr_debug("Suspend: Can't switch VCs.");
		return -EINTR;
	}
	return prev;
}


void pm_set_vt_switch(int do_switch)
{
	console_lock();
	disable_vt_switch = !do_switch;
	console_unlock();
}
EXPORT_SYMBOL(pm_set_vt_switch);
