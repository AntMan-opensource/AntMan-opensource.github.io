






























int ptrace_access_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	if (!tsk->ptrace || (current != tsk->parent) || ((get_dumpable(mm) != SUID_DUMP_USER) && !ptracer_capable(tsk, mm->user_ns))) {


		mmput(mm);
		return 0;
	}

	ret = __access_remote_vm(mm, addr, buf, len, gup_flags);
	mmput(mm);

	return ret;
}


void __ptrace_link(struct task_struct *child, struct task_struct *new_parent, const struct cred *ptracer_cred)
{
	BUG_ON(!list_empty(&child->ptrace_entry));
	list_add(&child->ptrace_entry, &new_parent->ptraced);
	child->parent = new_parent;
	child->ptracer_cred = get_cred(ptracer_cred);
}


static void ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
	__ptrace_link(child, new_parent, current_cred());
}


void __ptrace_unlink(struct task_struct *child)
{
	const struct cred *old_cred;
	BUG_ON(!child->ptrace);

	clear_task_syscall_work(child, SYSCALL_TRACE);

	clear_task_syscall_work(child, SYSCALL_EMU);


	child->parent = child->real_parent;
	list_del_init(&child->ptrace_entry);
	old_cred = child->ptracer_cred;
	child->ptracer_cred = NULL;
	put_cred(old_cred);

	spin_lock(&child->sighand->siglock);
	child->ptrace = 0;
	
	task_clear_jobctl_pending(child, JOBCTL_TRAP_MASK);
	task_clear_jobctl_trapping(child);

	
	if (!(child->flags & PF_EXITING) && (child->signal->flags & SIGNAL_STOP_STOPPED || child->signal->group_stop_count)) {

		child->jobctl |= JOBCTL_STOP_PENDING;

		
		if (!(child->jobctl & JOBCTL_STOP_SIGMASK))
			child->jobctl |= SIGSTOP;
	}

	
	if (child->jobctl & JOBCTL_STOP_PENDING || task_is_traced(child))
		ptrace_signal_wake_up(child, true);

	spin_unlock(&child->sighand->siglock);
}

static bool looks_like_a_spurious_pid(struct task_struct *task)
{
	if (task->exit_code != ((PTRACE_EVENT_EXEC << 8) | SIGTRAP))
		return false;

	if (task_pid_vnr(task) == task->ptrace_message)
		return false;
	
	return true;
}


static bool ptrace_freeze_traced(struct task_struct *task)
{
	bool ret = false;

	
	if (task->jobctl & JOBCTL_LISTENING)
		return ret;

	spin_lock_irq(&task->sighand->siglock);
	if (task_is_traced(task) && !looks_like_a_spurious_pid(task) && !__fatal_signal_pending(task)) {
		WRITE_ONCE(task->__state, __TASK_TRACED);
		ret = true;
	}
	spin_unlock_irq(&task->sighand->siglock);

	return ret;
}

static void ptrace_unfreeze_traced(struct task_struct *task)
{
	if (READ_ONCE(task->__state) != __TASK_TRACED)
		return;

	WARN_ON(!task->ptrace || task->parent != current);

	
	spin_lock_irq(&task->sighand->siglock);
	if (READ_ONCE(task->__state) == __TASK_TRACED) {
		if (__fatal_signal_pending(task))
			wake_up_state(task, __TASK_TRACED);
		else WRITE_ONCE(task->__state, TASK_TRACED);
	}
	spin_unlock_irq(&task->sighand->siglock);
}


static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
{
	int ret = -ESRCH;

	
	read_lock(&tasklist_lock);
	if (child->ptrace && child->parent == current) {
		WARN_ON(READ_ONCE(child->__state) == __TASK_TRACED);
		
		if (ignore_state || ptrace_freeze_traced(child))
			ret = 0;
	}
	read_unlock(&tasklist_lock);

	if (!ret && !ignore_state) {
		if (!wait_task_inactive(child, __TASK_TRACED)) {
			
			WARN_ON(READ_ONCE(child->__state) == __TASK_TRACED);
			ret = -ESRCH;
		}
	}

	return ret;
}

static bool ptrace_has_cap(struct user_namespace *ns, unsigned int mode)
{
	if (mode & PTRACE_MODE_NOAUDIT)
		return ns_capable_noaudit(ns, CAP_SYS_PTRACE);
	return ns_capable(ns, CAP_SYS_PTRACE);
}


static int __ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	const struct cred *cred = current_cred(), *tcred;
	struct mm_struct *mm;
	kuid_t caller_uid;
	kgid_t caller_gid;

	if (!(mode & PTRACE_MODE_FSCREDS) == !(mode & PTRACE_MODE_REALCREDS)) {
		WARN(1, "denying ptrace access check without PTRACE_MODE_*CREDS\n");
		return -EPERM;
	}

	

	
	if (same_thread_group(task, current))
		return 0;
	rcu_read_lock();
	if (mode & PTRACE_MODE_FSCREDS) {
		caller_uid = cred->fsuid;
		caller_gid = cred->fsgid;
	} else {
		
		caller_uid = cred->uid;
		caller_gid = cred->gid;
	}
	tcred = __task_cred(task);
	if (uid_eq(caller_uid, tcred->euid) && uid_eq(caller_uid, tcred->suid) && uid_eq(caller_uid, tcred->uid)  && gid_eq(caller_gid, tcred->egid) && gid_eq(caller_gid, tcred->sgid) && gid_eq(caller_gid, tcred->gid))




		goto ok;
	if (ptrace_has_cap(tcred->user_ns, mode))
		goto ok;
	rcu_read_unlock();
	return -EPERM;
ok:
	rcu_read_unlock();
	
	smp_rmb();
	mm = task->mm;
	if (mm && ((get_dumpable(mm) != SUID_DUMP_USER) && !ptrace_has_cap(mm->user_ns, mode)))

	    return -EPERM;

	return security_ptrace_access_check(task, mode);
}

bool ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	int err;
	task_lock(task);
	err = __ptrace_may_access(task, mode);
	task_unlock(task);
	return !err;
}

static int ptrace_attach(struct task_struct *task, long request, unsigned long addr, unsigned long flags)

{
	bool seize = (request == PTRACE_SEIZE);
	int retval;

	retval = -EIO;
	if (seize) {
		if (addr != 0)
			goto out;
		if (flags & ~(unsigned long)PTRACE_O_MASK)
			goto out;
		flags = PT_PTRACED | PT_SEIZED | (flags << PT_OPT_FLAG_SHIFT);
	} else {
		flags = PT_PTRACED;
	}

	audit_ptrace(task);

	retval = -EPERM;
	if (unlikely(task->flags & PF_KTHREAD))
		goto out;
	if (same_thread_group(task, current))
		goto out;

	
	retval = -ERESTARTNOINTR;
	if (mutex_lock_interruptible(&task->signal->cred_guard_mutex))
		goto out;

	task_lock(task);
	retval = __ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS);
	task_unlock(task);
	if (retval)
		goto unlock_creds;

	write_lock_irq(&tasklist_lock);
	retval = -EPERM;
	if (unlikely(task->exit_state))
		goto unlock_tasklist;
	if (task->ptrace)
		goto unlock_tasklist;

	task->ptrace = flags;

	ptrace_link(task, current);

	
	if (!seize)
		send_sig_info(SIGSTOP, SEND_SIG_PRIV, task);

	spin_lock(&task->sighand->siglock);

	
	if (task_is_stopped(task) && task_set_jobctl_pending(task, JOBCTL_TRAP_STOP | JOBCTL_TRAPPING))
		signal_wake_up_state(task, __TASK_STOPPED);

	spin_unlock(&task->sighand->siglock);

	retval = 0;
unlock_tasklist:
	write_unlock_irq(&tasklist_lock);
unlock_creds:
	mutex_unlock(&task->signal->cred_guard_mutex);
out:
	if (!retval) {
		
		wait_on_bit(&task->jobctl, JOBCTL_TRAPPING_BIT, TASK_KILLABLE);
		proc_ptrace_connector(task, PTRACE_ATTACH);
	}

	return retval;
}


static int ptrace_traceme(void)
{
	int ret = -EPERM;

	write_lock_irq(&tasklist_lock);
	
	if (!current->ptrace) {
		ret = security_ptrace_traceme(current->parent);
		
		if (!ret && !(current->real_parent->flags & PF_EXITING)) {
			current->ptrace = PT_PTRACED;
			ptrace_link(current, current->real_parent);
		}
	}
	write_unlock_irq(&tasklist_lock);

	return ret;
}


static int ignoring_children(struct sighand_struct *sigh)
{
	int ret;
	spin_lock(&sigh->siglock);
	ret = (sigh->action[SIGCHLD-1].sa.sa_handler == SIG_IGN) || (sigh->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT);
	spin_unlock(&sigh->siglock);
	return ret;
}


static bool __ptrace_detach(struct task_struct *tracer, struct task_struct *p)
{
	bool dead;

	__ptrace_unlink(p);

	if (p->exit_state != EXIT_ZOMBIE)
		return false;

	dead = !thread_group_leader(p);

	if (!dead && thread_group_empty(p)) {
		if (!same_thread_group(p->real_parent, tracer))
			dead = do_notify_parent(p, p->exit_signal);
		else if (ignoring_children(tracer->sighand)) {
			__wake_up_parent(p, tracer);
			dead = true;
		}
	}
	
	if (dead)
		p->exit_state = EXIT_DEAD;
	return dead;
}

static int ptrace_detach(struct task_struct *child, unsigned int data)
{
	if (!valid_signal(data))
		return -EIO;

	
	ptrace_disable(child);

	write_lock_irq(&tasklist_lock);
	
	WARN_ON(!child->ptrace || child->exit_state);
	
	child->exit_code = data;
	__ptrace_detach(current, child);
	write_unlock_irq(&tasklist_lock);

	proc_ptrace_connector(child, PTRACE_DETACH);

	return 0;
}


void exit_ptrace(struct task_struct *tracer, struct list_head *dead)
{
	struct task_struct *p, *n;

	list_for_each_entry_safe(p, n, &tracer->ptraced, ptrace_entry) {
		if (unlikely(p->ptrace & PT_EXITKILL))
			send_sig_info(SIGKILL, SEND_SIG_PRIV, p);

		if (__ptrace_detach(tracer, p))
			list_add(&p->ptrace_entry, dead);
	}
}

int ptrace_readdata(struct task_struct *tsk, unsigned long src, char __user *dst, int len)
{
	int copied = 0;

	while (len > 0) {
		char buf[128];
		int this_len, retval;

		this_len = (len > sizeof(buf)) ? sizeof(buf) : len;
		retval = ptrace_access_vm(tsk, src, buf, this_len, FOLL_FORCE);

		if (!retval) {
			if (copied)
				break;
			return -EIO;
		}
		if (copy_to_user(dst, buf, retval))
			return -EFAULT;
		copied += retval;
		src += retval;
		dst += retval;
		len -= retval;
	}
	return copied;
}

int ptrace_writedata(struct task_struct *tsk, char __user *src, unsigned long dst, int len)
{
	int copied = 0;

	while (len > 0) {
		char buf[128];
		int this_len, retval;

		this_len = (len > sizeof(buf)) ? sizeof(buf) : len;
		if (copy_from_user(buf, src, this_len))
			return -EFAULT;
		retval = ptrace_access_vm(tsk, dst, buf, this_len, FOLL_FORCE | FOLL_WRITE);
		if (!retval) {
			if (copied)
				break;
			return -EIO;
		}
		copied += retval;
		src += retval;
		dst += retval;
		len -= retval;
	}
	return copied;
}

static int ptrace_setoptions(struct task_struct *child, unsigned long data)
{
	unsigned flags;

	if (data & ~(unsigned long)PTRACE_O_MASK)
		return -EINVAL;

	if (unlikely(data & PTRACE_O_SUSPEND_SECCOMP)) {
		if (!IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) || !IS_ENABLED(CONFIG_SECCOMP))
			return -EINVAL;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (seccomp_mode(&current->seccomp) != SECCOMP_MODE_DISABLED || current->ptrace & PT_SUSPEND_SECCOMP)
			return -EPERM;
	}

	
	flags = child->ptrace;
	flags &= ~(PTRACE_O_MASK << PT_OPT_FLAG_SHIFT);
	flags |= (data << PT_OPT_FLAG_SHIFT);
	child->ptrace = flags;

	return 0;
}

static int ptrace_getsiginfo(struct task_struct *child, kernel_siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(info, child->last_siginfo);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}

static int ptrace_setsiginfo(struct task_struct *child, const kernel_siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(child->last_siginfo, info);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}

static int ptrace_peek_siginfo(struct task_struct *child, unsigned long addr, unsigned long data)

{
	struct ptrace_peeksiginfo_args arg;
	struct sigpending *pending;
	struct sigqueue *q;
	int ret, i;

	ret = copy_from_user(&arg, (void __user *) addr, sizeof(struct ptrace_peeksiginfo_args));
	if (ret)
		return -EFAULT;

	if (arg.flags & ~PTRACE_PEEKSIGINFO_SHARED)
		return -EINVAL; 

	if (arg.nr < 0)
		return -EINVAL;

	
	if (arg.off > ULONG_MAX)
		return 0;

	if (arg.flags & PTRACE_PEEKSIGINFO_SHARED)
		pending = &child->signal->shared_pending;
	else pending = &child->pending;

	for (i = 0; i < arg.nr; ) {
		kernel_siginfo_t info;
		unsigned long off = arg.off + i;
		bool found = false;

		spin_lock_irq(&child->sighand->siglock);
		list_for_each_entry(q, &pending->list, list) {
			if (!off--) {
				found = true;
				copy_siginfo(&info, &q->info);
				break;
			}
		}
		spin_unlock_irq(&child->sighand->siglock);

		if (!found) 
			break;


		if (unlikely(in_compat_syscall())) {
			compat_siginfo_t __user *uinfo = compat_ptr(data);

			if (copy_siginfo_to_user32(uinfo, &info)) {
				ret = -EFAULT;
				break;
			}

		} else  {

			siginfo_t __user *uinfo = (siginfo_t __user *) data;

			if (copy_siginfo_to_user(uinfo, &info)) {
				ret = -EFAULT;
				break;
			}
		}

		data += sizeof(siginfo_t);
		i++;

		if (signal_pending(current))
			break;

		cond_resched();
	}

	if (i > 0)
		return i;

	return ret;
}


static long ptrace_get_rseq_configuration(struct task_struct *task, unsigned long size, void __user *data)
{
	struct ptrace_rseq_configuration conf = {
		.rseq_abi_pointer = (u64)(uintptr_t)task->rseq, .rseq_abi_size = sizeof(*task->rseq), .signature = task->rseq_sig, .flags = 0, };




	size = min_t(unsigned long, size, sizeof(conf));
	if (copy_to_user(data, &conf, size))
		return -EFAULT;
	return sizeof(conf);
}




















static int ptrace_resume(struct task_struct *child, long request, unsigned long data)
{
	bool need_siglock;

	if (!valid_signal(data))
		return -EIO;

	if (request == PTRACE_SYSCALL)
		set_task_syscall_work(child, SYSCALL_TRACE);
	else clear_task_syscall_work(child, SYSCALL_TRACE);


	if (request == PTRACE_SYSEMU || request == PTRACE_SYSEMU_SINGLESTEP)
		set_task_syscall_work(child, SYSCALL_EMU);
	else clear_task_syscall_work(child, SYSCALL_EMU);


	if (is_singleblock(request)) {
		if (unlikely(!arch_has_block_step()))
			return -EIO;
		user_enable_block_step(child);
	} else if (is_singlestep(request) || is_sysemu_singlestep(request)) {
		if (unlikely(!arch_has_single_step()))
			return -EIO;
		user_enable_single_step(child);
	} else {
		user_disable_single_step(child);
	}

	
	need_siglock = data && !thread_group_empty(current);
	if (need_siglock)
		spin_lock_irq(&child->sighand->siglock);
	child->exit_code = data;
	wake_up_state(child, __TASK_TRACED);
	if (need_siglock)
		spin_unlock_irq(&child->sighand->siglock);

	return 0;
}



static const struct user_regset * find_regset(const struct user_regset_view *view, unsigned int type)
{
	const struct user_regset *regset;
	int n;

	for (n = 0; n < view->n; ++n) {
		regset = view->regsets + n;
		if (regset->core_note_type == type)
			return regset;
	}

	return NULL;
}

static int ptrace_regset(struct task_struct *task, int req, unsigned int type, struct iovec *kiov)
{
	const struct user_regset_view *view = task_user_regset_view(task);
	const struct user_regset *regset = find_regset(view, type);
	int regset_no;

	if (!regset || (kiov->iov_len % regset->size) != 0)
		return -EINVAL;

	regset_no = regset - view->regsets;
	kiov->iov_len = min(kiov->iov_len, (__kernel_size_t) (regset->n * regset->size));

	if (req == PTRACE_GETREGSET)
		return copy_regset_to_user(task, view, regset_no, 0, kiov->iov_len, kiov->iov_base);
	else return copy_regset_from_user(task, view, regset_no, 0, kiov->iov_len, kiov->iov_base);

}


EXPORT_SYMBOL_GPL(task_user_regset_view);

static unsigned long ptrace_get_syscall_info_entry(struct task_struct *child, struct pt_regs *regs, struct ptrace_syscall_info *info)

{
	unsigned long args[ARRAY_SIZE(info->entry.args)];
	int i;

	info->op = PTRACE_SYSCALL_INFO_ENTRY;
	info->entry.nr = syscall_get_nr(child, regs);
	syscall_get_arguments(child, regs, args);
	for (i = 0; i < ARRAY_SIZE(args); i++)
		info->entry.args[i] = args[i];

	
	return offsetofend(struct ptrace_syscall_info, entry.args);
}

static unsigned long ptrace_get_syscall_info_seccomp(struct task_struct *child, struct pt_regs *regs, struct ptrace_syscall_info *info)

{
	
	ptrace_get_syscall_info_entry(child, regs, info);
	info->op = PTRACE_SYSCALL_INFO_SECCOMP;
	info->seccomp.ret_data = child->ptrace_message;

	
	return offsetofend(struct ptrace_syscall_info, seccomp.ret_data);
}

static unsigned long ptrace_get_syscall_info_exit(struct task_struct *child, struct pt_regs *regs, struct ptrace_syscall_info *info)

{
	info->op = PTRACE_SYSCALL_INFO_EXIT;
	info->exit.rval = syscall_get_error(child, regs);
	info->exit.is_error = !!info->exit.rval;
	if (!info->exit.is_error)
		info->exit.rval = syscall_get_return_value(child, regs);

	
	return offsetofend(struct ptrace_syscall_info, exit.is_error);
}

static int ptrace_get_syscall_info(struct task_struct *child, unsigned long user_size, void __user *datavp)

{
	struct pt_regs *regs = task_pt_regs(child);
	struct ptrace_syscall_info info = {
		.op = PTRACE_SYSCALL_INFO_NONE, .arch = syscall_get_arch(child), .instruction_pointer = instruction_pointer(regs), .stack_pointer = user_stack_pointer(regs), };



	unsigned long actual_size = offsetof(struct ptrace_syscall_info, entry);
	unsigned long write_size;

	
	switch (child->last_siginfo ? child->last_siginfo->si_code : 0) {
	case SIGTRAP | 0x80:
		switch (child->ptrace_message) {
		case PTRACE_EVENTMSG_SYSCALL_ENTRY:
			actual_size = ptrace_get_syscall_info_entry(child, regs, &info);
			break;
		case PTRACE_EVENTMSG_SYSCALL_EXIT:
			actual_size = ptrace_get_syscall_info_exit(child, regs, &info);
			break;
		}
		break;
	case SIGTRAP | (PTRACE_EVENT_SECCOMP << 8):
		actual_size = ptrace_get_syscall_info_seccomp(child, regs, &info);
		break;
	}

	write_size = min(actual_size, user_size);
	return copy_to_user(datavp, &info, write_size) ? -EFAULT : actual_size;
}


int ptrace_request(struct task_struct *child, long request, unsigned long addr, unsigned long data)
{
	bool seized = child->ptrace & PT_SEIZED;
	int ret = -EIO;
	kernel_siginfo_t siginfo, *si;
	void __user *datavp = (void __user *) data;
	unsigned long __user *datalp = datavp;
	unsigned long flags;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		return generic_ptrace_peekdata(child, addr, data);
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		return generic_ptrace_pokedata(child, addr, data);


	case PTRACE_OLDSETOPTIONS:

	case PTRACE_SETOPTIONS:
		ret = ptrace_setoptions(child, data);
		break;
	case PTRACE_GETEVENTMSG:
		ret = put_user(child->ptrace_message, datalp);
		break;

	case PTRACE_PEEKSIGINFO:
		ret = ptrace_peek_siginfo(child, addr, data);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_getsiginfo(child, &siginfo);
		if (!ret)
			ret = copy_siginfo_to_user(datavp, &siginfo);
		break;

	case PTRACE_SETSIGINFO:
		ret = copy_siginfo_from_user(&siginfo, datavp);
		if (!ret)
			ret = ptrace_setsiginfo(child, &siginfo);
		break;

	case PTRACE_GETSIGMASK: {
		sigset_t *mask;

		if (addr != sizeof(sigset_t)) {
			ret = -EINVAL;
			break;
		}

		if (test_tsk_restore_sigmask(child))
			mask = &child->saved_sigmask;
		else mask = &child->blocked;

		if (copy_to_user(datavp, mask, sizeof(sigset_t)))
			ret = -EFAULT;
		else ret = 0;

		break;
	}

	case PTRACE_SETSIGMASK: {
		sigset_t new_set;

		if (addr != sizeof(sigset_t)) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(&new_set, datavp, sizeof(sigset_t))) {
			ret = -EFAULT;
			break;
		}

		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		
		spin_lock_irq(&child->sighand->siglock);
		child->blocked = new_set;
		spin_unlock_irq(&child->sighand->siglock);

		clear_tsk_restore_sigmask(child);

		ret = 0;
		break;
	}

	case PTRACE_INTERRUPT:
		
		if (unlikely(!seized || !lock_task_sighand(child, &flags)))
			break;

		
		if (likely(task_set_jobctl_pending(child, JOBCTL_TRAP_STOP)))
			ptrace_signal_wake_up(child, child->jobctl & JOBCTL_LISTENING);

		unlock_task_sighand(child, &flags);
		ret = 0;
		break;

	case PTRACE_LISTEN:
		
		if (unlikely(!seized || !lock_task_sighand(child, &flags)))
			break;

		si = child->last_siginfo;
		if (likely(si && (si->si_code >> 8) == PTRACE_EVENT_STOP)) {
			child->jobctl |= JOBCTL_LISTENING;
			
			if (child->jobctl & JOBCTL_TRAP_NOTIFY)
				ptrace_signal_wake_up(child, true);
			ret = 0;
		}
		unlock_task_sighand(child, &flags);
		break;

	case PTRACE_DETACH:	 
		ret = ptrace_detach(child, data);
		break;


	case PTRACE_GETFDPIC: {
		struct mm_struct *mm = get_task_mm(child);
		unsigned long tmp = 0;

		ret = -ESRCH;
		if (!mm)
			break;

		switch (addr) {
		case PTRACE_GETFDPIC_EXEC:
			tmp = mm->context.exec_fdpic_loadmap;
			break;
		case PTRACE_GETFDPIC_INTERP:
			tmp = mm->context.interp_fdpic_loadmap;
			break;
		default:
			break;
		}
		mmput(mm);

		ret = put_user(tmp, datalp);
		break;
	}



	case PTRACE_SINGLESTEP:


	case PTRACE_SINGLEBLOCK:


	case PTRACE_SYSEMU:
	case PTRACE_SYSEMU_SINGLESTEP:

	case PTRACE_SYSCALL:
	case PTRACE_CONT:
		return ptrace_resume(child, request, data);

	case PTRACE_KILL:
		if (child->exit_state)	
			return 0;
		return ptrace_resume(child, request, SIGKILL);


	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET: {
		struct iovec kiov;
		struct iovec __user *uiov = datavp;

		if (!access_ok(uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(kiov.iov_base, &uiov->iov_base) || __get_user(kiov.iov_len, &uiov->iov_len))
			return -EFAULT;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}

	case PTRACE_GET_SYSCALL_INFO:
		ret = ptrace_get_syscall_info(child, addr, datavp);
		break;


	case PTRACE_SECCOMP_GET_FILTER:
		ret = seccomp_get_filter(child, addr, datavp);
		break;

	case PTRACE_SECCOMP_GET_METADATA:
		ret = seccomp_get_metadata(child, addr, datavp);
		break;


	case PTRACE_GET_RSEQ_CONFIGURATION:
		ret = ptrace_get_rseq_configuration(child, addr, datavp);
		break;


	default:
		break;
	}

	return ret;
}





SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr, unsigned long, data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		if (!ret)
			arch_ptrace_attach(current);
		goto out;
	}

	child = find_get_task_by_vpid(pid);
	if (!child) {
		ret = -ESRCH;
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL || request == PTRACE_INTERRUPT);
	if (ret < 0)
		goto out_put_task_struct;

	ret = arch_ptrace(child, request, addr, data);
	if (ret || request != PTRACE_DETACH)
		ptrace_unfreeze_traced(child);

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}

int generic_ptrace_peekdata(struct task_struct *tsk, unsigned long addr, unsigned long data)
{
	unsigned long tmp;
	int copied;

	copied = ptrace_access_vm(tsk, addr, &tmp, sizeof(tmp), FOLL_FORCE);
	if (copied != sizeof(tmp))
		return -EIO;
	return put_user(tmp, (unsigned long __user *)data);
}

int generic_ptrace_pokedata(struct task_struct *tsk, unsigned long addr, unsigned long data)
{
	int copied;

	copied = ptrace_access_vm(tsk, addr, &data, sizeof(data), FOLL_FORCE | FOLL_WRITE);
	return (copied == sizeof(data)) ? 0 : -EIO;
}



int compat_ptrace_request(struct task_struct *child, compat_long_t request, compat_ulong_t addr, compat_ulong_t data)
{
	compat_ulong_t __user *datap = compat_ptr(data);
	compat_ulong_t word;
	kernel_siginfo_t siginfo;
	int ret;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		ret = ptrace_access_vm(child, addr, &word, sizeof(word), FOLL_FORCE);
		if (ret != sizeof(word))
			ret = -EIO;
		else ret = put_user(word, datap);
		break;

	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		ret = ptrace_access_vm(child, addr, &data, sizeof(data), FOLL_FORCE | FOLL_WRITE);
		ret = (ret != sizeof(data) ? -EIO : 0);
		break;

	case PTRACE_GETEVENTMSG:
		ret = put_user((compat_ulong_t) child->ptrace_message, datap);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_getsiginfo(child, &siginfo);
		if (!ret)
			ret = copy_siginfo_to_user32( (struct compat_siginfo __user *) datap, &siginfo);

		break;

	case PTRACE_SETSIGINFO:
		ret = copy_siginfo_from_user32( &siginfo, (struct compat_siginfo __user *) datap);
		if (!ret)
			ret = ptrace_setsiginfo(child, &siginfo);
		break;

	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET:
	{
		struct iovec kiov;
		struct compat_iovec __user *uiov = (struct compat_iovec __user *) datap;
		compat_uptr_t ptr;
		compat_size_t len;

		if (!access_ok(uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(ptr, &uiov->iov_base) || __get_user(len, &uiov->iov_len))
			return -EFAULT;

		kiov.iov_base = compat_ptr(ptr);
		kiov.iov_len = len;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}


	default:
		ret = ptrace_request(child, request, addr, data);
	}

	return ret;
}

COMPAT_SYSCALL_DEFINE4(ptrace, compat_long_t, request, compat_long_t, pid, compat_long_t, addr, compat_long_t, data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		goto out;
	}

	child = find_get_task_by_vpid(pid);
	if (!child) {
		ret = -ESRCH;
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL || request == PTRACE_INTERRUPT);
	if (!ret) {
		ret = compat_arch_ptrace(child, request, addr, data);
		if (ret || request != PTRACE_DETACH)
			ptrace_unfreeze_traced(child);
	}

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}

