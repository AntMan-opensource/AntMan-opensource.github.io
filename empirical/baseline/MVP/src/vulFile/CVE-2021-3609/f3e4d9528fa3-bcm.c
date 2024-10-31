






































MODULE_DESCRIPTION("PF_CAN broadcast manager protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");
MODULE_ALIAS("can-proto-2");




static inline u64 get_u64(const struct canfd_frame *cp, int offset)
{
	return *(u64 *)(cp->data + offset);
}

struct bcm_op {
	struct list_head list;
	int ifindex;
	canid_t can_id;
	u32 flags;
	unsigned long frames_abs, frames_filtered;
	struct bcm_timeval ival1, ival2;
	struct hrtimer timer, thrtimer;
	ktime_t rx_stamp, kt_ival1, kt_ival2, kt_lastmsg;
	int rx_ifindex;
	int cfsiz;
	u32 count;
	u32 nframes;
	u32 currframe;
	
	void *frames;
	void *last_frames;
	struct canfd_frame sframe;
	struct canfd_frame last_sframe;
	struct sock *sk;
	struct net_device *rx_reg_dev;
};

struct bcm_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct list_head notifier;
	struct list_head rx_ops;
	struct list_head tx_ops;
	unsigned long dropped_usr_msgs;
	struct proc_dir_entry *bcm_proc_read;
	char procname [32]; 
};

static LIST_HEAD(bcm_notifier_list);
static DEFINE_SPINLOCK(bcm_notifier_lock);
static struct bcm_sock *bcm_busy_notifier;

static inline struct bcm_sock *bcm_sk(const struct sock *sk)
{
	return (struct bcm_sock *)sk;
}

static inline ktime_t bcm_timeval_to_ktime(struct bcm_timeval tv)
{
	return ktime_set(tv.tv_sec, tv.tv_usec * NSEC_PER_USEC);
}


static bool bcm_is_invalid_tv(struct bcm_msg_head *msg_head)
{
	if ((msg_head->ival1.tv_sec < 0) || (msg_head->ival1.tv_sec > BCM_TIMER_SEC_MAX) || (msg_head->ival1.tv_usec < 0) || (msg_head->ival1.tv_usec >= USEC_PER_SEC) || (msg_head->ival2.tv_sec < 0) || (msg_head->ival2.tv_sec > BCM_TIMER_SEC_MAX) || (msg_head->ival2.tv_usec < 0) || (msg_head->ival2.tv_usec >= USEC_PER_SEC))






		return true;

	return false;
}







static char *bcm_proc_getifname(struct net *net, char *result, int ifindex)
{
	struct net_device *dev;

	if (!ifindex)
		return "any";

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	if (dev)
		strcpy(result, dev->name);
	else strcpy(result, "???");
	rcu_read_unlock();

	return result;
}

static int bcm_proc_show(struct seq_file *m, void *v)
{
	char ifname[IFNAMSIZ];
	struct net *net = m->private;
	struct sock *sk = (struct sock *)PDE_DATA(m->file->f_inode);
	struct bcm_sock *bo = bcm_sk(sk);
	struct bcm_op *op;

	seq_printf(m, ">>> socket %pK", sk->sk_socket);
	seq_printf(m, " / sk %pK", sk);
	seq_printf(m, " / bo %pK", bo);
	seq_printf(m, " / dropped %lu", bo->dropped_usr_msgs);
	seq_printf(m, " / bound %s", bcm_proc_getifname(net, ifname, bo->ifindex));
	seq_printf(m, " <<<\n");

	list_for_each_entry(op, &bo->rx_ops, list) {

		unsigned long reduction;

		
		if (!op->frames_abs)
			continue;

		seq_printf(m, "rx_op: %03X %-5s ", op->can_id, bcm_proc_getifname(net, ifname, op->ifindex));

		if (op->flags & CAN_FD_FRAME)
			seq_printf(m, "(%u)", op->nframes);
		else seq_printf(m, "[%u]", op->nframes);

		seq_printf(m, "%c ", (op->flags & RX_CHECK_DLC) ? 'd' : ' ');

		if (op->kt_ival1)
			seq_printf(m, "timeo=%lld ", (long long)ktime_to_us(op->kt_ival1));

		if (op->kt_ival2)
			seq_printf(m, "thr=%lld ", (long long)ktime_to_us(op->kt_ival2));

		seq_printf(m, "# recv %ld (%ld) => reduction: ", op->frames_filtered, op->frames_abs);

		reduction = 100 - (op->frames_filtered * 100) / op->frames_abs;

		seq_printf(m, "%s%ld%%\n", (reduction == 100) ? "near " : "", reduction);
	}

	list_for_each_entry(op, &bo->tx_ops, list) {

		seq_printf(m, "tx_op: %03X %s ", op->can_id, bcm_proc_getifname(net, ifname, op->ifindex));

		if (op->flags & CAN_FD_FRAME)
			seq_printf(m, "(%u) ", op->nframes);
		else seq_printf(m, "[%u] ", op->nframes);

		if (op->kt_ival1)
			seq_printf(m, "t1=%lld ", (long long)ktime_to_us(op->kt_ival1));

		if (op->kt_ival2)
			seq_printf(m, "t2=%lld ", (long long)ktime_to_us(op->kt_ival2));

		seq_printf(m, "# sent %ld\n", op->frames_abs);
	}
	seq_putc(m, '\n');
	return 0;
}



static void bcm_can_tx(struct bcm_op *op)
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct canfd_frame *cf = op->frames + op->cfsiz * op->currframe;

	
	if (!op->ifindex)
		return;

	dev = dev_get_by_index(sock_net(op->sk), op->ifindex);
	if (!dev) {
		
		return;
	}

	skb = alloc_skb(op->cfsiz + sizeof(struct can_skb_priv), gfp_any());
	if (!skb)
		goto out;

	can_skb_reserve(skb);
	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;

	skb_put_data(skb, cf, op->cfsiz);

	
	skb->dev = dev;
	can_skb_set_owner(skb, op->sk);
	can_send(skb, 1);

	
	op->currframe++;
	op->frames_abs++;

	
	if (op->currframe >= op->nframes)
		op->currframe = 0;
out:
	dev_put(dev);
}


static void bcm_send_to_user(struct bcm_op *op, struct bcm_msg_head *head, struct canfd_frame *frames, int has_timestamp)
{
	struct sk_buff *skb;
	struct canfd_frame *firstframe;
	struct sockaddr_can *addr;
	struct sock *sk = op->sk;
	unsigned int datalen = head->nframes * op->cfsiz;
	int err;

	skb = alloc_skb(sizeof(*head) + datalen, gfp_any());
	if (!skb)
		return;

	skb_put_data(skb, head, sizeof(*head));

	if (head->nframes) {
		
		firstframe = (struct canfd_frame *)skb_tail_pointer(skb);

		skb_put_data(skb, frames, datalen);

		
		if (head->nframes == 1)
			firstframe->flags &= BCM_CAN_FLAGS_MASK;
	}

	if (has_timestamp) {
		
		skb->tstamp = op->rx_stamp;
	}

	

	sock_skb_cb_check_size(sizeof(struct sockaddr_can));
	addr = (struct sockaddr_can *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = op->rx_ifindex;

	err = sock_queue_rcv_skb(sk, skb);
	if (err < 0) {
		struct bcm_sock *bo = bcm_sk(sk);

		kfree_skb(skb);
		
		bo->dropped_usr_msgs++;
	}
}

static bool bcm_tx_set_expiry(struct bcm_op *op, struct hrtimer *hrt)
{
	ktime_t ival;

	if (op->kt_ival1 && op->count)
		ival = op->kt_ival1;
	else if (op->kt_ival2)
		ival = op->kt_ival2;
	else return false;

	hrtimer_set_expires(hrt, ktime_add(ktime_get(), ival));
	return true;
}

static void bcm_tx_start_timer(struct bcm_op *op)
{
	if (bcm_tx_set_expiry(op, &op->timer))
		hrtimer_start_expires(&op->timer, HRTIMER_MODE_ABS_SOFT);
}


static enum hrtimer_restart bcm_tx_timeout_handler(struct hrtimer *hrtimer)
{
	struct bcm_op *op = container_of(hrtimer, struct bcm_op, timer);
	struct bcm_msg_head msg_head;

	if (op->kt_ival1 && (op->count > 0)) {
		op->count--;
		if (!op->count && (op->flags & TX_COUNTEVT)) {

			
			memset(&msg_head, 0, sizeof(msg_head));
			msg_head.opcode  = TX_EXPIRED;
			msg_head.flags   = op->flags;
			msg_head.count   = op->count;
			msg_head.ival1   = op->ival1;
			msg_head.ival2   = op->ival2;
			msg_head.can_id  = op->can_id;
			msg_head.nframes = 0;

			bcm_send_to_user(op, &msg_head, NULL, 0);
		}
		bcm_can_tx(op);

	} else if (op->kt_ival2) {
		bcm_can_tx(op);
	}

	return bcm_tx_set_expiry(op, &op->timer) ? HRTIMER_RESTART : HRTIMER_NORESTART;
}


static void bcm_rx_changed(struct bcm_op *op, struct canfd_frame *data)
{
	struct bcm_msg_head head;

	
	op->frames_filtered++;

	
	if (op->frames_filtered > ULONG_MAX/100)
		op->frames_filtered = op->frames_abs = 0;

	
	data->flags &= (BCM_CAN_FLAGS_MASK|RX_RECV);

	memset(&head, 0, sizeof(head));
	head.opcode  = RX_CHANGED;
	head.flags   = op->flags;
	head.count   = op->count;
	head.ival1   = op->ival1;
	head.ival2   = op->ival2;
	head.can_id  = op->can_id;
	head.nframes = 1;

	bcm_send_to_user(op, &head, data, 1);
}


static void bcm_rx_update_and_send(struct bcm_op *op, struct canfd_frame *lastdata, const struct canfd_frame *rxdata)

{
	memcpy(lastdata, rxdata, op->cfsiz);

	
	lastdata->flags |= (RX_RECV|RX_THR);

	
	if (!op->kt_ival2) {
		
		bcm_rx_changed(op, lastdata);
		return;
	}

	
	if (hrtimer_active(&op->thrtimer))
		return;

	
	if (!op->kt_lastmsg)
		goto rx_changed_settime;

	
	if (ktime_us_delta(ktime_get(), op->kt_lastmsg) < ktime_to_us(op->kt_ival2)) {
		
		hrtimer_start(&op->thrtimer, ktime_add(op->kt_lastmsg, op->kt_ival2), HRTIMER_MODE_ABS_SOFT);

		return;
	}

	
rx_changed_settime:
	bcm_rx_changed(op, lastdata);
	op->kt_lastmsg = ktime_get();
}


static void bcm_rx_cmp_to_index(struct bcm_op *op, unsigned int index, const struct canfd_frame *rxdata)
{
	struct canfd_frame *cf = op->frames + op->cfsiz * index;
	struct canfd_frame *lcf = op->last_frames + op->cfsiz * index;
	int i;

	

	if (!(lcf->flags & RX_RECV)) {
		
		bcm_rx_update_and_send(op, lcf, rxdata);
		return;
	}

	
	for (i = 0; i < rxdata->len; i += 8) {
		if ((get_u64(cf, i) & get_u64(rxdata, i)) != (get_u64(cf, i) & get_u64(lcf, i))) {
			bcm_rx_update_and_send(op, lcf, rxdata);
			return;
		}
	}

	if (op->flags & RX_CHECK_DLC) {
		
		if (rxdata->len != lcf->len) {
			bcm_rx_update_and_send(op, lcf, rxdata);
			return;
		}
	}
}


static void bcm_rx_starttimer(struct bcm_op *op)
{
	if (op->flags & RX_NO_AUTOTIMER)
		return;

	if (op->kt_ival1)
		hrtimer_start(&op->timer, op->kt_ival1, HRTIMER_MODE_REL_SOFT);
}


static enum hrtimer_restart bcm_rx_timeout_handler(struct hrtimer *hrtimer)
{
	struct bcm_op *op = container_of(hrtimer, struct bcm_op, timer);
	struct bcm_msg_head msg_head;

	
	if ((op->flags & RX_ANNOUNCE_RESUME) && op->last_frames) {
		
		memset(op->last_frames, 0, op->nframes * op->cfsiz);
	}

	
	memset(&msg_head, 0, sizeof(msg_head));
	msg_head.opcode  = RX_TIMEOUT;
	msg_head.flags   = op->flags;
	msg_head.count   = op->count;
	msg_head.ival1   = op->ival1;
	msg_head.ival2   = op->ival2;
	msg_head.can_id  = op->can_id;
	msg_head.nframes = 0;

	bcm_send_to_user(op, &msg_head, NULL, 0);

	return HRTIMER_NORESTART;
}


static inline int bcm_rx_do_flush(struct bcm_op *op, unsigned int index)
{
	struct canfd_frame *lcf = op->last_frames + op->cfsiz * index;

	if ((op->last_frames) && (lcf->flags & RX_THR)) {
		bcm_rx_changed(op, lcf);
		return 1;
	}
	return 0;
}


static int bcm_rx_thr_flush(struct bcm_op *op)
{
	int updated = 0;

	if (op->nframes > 1) {
		unsigned int i;

		
		for (i = 1; i < op->nframes; i++)
			updated += bcm_rx_do_flush(op, i);

	} else {
		
		updated += bcm_rx_do_flush(op, 0);
	}

	return updated;
}


static enum hrtimer_restart bcm_rx_thr_handler(struct hrtimer *hrtimer)
{
	struct bcm_op *op = container_of(hrtimer, struct bcm_op, thrtimer);

	if (bcm_rx_thr_flush(op)) {
		hrtimer_forward(hrtimer, ktime_get(), op->kt_ival2);
		return HRTIMER_RESTART;
	} else {
		
		op->kt_lastmsg = 0;
		return HRTIMER_NORESTART;
	}
}


static void bcm_rx_handler(struct sk_buff *skb, void *data)
{
	struct bcm_op *op = (struct bcm_op *)data;
	const struct canfd_frame *rxframe = (struct canfd_frame *)skb->data;
	unsigned int i;

	if (op->can_id != rxframe->can_id)
		return;

	
	if (skb->len != op->cfsiz)
		return;

	
	hrtimer_cancel(&op->timer);

	
	op->rx_stamp = skb->tstamp;
	
	op->rx_ifindex = skb->dev->ifindex;
	
	op->frames_abs++;

	if (op->flags & RX_RTR_FRAME) {
		
		bcm_can_tx(op);
		return;
	}

	if (op->flags & RX_FILTER_ID) {
		
		bcm_rx_update_and_send(op, op->last_frames, rxframe);
		goto rx_starttimer;
	}

	if (op->nframes == 1) {
		
		bcm_rx_cmp_to_index(op, 0, rxframe);
		goto rx_starttimer;
	}

	if (op->nframes > 1) {
		

		for (i = 1; i < op->nframes; i++) {
			if ((get_u64(op->frames, 0) & get_u64(rxframe, 0)) == (get_u64(op->frames, 0) & get_u64(op->frames + op->cfsiz * i, 0))) {

				bcm_rx_cmp_to_index(op, i, rxframe);
				break;
			}
		}
	}

rx_starttimer:
	bcm_rx_starttimer(op);
}


static struct bcm_op *bcm_find_op(struct list_head *ops, struct bcm_msg_head *mh, int ifindex)
{
	struct bcm_op *op;

	list_for_each_entry(op, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) && (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME))
			return op;
	}

	return NULL;
}

static void bcm_remove_op(struct bcm_op *op)
{
	hrtimer_cancel(&op->timer);
	hrtimer_cancel(&op->thrtimer);

	if ((op->frames) && (op->frames != &op->sframe))
		kfree(op->frames);

	if ((op->last_frames) && (op->last_frames != &op->last_sframe))
		kfree(op->last_frames);

	kfree(op);
}

static void bcm_rx_unreg(struct net_device *dev, struct bcm_op *op)
{
	if (op->rx_reg_dev == dev) {
		can_rx_unregister(dev_net(dev), dev, op->can_id, REGMASK(op->can_id), bcm_rx_handler, op);

		
		op->rx_reg_dev = NULL;
	} else printk(KERN_ERR "can-bcm: bcm_rx_unreg: registered device " "mismatch %p %p\n", op->rx_reg_dev, dev);

}


static int bcm_delete_rx_op(struct list_head *ops, struct bcm_msg_head *mh, int ifindex)
{
	struct bcm_op *op, *n;

	list_for_each_entry_safe(op, n, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) && (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME)) {

			
			if (op->ifindex) {
				
				if (op->rx_reg_dev) {
					struct net_device *dev;

					dev = dev_get_by_index(sock_net(op->sk), op->ifindex);
					if (dev) {
						bcm_rx_unreg(dev, op);
						dev_put(dev);
					}
				}
			} else can_rx_unregister(sock_net(op->sk), NULL, op->can_id, REGMASK(op->can_id), bcm_rx_handler, op);




			list_del(&op->list);
			bcm_remove_op(op);
			return 1; 
		}
	}

	return 0; 
}


static int bcm_delete_tx_op(struct list_head *ops, struct bcm_msg_head *mh, int ifindex)
{
	struct bcm_op *op, *n;

	list_for_each_entry_safe(op, n, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) && (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME)) {
			list_del(&op->list);
			bcm_remove_op(op);
			return 1; 
		}
	}

	return 0; 
}


static int bcm_read_op(struct list_head *ops, struct bcm_msg_head *msg_head, int ifindex)
{
	struct bcm_op *op = bcm_find_op(ops, msg_head, ifindex);

	if (!op)
		return -EINVAL;

	
	msg_head->flags   = op->flags;
	msg_head->count   = op->count;
	msg_head->ival1   = op->ival1;
	msg_head->ival2   = op->ival2;
	msg_head->nframes = op->nframes;

	bcm_send_to_user(op, msg_head, op->frames, 0);

	return MHSIZ;
}


static int bcm_tx_setup(struct bcm_msg_head *msg_head, struct msghdr *msg, int ifindex, struct sock *sk)
{
	struct bcm_sock *bo = bcm_sk(sk);
	struct bcm_op *op;
	struct canfd_frame *cf;
	unsigned int i;
	int err;

	
	if (!ifindex)
		return -ENODEV;

	
	if (msg_head->nframes < 1 || msg_head->nframes > MAX_NFRAMES)
		return -EINVAL;

	
	if ((msg_head->flags & SETTIMER) && bcm_is_invalid_tv(msg_head))
		return -EINVAL;

	
	op = bcm_find_op(&bo->tx_ops, msg_head, ifindex);
	if (op) {
		

		
		if (msg_head->nframes > op->nframes)
			return -E2BIG;

		
		for (i = 0; i < msg_head->nframes; i++) {

			cf = op->frames + op->cfsiz * i;
			err = memcpy_from_msg((u8 *)cf, msg, op->cfsiz);

			if (op->flags & CAN_FD_FRAME) {
				if (cf->len > 64)
					err = -EINVAL;
			} else {
				if (cf->len > 8)
					err = -EINVAL;
			}

			if (err < 0)
				return err;

			if (msg_head->flags & TX_CP_CAN_ID) {
				
				cf->can_id = msg_head->can_id;
			}
		}
		op->flags = msg_head->flags;

	} else {
		

		op = kzalloc(OPSIZ, GFP_KERNEL);
		if (!op)
			return -ENOMEM;

		op->can_id = msg_head->can_id;
		op->cfsiz = CFSIZ(msg_head->flags);
		op->flags = msg_head->flags;

		
		if (msg_head->nframes > 1) {
			op->frames = kmalloc_array(msg_head->nframes, op->cfsiz, GFP_KERNEL);

			if (!op->frames) {
				kfree(op);
				return -ENOMEM;
			}
		} else op->frames = &op->sframe;

		for (i = 0; i < msg_head->nframes; i++) {

			cf = op->frames + op->cfsiz * i;
			err = memcpy_from_msg((u8 *)cf, msg, op->cfsiz);

			if (op->flags & CAN_FD_FRAME) {
				if (cf->len > 64)
					err = -EINVAL;
			} else {
				if (cf->len > 8)
					err = -EINVAL;
			}

			if (err < 0) {
				if (op->frames != &op->sframe)
					kfree(op->frames);
				kfree(op);
				return err;
			}

			if (msg_head->flags & TX_CP_CAN_ID) {
				
				cf->can_id = msg_head->can_id;
			}
		}

		
		op->last_frames = NULL;

		
		op->sk = sk;
		op->ifindex = ifindex;

		
		hrtimer_init(&op->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
		op->timer.function = bcm_tx_timeout_handler;

		
		hrtimer_init(&op->thrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);

		
		list_add(&op->list, &bo->tx_ops);

	} 

	if (op->nframes != msg_head->nframes) {
		op->nframes   = msg_head->nframes;
		
		op->currframe = 0;
	}

	

	if (op->flags & TX_RESET_MULTI_IDX) {
		
		op->currframe = 0;
	}

	if (op->flags & SETTIMER) {
		
		op->count = msg_head->count;
		op->ival1 = msg_head->ival1;
		op->ival2 = msg_head->ival2;
		op->kt_ival1 = bcm_timeval_to_ktime(msg_head->ival1);
		op->kt_ival2 = bcm_timeval_to_ktime(msg_head->ival2);

		
		if (!op->kt_ival1 && !op->kt_ival2)
			hrtimer_cancel(&op->timer);
	}

	if (op->flags & STARTTIMER) {
		hrtimer_cancel(&op->timer);
		
		op->flags |= TX_ANNOUNCE;
	}

	if (op->flags & TX_ANNOUNCE) {
		bcm_can_tx(op);
		if (op->count)
			op->count--;
	}

	if (op->flags & STARTTIMER)
		bcm_tx_start_timer(op);

	return msg_head->nframes * op->cfsiz + MHSIZ;
}


static int bcm_rx_setup(struct bcm_msg_head *msg_head, struct msghdr *msg, int ifindex, struct sock *sk)
{
	struct bcm_sock *bo = bcm_sk(sk);
	struct bcm_op *op;
	int do_rx_register;
	int err = 0;

	if ((msg_head->flags & RX_FILTER_ID) || (!(msg_head->nframes))) {
		
		msg_head->flags |= RX_FILTER_ID;
		
		msg_head->nframes = 0;
	}

	
	if (msg_head->nframes > MAX_NFRAMES + 1)
		return -EINVAL;

	if ((msg_head->flags & RX_RTR_FRAME) && ((msg_head->nframes != 1) || (!(msg_head->can_id & CAN_RTR_FLAG))))

		return -EINVAL;

	
	if ((msg_head->flags & SETTIMER) && bcm_is_invalid_tv(msg_head))
		return -EINVAL;

	
	op = bcm_find_op(&bo->rx_ops, msg_head, ifindex);
	if (op) {
		

		
		if (msg_head->nframes > op->nframes)
			return -E2BIG;

		if (msg_head->nframes) {
			
			err = memcpy_from_msg(op->frames, msg, msg_head->nframes * op->cfsiz);
			if (err < 0)
				return err;

			
			memset(op->last_frames, 0, msg_head->nframes * op->cfsiz);
		}

		op->nframes = msg_head->nframes;
		op->flags = msg_head->flags;

		
		do_rx_register = 0;

	} else {
		
		op = kzalloc(OPSIZ, GFP_KERNEL);
		if (!op)
			return -ENOMEM;

		op->can_id = msg_head->can_id;
		op->nframes = msg_head->nframes;
		op->cfsiz = CFSIZ(msg_head->flags);
		op->flags = msg_head->flags;

		if (msg_head->nframes > 1) {
			
			op->frames = kmalloc_array(msg_head->nframes, op->cfsiz, GFP_KERNEL);

			if (!op->frames) {
				kfree(op);
				return -ENOMEM;
			}

			
			op->last_frames = kcalloc(msg_head->nframes, op->cfsiz, GFP_KERNEL);

			if (!op->last_frames) {
				kfree(op->frames);
				kfree(op);
				return -ENOMEM;
			}

		} else {
			op->frames = &op->sframe;
			op->last_frames = &op->last_sframe;
		}

		if (msg_head->nframes) {
			err = memcpy_from_msg(op->frames, msg, msg_head->nframes * op->cfsiz);
			if (err < 0) {
				if (op->frames != &op->sframe)
					kfree(op->frames);
				if (op->last_frames != &op->last_sframe)
					kfree(op->last_frames);
				kfree(op);
				return err;
			}
		}

		
		op->sk = sk;
		op->ifindex = ifindex;

		
		op->rx_ifindex = ifindex;

		
		hrtimer_init(&op->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
		op->timer.function = bcm_rx_timeout_handler;

		hrtimer_init(&op->thrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
		op->thrtimer.function = bcm_rx_thr_handler;

		
		list_add(&op->list, &bo->rx_ops);

		
		do_rx_register = 1;

	} 

	

	if (op->flags & RX_RTR_FRAME) {
		struct canfd_frame *frame0 = op->frames;

		
		hrtimer_cancel(&op->thrtimer);
		hrtimer_cancel(&op->timer);

		
		if ((op->flags & TX_CP_CAN_ID) || (frame0->can_id == op->can_id))
			frame0->can_id = op->can_id & ~CAN_RTR_FLAG;

	} else {
		if (op->flags & SETTIMER) {

			
			op->ival1 = msg_head->ival1;
			op->ival2 = msg_head->ival2;
			op->kt_ival1 = bcm_timeval_to_ktime(msg_head->ival1);
			op->kt_ival2 = bcm_timeval_to_ktime(msg_head->ival2);

			
			if (!op->kt_ival1)
				hrtimer_cancel(&op->timer);

			
			op->kt_lastmsg = 0;
			hrtimer_cancel(&op->thrtimer);
			bcm_rx_thr_flush(op);
		}

		if ((op->flags & STARTTIMER) && op->kt_ival1)
			hrtimer_start(&op->timer, op->kt_ival1, HRTIMER_MODE_REL_SOFT);
	}

	
	if (do_rx_register) {
		if (ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(sock_net(sk), ifindex);
			if (dev) {
				err = can_rx_register(sock_net(sk), dev, op->can_id, REGMASK(op->can_id), bcm_rx_handler, op, "bcm", sk);




				op->rx_reg_dev = dev;
				dev_put(dev);
			}

		} else err = can_rx_register(sock_net(sk), NULL, op->can_id, REGMASK(op->can_id), bcm_rx_handler, op, "bcm", sk);


		if (err) {
			
			list_del(&op->list);
			bcm_remove_op(op);
			return err;
		}
	}

	return msg_head->nframes * op->cfsiz + MHSIZ;
}


static int bcm_tx_send(struct msghdr *msg, int ifindex, struct sock *sk, int cfsiz)
{
	struct sk_buff *skb;
	struct net_device *dev;
	int err;

	
	if (!ifindex)
		return -ENODEV;

	skb = alloc_skb(cfsiz + sizeof(struct can_skb_priv), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	can_skb_reserve(skb);

	err = memcpy_from_msg(skb_put(skb, cfsiz), msg, cfsiz);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}

	dev = dev_get_by_index(sock_net(sk), ifindex);
	if (!dev) {
		kfree_skb(skb);
		return -ENODEV;
	}

	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;
	skb->dev = dev;
	can_skb_set_owner(skb, sk);
	err = can_send(skb, 1); 
	dev_put(dev);

	if (err)
		return err;

	return cfsiz + MHSIZ;
}


static int bcm_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct bcm_sock *bo = bcm_sk(sk);
	int ifindex = bo->ifindex; 
	struct bcm_msg_head msg_head;
	int cfsiz;
	int ret; 

	if (!bo->bound)
		return -ENOTCONN;

	
	if (size < MHSIZ)
		return -EINVAL;

	
	ret = memcpy_from_msg((u8 *)&msg_head, msg, MHSIZ);
	if (ret < 0)
		return ret;

	cfsiz = CFSIZ(msg_head.flags);
	if ((size - MHSIZ) % cfsiz)
		return -EINVAL;

	

	if (!ifindex && msg->msg_name) {
		
		DECLARE_SOCKADDR(struct sockaddr_can *, addr, msg->msg_name);

		if (msg->msg_namelen < BCM_MIN_NAMELEN)
			return -EINVAL;

		if (addr->can_family != AF_CAN)
			return -EINVAL;

		
		ifindex = addr->can_ifindex;

		if (ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(sock_net(sk), ifindex);
			if (!dev)
				return -ENODEV;

			if (dev->type != ARPHRD_CAN) {
				dev_put(dev);
				return -ENODEV;
			}

			dev_put(dev);
		}
	}

	lock_sock(sk);

	switch (msg_head.opcode) {

	case TX_SETUP:
		ret = bcm_tx_setup(&msg_head, msg, ifindex, sk);
		break;

	case RX_SETUP:
		ret = bcm_rx_setup(&msg_head, msg, ifindex, sk);
		break;

	case TX_DELETE:
		if (bcm_delete_tx_op(&bo->tx_ops, &msg_head, ifindex))
			ret = MHSIZ;
		else ret = -EINVAL;
		break;

	case RX_DELETE:
		if (bcm_delete_rx_op(&bo->rx_ops, &msg_head, ifindex))
			ret = MHSIZ;
		else ret = -EINVAL;
		break;

	case TX_READ:
		
		msg_head.opcode  = TX_STATUS;
		ret = bcm_read_op(&bo->tx_ops, &msg_head, ifindex);
		break;

	case RX_READ:
		
		msg_head.opcode  = RX_STATUS;
		ret = bcm_read_op(&bo->rx_ops, &msg_head, ifindex);
		break;

	case TX_SEND:
		
		if ((msg_head.nframes != 1) || (size != cfsiz + MHSIZ))
			ret = -EINVAL;
		else ret = bcm_tx_send(msg, ifindex, sk, cfsiz);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	release_sock(sk);

	return ret;
}


static void bcm_notify(struct bcm_sock *bo, unsigned long msg, struct net_device *dev)
{
	struct sock *sk = &bo->sk;
	struct bcm_op *op;
	int notify_enodev = 0;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		return;

	switch (msg) {

	case NETDEV_UNREGISTER:
		lock_sock(sk);

		
		list_for_each_entry(op, &bo->rx_ops, list)
			if (op->rx_reg_dev == dev)
				bcm_rx_unreg(dev, op);

		
		if (bo->bound && bo->ifindex == dev->ifindex) {
			bo->bound   = 0;
			bo->ifindex = 0;
			notify_enodev = 1;
		}

		release_sock(sk);

		if (notify_enodev) {
			sk->sk_err = ENODEV;
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_error_report(sk);
		}
		break;

	case NETDEV_DOWN:
		if (bo->bound && bo->ifindex == dev->ifindex) {
			sk->sk_err = ENETDOWN;
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_error_report(sk);
		}
	}
}

static int bcm_notifier(struct notifier_block *nb, unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;
	if (msg != NETDEV_UNREGISTER && msg != NETDEV_DOWN)
		return NOTIFY_DONE;
	if (unlikely(bcm_busy_notifier)) 
		return NOTIFY_DONE;

	spin_lock(&bcm_notifier_lock);
	list_for_each_entry(bcm_busy_notifier, &bcm_notifier_list, notifier) {
		spin_unlock(&bcm_notifier_lock);
		bcm_notify(bcm_busy_notifier, msg, dev);
		spin_lock(&bcm_notifier_lock);
	}
	bcm_busy_notifier = NULL;
	spin_unlock(&bcm_notifier_lock);
	return NOTIFY_DONE;
}


static int bcm_init(struct sock *sk)
{
	struct bcm_sock *bo = bcm_sk(sk);

	bo->bound            = 0;
	bo->ifindex          = 0;
	bo->dropped_usr_msgs = 0;
	bo->bcm_proc_read    = NULL;

	INIT_LIST_HEAD(&bo->tx_ops);
	INIT_LIST_HEAD(&bo->rx_ops);

	
	spin_lock(&bcm_notifier_lock);
	list_add_tail(&bo->notifier, &bcm_notifier_list);
	spin_unlock(&bcm_notifier_lock);

	return 0;
}


static int bcm_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct net *net;
	struct bcm_sock *bo;
	struct bcm_op *op, *next;

	if (!sk)
		return 0;

	net = sock_net(sk);
	bo = bcm_sk(sk);

	

	spin_lock(&bcm_notifier_lock);
	while (bcm_busy_notifier == bo) {
		spin_unlock(&bcm_notifier_lock);
		schedule_timeout_uninterruptible(1);
		spin_lock(&bcm_notifier_lock);
	}
	list_del(&bo->notifier);
	spin_unlock(&bcm_notifier_lock);

	lock_sock(sk);

	list_for_each_entry_safe(op, next, &bo->tx_ops, list)
		bcm_remove_op(op);

	list_for_each_entry_safe(op, next, &bo->rx_ops, list) {
		
		if (op->ifindex) {
			
			if (op->rx_reg_dev) {
				struct net_device *dev;

				dev = dev_get_by_index(net, op->ifindex);
				if (dev) {
					bcm_rx_unreg(dev, op);
					dev_put(dev);
				}
			}
		} else can_rx_unregister(net, NULL, op->can_id, REGMASK(op->can_id), bcm_rx_handler, op);



		bcm_remove_op(op);
	}


	
	if (net->can.bcmproc_dir && bo->bcm_proc_read)
		remove_proc_entry(bo->procname, net->can.bcmproc_dir);


	
	if (bo->bound) {
		bo->bound   = 0;
		bo->ifindex = 0;
	}

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int bcm_connect(struct socket *sock, struct sockaddr *uaddr, int len, int flags)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct bcm_sock *bo = bcm_sk(sk);
	struct net *net = sock_net(sk);
	int ret = 0;

	if (len < BCM_MIN_NAMELEN)
		return -EINVAL;

	lock_sock(sk);

	if (bo->bound) {
		ret = -EISCONN;
		goto fail;
	}

	
	if (addr->can_ifindex) {
		struct net_device *dev;

		dev = dev_get_by_index(net, addr->can_ifindex);
		if (!dev) {
			ret = -ENODEV;
			goto fail;
		}
		if (dev->type != ARPHRD_CAN) {
			dev_put(dev);
			ret = -ENODEV;
			goto fail;
		}

		bo->ifindex = dev->ifindex;
		dev_put(dev);

	} else {
		
		bo->ifindex = 0;
	}


	if (net->can.bcmproc_dir) {
		
		sprintf(bo->procname, "%lu", sock_i_ino(sk));
		bo->bcm_proc_read = proc_create_net_single(bo->procname, 0644, net->can.bcmproc_dir, bcm_proc_show, sk);

		if (!bo->bcm_proc_read) {
			ret = -ENOMEM;
			goto fail;
		}
	}


	bo->bound = 1;

fail:
	release_sock(sk);

	return ret;
}

static int bcm_recvmsg(struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int error = 0;
	int noblock;
	int err;

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;
	skb = skb_recv_datagram(sk, flags, noblock, &error);
	if (!skb)
		return error;

	if (skb->len < size)
		size = skb->len;

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(BCM_MIN_NAMELEN);
		msg->msg_namelen = BCM_MIN_NAMELEN;
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}

static int bcm_sock_no_ioctlcmd(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	
	return -ENOIOCTLCMD;
}

static const struct proto_ops bcm_ops = {
	.family        = PF_CAN, .release       = bcm_release, .bind          = sock_no_bind, .connect       = bcm_connect, .socketpair    = sock_no_socketpair, .accept        = sock_no_accept, .getname       = sock_no_getname, .poll          = datagram_poll, .ioctl         = bcm_sock_no_ioctlcmd, .gettstamp     = sock_gettstamp, .listen        = sock_no_listen, .shutdown      = sock_no_shutdown, .sendmsg       = bcm_sendmsg, .recvmsg       = bcm_recvmsg, .mmap          = sock_no_mmap, .sendpage      = sock_no_sendpage, };
















static struct proto bcm_proto __read_mostly = {
	.name       = "CAN_BCM", .owner      = THIS_MODULE, .obj_size   = sizeof(struct bcm_sock), .init       = bcm_init, };




static const struct can_proto bcm_can_proto = {
	.type       = SOCK_DGRAM, .protocol   = CAN_BCM, .ops        = &bcm_ops, .prot       = &bcm_proto, };




static int canbcm_pernet_init(struct net *net)
{

	
	net->can.bcmproc_dir = proc_net_mkdir(net, "can-bcm", net->proc_net);


	return 0;
}

static void canbcm_pernet_exit(struct net *net)
{

	
	if (net->can.bcmproc_dir)
		remove_proc_entry("can-bcm", net->proc_net);

}

static struct pernet_operations canbcm_pernet_ops __read_mostly = {
	.init = canbcm_pernet_init, .exit = canbcm_pernet_exit, };


static struct notifier_block canbcm_notifier = {
	.notifier_call = bcm_notifier };

static int __init bcm_module_init(void)
{
	int err;

	pr_info("can: broadcast manager protocol\n");

	err = can_proto_register(&bcm_can_proto);
	if (err < 0) {
		printk(KERN_ERR "can: registration of bcm protocol failed\n");
		return err;
	}

	register_pernet_subsys(&canbcm_pernet_ops);
	register_netdevice_notifier(&canbcm_notifier);
	return 0;
}

static void __exit bcm_module_exit(void)
{
	can_proto_unregister(&bcm_can_proto);
	unregister_netdevice_notifier(&canbcm_notifier);
	unregister_pernet_subsys(&canbcm_pernet_ops);
}

module_init(bcm_module_init);
module_exit(bcm_module_exit);
