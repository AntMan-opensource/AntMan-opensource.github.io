






























static __le16 ieee80211_duration(struct ieee80211_tx_data *tx, struct sk_buff *skb, int group_addr, int next_frag_len)

{
	int rate, mrate, erp, dur, i, shift = 0;
	struct ieee80211_rate *txrate;
	struct ieee80211_local *local = tx->local;
	struct ieee80211_supported_band *sband;
	struct ieee80211_hdr *hdr;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_chanctx_conf *chanctx_conf;
	u32 rate_flags = 0;

	
	if (tx->rate.flags & (IEEE80211_TX_RC_MCS | IEEE80211_TX_RC_VHT_MCS))
		return 0;

	rcu_read_lock();
	chanctx_conf = rcu_dereference(tx->sdata->vif.chanctx_conf);
	if (chanctx_conf) {
		shift = ieee80211_chandef_get_shift(&chanctx_conf->def);
		rate_flags = ieee80211_chandef_rate_flags(&chanctx_conf->def);
	}
	rcu_read_unlock();

	
	if (WARN_ON_ONCE(tx->rate.idx < 0))
		return 0;

	sband = local->hw.wiphy->bands[info->band];
	txrate = &sband->bitrates[tx->rate.idx];

	erp = txrate->flags & IEEE80211_RATE_ERP_G;

	
	if (sband->band == NL80211_BAND_S1GHZ)
		return 0;

	
	hdr = (struct ieee80211_hdr *)skb->data;
	if (ieee80211_is_ctl(hdr->frame_control)) {
		
		return 0;
	}

	
	if (0 )
		return cpu_to_le16(32768);

	if (group_addr) 
		return 0;

	
	rate = -1;
	
	mrate = sband->bitrates[0].bitrate;
	for (i = 0; i < sband->n_bitrates; i++) {
		struct ieee80211_rate *r = &sband->bitrates[i];

		if (r->bitrate > txrate->bitrate)
			break;

		if ((rate_flags & r->flags) != rate_flags)
			continue;

		if (tx->sdata->vif.bss_conf.basic_rates & BIT(i))
			rate = DIV_ROUND_UP(r->bitrate, 1 << shift);

		switch (sband->band) {
		case NL80211_BAND_2GHZ: {
			u32 flag;
			if (tx->sdata->flags & IEEE80211_SDATA_OPERATING_GMODE)
				flag = IEEE80211_RATE_MANDATORY_G;
			else flag = IEEE80211_RATE_MANDATORY_B;
			if (r->flags & flag)
				mrate = r->bitrate;
			break;
		}
		case NL80211_BAND_5GHZ:
		case NL80211_BAND_6GHZ:
			if (r->flags & IEEE80211_RATE_MANDATORY_A)
				mrate = r->bitrate;
			break;
		case NL80211_BAND_S1GHZ:
		case NL80211_BAND_60GHZ:
			
		case NUM_NL80211_BANDS:
			WARN_ON(1);
			break;
		}
	}
	if (rate == -1) {
		
		rate = DIV_ROUND_UP(mrate, 1 << shift);
	}

	
	if (ieee80211_is_data_qos(hdr->frame_control) && *(ieee80211_get_qos_ctl(hdr)) & IEEE80211_QOS_CTL_ACK_POLICY_NOACK)
		dur = 0;
	else  dur = ieee80211_frame_duration(sband->band, 10, rate, erp, tx->sdata->vif.bss_conf.use_short_preamble, shift);




	if (next_frag_len) {
		
		dur *= 2; 
		
		dur += ieee80211_frame_duration(sband->band, next_frag_len, txrate->bitrate, erp, tx->sdata->vif.bss_conf.use_short_preamble, shift);


	}

	return cpu_to_le16(dur);
}


static ieee80211_tx_result debug_noinline ieee80211_tx_h_dynamic_ps(struct ieee80211_tx_data *tx)
{
	struct ieee80211_local *local = tx->local;
	struct ieee80211_if_managed *ifmgd;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);

	
	if (!ieee80211_hw_check(&local->hw, SUPPORTS_PS))
		return TX_CONTINUE;

	
	if (ieee80211_hw_check(&local->hw, SUPPORTS_DYNAMIC_PS))
		return TX_CONTINUE;

	
	if (local->hw.conf.dynamic_ps_timeout <= 0)
		return TX_CONTINUE;

	
	if (local->scanning)
		return TX_CONTINUE;

	if (!local->ps_sdata)
		return TX_CONTINUE;

	
	if (local->quiescing)
		return TX_CONTINUE;

	
	if (tx->sdata->vif.type != NL80211_IFTYPE_STATION)
		return TX_CONTINUE;

	if (unlikely(info->flags & IEEE80211_TX_INTFL_OFFCHAN_TX_OK))
		return TX_CONTINUE;

	ifmgd = &tx->sdata->u.mgd;

	
	if ((ifmgd->flags & IEEE80211_STA_UAPSD_ENABLED) && (ifmgd->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VO) && skb_get_queue_mapping(tx->skb) == IEEE80211_AC_VO)

		return TX_CONTINUE;

	if (local->hw.conf.flags & IEEE80211_CONF_PS) {
		ieee80211_stop_queues_by_reason(&local->hw, IEEE80211_MAX_QUEUE_MAP, IEEE80211_QUEUE_STOP_REASON_PS, false);


		ifmgd->flags &= ~IEEE80211_STA_NULLFUNC_ACKED;
		ieee80211_queue_work(&local->hw, &local->dynamic_ps_disable_work);
	}

	
	if (!ifmgd->associated)
		return TX_CONTINUE;

	mod_timer(&local->dynamic_ps_timer, jiffies + msecs_to_jiffies(local->hw.conf.dynamic_ps_timeout));

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_check_assoc(struct ieee80211_tx_data *tx)
{

	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx->skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	bool assoc = false;

	if (unlikely(info->flags & IEEE80211_TX_CTL_INJECTED))
		return TX_CONTINUE;

	if (unlikely(test_bit(SCAN_SW_SCANNING, &tx->local->scanning)) && test_bit(SDATA_STATE_OFFCHANNEL, &tx->sdata->state) && !ieee80211_is_probe_req(hdr->frame_control) && !ieee80211_is_any_nullfunc(hdr->frame_control))


		
		return TX_DROP;

	if (tx->sdata->vif.type == NL80211_IFTYPE_OCB)
		return TX_CONTINUE;

	if (tx->flags & IEEE80211_TX_PS_BUFFERED)
		return TX_CONTINUE;

	if (tx->sta)
		assoc = test_sta_flag(tx->sta, WLAN_STA_ASSOC);

	if (likely(tx->flags & IEEE80211_TX_UNICAST)) {
		if (unlikely(!assoc && ieee80211_is_data(hdr->frame_control))) {

			sdata_info(tx->sdata, "dropped data frame to not associated station %pM\n", hdr->addr1);


			I802_DEBUG_INC(tx->local->tx_handlers_drop_not_assoc);
			return TX_DROP;
		}
	} else if (unlikely(ieee80211_is_data(hdr->frame_control) && ieee80211_vif_get_num_mcast_if(tx->sdata) == 0)) {
		
		return TX_DROP;
	}

	return TX_CONTINUE;
}


static void purge_old_ps_buffers(struct ieee80211_local *local)
{
	int total = 0, purged = 0;
	struct sk_buff *skb;
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;

	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		struct ps_data *ps;

		if (sdata->vif.type == NL80211_IFTYPE_AP)
			ps = &sdata->u.ap.ps;
		else if (ieee80211_vif_is_mesh(&sdata->vif))
			ps = &sdata->u.mesh.ps;
		else continue;

		skb = skb_dequeue(&ps->bc_buf);
		if (skb) {
			purged++;
			ieee80211_free_txskb(&local->hw, skb);
		}
		total += skb_queue_len(&ps->bc_buf);
	}

	
	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		int ac;

		for (ac = IEEE80211_AC_BK; ac >= IEEE80211_AC_VO; ac--) {
			skb = skb_dequeue(&sta->ps_tx_buf[ac]);
			total += skb_queue_len(&sta->ps_tx_buf[ac]);
			if (skb) {
				purged++;
				ieee80211_free_txskb(&local->hw, skb);
				break;
			}
		}
	}

	local->total_ps_buffered = total;
	ps_dbg_hw(&local->hw, "PS buffers full - purged %d frames\n", purged);
}

static ieee80211_tx_result ieee80211_tx_h_multicast_ps_buf(struct ieee80211_tx_data *tx)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx->skb->data;
	struct ps_data *ps;

	

	
	if (tx->sdata->vif.type == NL80211_IFTYPE_AP || tx->sdata->vif.type == NL80211_IFTYPE_AP_VLAN) {
		if (!tx->sdata->bss)
			return TX_CONTINUE;

		ps = &tx->sdata->bss->ps;
	} else if (ieee80211_vif_is_mesh(&tx->sdata->vif)) {
		ps = &tx->sdata->u.mesh.ps;
	} else {
		return TX_CONTINUE;
	}


	
	if (ieee80211_has_order(hdr->frame_control))
		return TX_CONTINUE;

	if (ieee80211_is_probe_req(hdr->frame_control))
		return TX_CONTINUE;

	if (ieee80211_hw_check(&tx->local->hw, QUEUE_CONTROL))
		info->hw_queue = tx->sdata->vif.cab_queue;

	
	if (!atomic_read(&ps->num_sta_ps) && skb_queue_empty(&ps->bc_buf))
		return TX_CONTINUE;

	info->flags |= IEEE80211_TX_CTL_SEND_AFTER_DTIM;

	
	if (!ieee80211_hw_check(&tx->local->hw, HOST_BROADCAST_PS_BUFFERING))
		return TX_CONTINUE;

	
	if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
		purge_old_ps_buffers(tx->local);

	if (skb_queue_len(&ps->bc_buf) >= AP_MAX_BC_BUFFER) {
		ps_dbg(tx->sdata, "BC TX buffer full - dropping the oldest frame\n");
		ieee80211_free_txskb(&tx->local->hw, skb_dequeue(&ps->bc_buf));
	} else tx->local->total_ps_buffered++;

	skb_queue_tail(&ps->bc_buf, tx->skb);

	return TX_QUEUED;
}

static int ieee80211_use_mfp(__le16 fc, struct sta_info *sta, struct sk_buff *skb)
{
	if (!ieee80211_is_mgmt(fc))
		return 0;

	if (sta == NULL || !test_sta_flag(sta, WLAN_STA_MFP))
		return 0;

	if (!ieee80211_is_robust_mgmt_frame(skb))
		return 0;

	return 1;
}

static ieee80211_tx_result ieee80211_tx_h_unicast_ps_buf(struct ieee80211_tx_data *tx)
{
	struct sta_info *sta = tx->sta;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx->skb->data;
	struct ieee80211_local *local = tx->local;

	if (unlikely(!sta))
		return TX_CONTINUE;

	if (unlikely((test_sta_flag(sta, WLAN_STA_PS_STA) || test_sta_flag(sta, WLAN_STA_PS_DRIVER) || test_sta_flag(sta, WLAN_STA_PS_DELIVER)) && !(info->flags & IEEE80211_TX_CTL_NO_PS_BUFFER))) {


		int ac = skb_get_queue_mapping(tx->skb);

		if (ieee80211_is_mgmt(hdr->frame_control) && !ieee80211_is_bufferable_mmpdu(hdr->frame_control)) {
			info->flags |= IEEE80211_TX_CTL_NO_PS_BUFFER;
			return TX_CONTINUE;
		}

		ps_dbg(sta->sdata, "STA %pM aid %d: PS buffer for AC %d\n", sta->sta.addr, sta->sta.aid, ac);
		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
			purge_old_ps_buffers(tx->local);

		
		spin_lock(&sta->ps_lock);
		
		if (!test_sta_flag(sta, WLAN_STA_PS_STA) && !test_sta_flag(sta, WLAN_STA_PS_DRIVER) && !test_sta_flag(sta, WLAN_STA_PS_DELIVER)) {

			spin_unlock(&sta->ps_lock);
			return TX_CONTINUE;
		}

		if (skb_queue_len(&sta->ps_tx_buf[ac]) >= STA_MAX_TX_BUFFER) {
			struct sk_buff *old = skb_dequeue(&sta->ps_tx_buf[ac]);
			ps_dbg(tx->sdata, "STA %pM TX buffer for AC %d full - dropping oldest frame\n", sta->sta.addr, ac);

			ieee80211_free_txskb(&local->hw, old);
		} else tx->local->total_ps_buffered++;

		info->control.jiffies = jiffies;
		info->control.vif = &tx->sdata->vif;
		info->control.flags |= IEEE80211_TX_INTCFL_NEED_TXPROCESSING;
		info->flags &= ~IEEE80211_TX_TEMPORARY_FLAGS;
		skb_queue_tail(&sta->ps_tx_buf[ac], tx->skb);
		spin_unlock(&sta->ps_lock);

		if (!timer_pending(&local->sta_cleanup))
			mod_timer(&local->sta_cleanup, round_jiffies(jiffies + STA_INFO_CLEANUP_INTERVAL));


		
		sta_info_recalc_tim(sta);

		return TX_QUEUED;
	} else if (unlikely(test_sta_flag(sta, WLAN_STA_PS_STA))) {
		ps_dbg(tx->sdata, "STA %pM in PS mode, but polling/in SP -> send frame\n", sta->sta.addr);

	}

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_ps_buf(struct ieee80211_tx_data *tx)
{
	if (unlikely(tx->flags & IEEE80211_TX_PS_BUFFERED))
		return TX_CONTINUE;

	if (tx->flags & IEEE80211_TX_UNICAST)
		return ieee80211_tx_h_unicast_ps_buf(tx);
	else return ieee80211_tx_h_multicast_ps_buf(tx);
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_check_control_port_protocol(struct ieee80211_tx_data *tx)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);

	if (unlikely(tx->sdata->control_port_protocol == tx->skb->protocol)) {
		if (tx->sdata->control_port_no_encrypt)
			info->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;
		info->control.flags |= IEEE80211_TX_CTRL_PORT_CTRL_PROTO;
		info->flags |= IEEE80211_TX_CTL_USE_MINRATE;
	}

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_select_key(struct ieee80211_tx_data *tx)
{
	struct ieee80211_key *key;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx->skb->data;

	if (unlikely(info->flags & IEEE80211_TX_INTFL_DONT_ENCRYPT)) {
		tx->key = NULL;
		return TX_CONTINUE;
	}

	if (tx->sta && (key = rcu_dereference(tx->sta->ptk[tx->sta->ptk_idx])))
		tx->key = key;
	else if (ieee80211_is_group_privacy_action(tx->skb) && (key = rcu_dereference(tx->sdata->default_multicast_key)))
		tx->key = key;
	else if (ieee80211_is_mgmt(hdr->frame_control) && is_multicast_ether_addr(hdr->addr1) && ieee80211_is_robust_mgmt_frame(tx->skb) && (key = rcu_dereference(tx->sdata->default_mgmt_key)))


		tx->key = key;
	else if (is_multicast_ether_addr(hdr->addr1) && (key = rcu_dereference(tx->sdata->default_multicast_key)))
		tx->key = key;
	else if (!is_multicast_ether_addr(hdr->addr1) && (key = rcu_dereference(tx->sdata->default_unicast_key)))
		tx->key = key;
	else tx->key = NULL;

	if (tx->key) {
		bool skip_hw = false;

		

		switch (tx->key->conf.cipher) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
		case WLAN_CIPHER_SUITE_TKIP:
			if (!ieee80211_is_data_present(hdr->frame_control))
				tx->key = NULL;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
		case WLAN_CIPHER_SUITE_CCMP_256:
		case WLAN_CIPHER_SUITE_GCMP:
		case WLAN_CIPHER_SUITE_GCMP_256:
			if (!ieee80211_is_data_present(hdr->frame_control) && !ieee80211_use_mfp(hdr->frame_control, tx->sta, tx->skb) && !ieee80211_is_group_privacy_action(tx->skb))


				tx->key = NULL;
			else skip_hw = (tx->key->conf.flags & IEEE80211_KEY_FLAG_SW_MGMT_TX) && ieee80211_is_mgmt(hdr->frame_control);


			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
		case WLAN_CIPHER_SUITE_BIP_CMAC_256:
		case WLAN_CIPHER_SUITE_BIP_GMAC_128:
		case WLAN_CIPHER_SUITE_BIP_GMAC_256:
			if (!ieee80211_is_mgmt(hdr->frame_control))
				tx->key = NULL;
			break;
		}

		if (unlikely(tx->key && tx->key->flags & KEY_FLAG_TAINTED && !ieee80211_is_deauth(hdr->frame_control)))
			return TX_DROP;

		if (!skip_hw && tx->key && tx->key->flags & KEY_FLAG_UPLOADED_TO_HARDWARE)
			info->control.hw_key = &tx->key->conf;
	} else if (ieee80211_is_data_present(hdr->frame_control) && tx->sta && test_sta_flag(tx->sta, WLAN_STA_USES_ENCRYPTION)) {
		return TX_DROP;
	}

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_rate_ctrl(struct ieee80211_tx_data *tx)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_hdr *hdr = (void *)tx->skb->data;
	struct ieee80211_supported_band *sband;
	u32 len;
	struct ieee80211_tx_rate_control txrc;
	struct ieee80211_sta_rates *ratetbl = NULL;
	bool assoc = false;

	memset(&txrc, 0, sizeof(txrc));

	sband = tx->local->hw.wiphy->bands[info->band];

	len = min_t(u32, tx->skb->len + FCS_LEN, tx->local->hw.wiphy->frag_threshold);

	
	txrc.hw = &tx->local->hw;
	txrc.sband = sband;
	txrc.bss_conf = &tx->sdata->vif.bss_conf;
	txrc.skb = tx->skb;
	txrc.reported_rate.idx = -1;
	txrc.rate_idx_mask = tx->sdata->rc_rateidx_mask[info->band];

	if (tx->sdata->rc_has_mcs_mask[info->band])
		txrc.rate_idx_mcs_mask = tx->sdata->rc_rateidx_mcs_mask[info->band];

	txrc.bss = (tx->sdata->vif.type == NL80211_IFTYPE_AP || tx->sdata->vif.type == NL80211_IFTYPE_MESH_POINT || tx->sdata->vif.type == NL80211_IFTYPE_ADHOC || tx->sdata->vif.type == NL80211_IFTYPE_OCB);



	
	if (len > tx->local->hw.wiphy->rts_threshold) {
		txrc.rts = true;
	}

	info->control.use_rts = txrc.rts;
	info->control.use_cts_prot = tx->sdata->vif.bss_conf.use_cts_prot;

	
	if (tx->sdata->vif.bss_conf.use_short_preamble && (ieee80211_is_data(hdr->frame_control) || (tx->sta && test_sta_flag(tx->sta, WLAN_STA_SHORT_PREAMBLE))))

		txrc.short_preamble = true;

	info->control.short_preamble = txrc.short_preamble;

	
	if (info->control.flags & IEEE80211_TX_CTRL_RATE_INJECT)
		return TX_CONTINUE;

	if (tx->sta)
		assoc = test_sta_flag(tx->sta, WLAN_STA_ASSOC);

	
	if (WARN(test_bit(SCAN_SW_SCANNING, &tx->local->scanning) && assoc && !rate_usable_index_exists(sband, &tx->sta->sta), "%s: Dropped data frame as no usable bitrate found while " "scanning and associated. Target station: " "%pM on %d GHz band\n", tx->sdata->name, hdr->addr1, info->band ? 5 : 2))





		return TX_DROP;

	
	rate_control_get_rate(tx->sdata, tx->sta, &txrc);

	if (tx->sta && !info->control.skip_table)
		ratetbl = rcu_dereference(tx->sta->sta.rates);

	if (unlikely(info->control.rates[0].idx < 0)) {
		if (ratetbl) {
			struct ieee80211_tx_rate rate = {
				.idx = ratetbl->rate[0].idx, .flags = ratetbl->rate[0].flags, .count = ratetbl->rate[0].count };



			if (ratetbl->rate[0].idx < 0)
				return TX_DROP;

			tx->rate = rate;
		} else {
			return TX_DROP;
		}
	} else {
		tx->rate = info->control.rates[0];
	}

	if (txrc.reported_rate.idx < 0) {
		txrc.reported_rate = tx->rate;
		if (tx->sta && ieee80211_is_data(hdr->frame_control))
			tx->sta->tx_stats.last_rate = txrc.reported_rate;
	} else if (tx->sta)
		tx->sta->tx_stats.last_rate = txrc.reported_rate;

	if (ratetbl)
		return TX_CONTINUE;

	if (unlikely(!info->control.rates[0].count))
		info->control.rates[0].count = 1;

	if (WARN_ON_ONCE((info->control.rates[0].count > 1) && (info->flags & IEEE80211_TX_CTL_NO_ACK)))
		info->control.rates[0].count = 1;

	return TX_CONTINUE;
}

static __le16 ieee80211_tx_next_seq(struct sta_info *sta, int tid)
{
	u16 *seq = &sta->tid_seq[tid];
	__le16 ret = cpu_to_le16(*seq);

	
	*seq = (*seq + 0x10) & IEEE80211_SCTL_SEQ;

	return ret;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_sequence(struct ieee80211_tx_data *tx)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)tx->skb->data;
	int tid;

	
	if (unlikely(info->control.vif->type == NL80211_IFTYPE_MONITOR))
		return TX_CONTINUE;

	if (unlikely(ieee80211_is_ctl(hdr->frame_control)))
		return TX_CONTINUE;

	if (ieee80211_hdrlen(hdr->frame_control) < 24)
		return TX_CONTINUE;

	if (ieee80211_is_qos_nullfunc(hdr->frame_control))
		return TX_CONTINUE;

	if (info->control.flags & IEEE80211_TX_CTRL_NO_SEQNO)
		return TX_CONTINUE;

	
	if (!ieee80211_is_data_qos(hdr->frame_control) || is_multicast_ether_addr(hdr->addr1)) {
		
		info->flags |= IEEE80211_TX_CTL_ASSIGN_SEQ;
		
		hdr->seq_ctrl = cpu_to_le16(tx->sdata->sequence_number);
		tx->sdata->sequence_number += 0x10;
		if (tx->sta)
			tx->sta->tx_stats.msdu[IEEE80211_NUM_TIDS]++;
		return TX_CONTINUE;
	}

	
	if (!tx->sta)
		return TX_CONTINUE;

	
	tid = ieee80211_get_tid(hdr);
	tx->sta->tx_stats.msdu[tid]++;

	hdr->seq_ctrl = ieee80211_tx_next_seq(tx->sta, tid);

	return TX_CONTINUE;
}

static int ieee80211_fragment(struct ieee80211_tx_data *tx, struct sk_buff *skb, int hdrlen, int frag_threshold)

{
	struct ieee80211_local *local = tx->local;
	struct ieee80211_tx_info *info;
	struct sk_buff *tmp;
	int per_fragm = frag_threshold - hdrlen - FCS_LEN;
	int pos = hdrlen + per_fragm;
	int rem = skb->len - hdrlen - per_fragm;

	if (WARN_ON(rem < 0))
		return -EINVAL;

	

	while (rem) {
		int fraglen = per_fragm;

		if (fraglen > rem)
			fraglen = rem;
		rem -= fraglen;
		tmp = dev_alloc_skb(local->tx_headroom + frag_threshold + tx->sdata->encrypt_headroom + IEEE80211_ENCRYPT_TAILROOM);


		if (!tmp)
			return -ENOMEM;

		__skb_queue_tail(&tx->skbs, tmp);

		skb_reserve(tmp, local->tx_headroom + tx->sdata->encrypt_headroom);

		
		memcpy(tmp->cb, skb->cb, sizeof(tmp->cb));

		info = IEEE80211_SKB_CB(tmp);
		info->flags &= ~(IEEE80211_TX_CTL_CLEAR_PS_FILT | IEEE80211_TX_CTL_FIRST_FRAGMENT);

		if (rem)
			info->flags |= IEEE80211_TX_CTL_MORE_FRAMES;

		skb_copy_queue_mapping(tmp, skb);
		tmp->priority = skb->priority;
		tmp->dev = skb->dev;

		
		skb_put_data(tmp, skb->data, hdrlen);
		skb_put_data(tmp, skb->data + pos, fraglen);

		pos += fraglen;
	}

	
	skb_trim(skb, hdrlen + per_fragm);
	return 0;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_fragment(struct ieee80211_tx_data *tx)
{
	struct sk_buff *skb = tx->skb;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (void *)skb->data;
	int frag_threshold = tx->local->hw.wiphy->frag_threshold;
	int hdrlen;
	int fragnum;

	
	__skb_queue_tail(&tx->skbs, skb);
	tx->skb = NULL;

	if (info->flags & IEEE80211_TX_CTL_DONTFRAG)
		return TX_CONTINUE;

	if (ieee80211_hw_check(&tx->local->hw, SUPPORTS_TX_FRAG))
		return TX_CONTINUE;

	
	if (WARN_ON(info->flags & IEEE80211_TX_CTL_AMPDU))
		return TX_DROP;

	hdrlen = ieee80211_hdrlen(hdr->frame_control);

	
	if (WARN_ON(skb->len + FCS_LEN <= frag_threshold))
		return TX_DROP;

	
	if (ieee80211_fragment(tx, skb, hdrlen, frag_threshold))
		return TX_DROP;

	
	fragnum = 0;

	skb_queue_walk(&tx->skbs, skb) {
		const __le16 morefrags = cpu_to_le16(IEEE80211_FCTL_MOREFRAGS);

		hdr = (void *)skb->data;
		info = IEEE80211_SKB_CB(skb);

		if (!skb_queue_is_last(&tx->skbs, skb)) {
			hdr->frame_control |= morefrags;
			
			info->control.rates[1].idx = -1;
			info->control.rates[2].idx = -1;
			info->control.rates[3].idx = -1;
			BUILD_BUG_ON(IEEE80211_TX_MAX_RATES != 4);
			info->flags &= ~IEEE80211_TX_CTL_RATE_CTRL_PROBE;
		} else {
			hdr->frame_control &= ~morefrags;
		}
		hdr->seq_ctrl |= cpu_to_le16(fragnum & IEEE80211_SCTL_FRAG);
		fragnum++;
	}

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_stats(struct ieee80211_tx_data *tx)
{
	struct sk_buff *skb;
	int ac = -1;

	if (!tx->sta)
		return TX_CONTINUE;

	skb_queue_walk(&tx->skbs, skb) {
		ac = skb_get_queue_mapping(skb);
		tx->sta->tx_stats.bytes[ac] += skb->len;
	}
	if (ac >= 0)
		tx->sta->tx_stats.packets[ac]++;

	return TX_CONTINUE;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_encrypt(struct ieee80211_tx_data *tx)
{
	if (!tx->key)
		return TX_CONTINUE;

	switch (tx->key->conf.cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		return ieee80211_crypto_wep_encrypt(tx);
	case WLAN_CIPHER_SUITE_TKIP:
		return ieee80211_crypto_tkip_encrypt(tx);
	case WLAN_CIPHER_SUITE_CCMP:
		return ieee80211_crypto_ccmp_encrypt( tx, IEEE80211_CCMP_MIC_LEN);
	case WLAN_CIPHER_SUITE_CCMP_256:
		return ieee80211_crypto_ccmp_encrypt( tx, IEEE80211_CCMP_256_MIC_LEN);
	case WLAN_CIPHER_SUITE_AES_CMAC:
		return ieee80211_crypto_aes_cmac_encrypt(tx);
	case WLAN_CIPHER_SUITE_BIP_CMAC_256:
		return ieee80211_crypto_aes_cmac_256_encrypt(tx);
	case WLAN_CIPHER_SUITE_BIP_GMAC_128:
	case WLAN_CIPHER_SUITE_BIP_GMAC_256:
		return ieee80211_crypto_aes_gmac_encrypt(tx);
	case WLAN_CIPHER_SUITE_GCMP:
	case WLAN_CIPHER_SUITE_GCMP_256:
		return ieee80211_crypto_gcmp_encrypt(tx);
	default:
		return ieee80211_crypto_hw_encrypt(tx);
	}

	return TX_DROP;
}

static ieee80211_tx_result debug_noinline ieee80211_tx_h_calculate_duration(struct ieee80211_tx_data *tx)
{
	struct sk_buff *skb;
	struct ieee80211_hdr *hdr;
	int next_len;
	bool group_addr;

	skb_queue_walk(&tx->skbs, skb) {
		hdr = (void *) skb->data;
		if (unlikely(ieee80211_is_pspoll(hdr->frame_control)))
			break; 
		if (!skb_queue_is_last(&tx->skbs, skb)) {
			struct sk_buff *next = skb_queue_next(&tx->skbs, skb);
			next_len = next->len;
		} else next_len = 0;
		group_addr = is_multicast_ether_addr(hdr->addr1);

		hdr->duration_id = ieee80211_duration(tx, skb, group_addr, next_len);
	}

	return TX_CONTINUE;
}



static bool ieee80211_tx_prep_agg(struct ieee80211_tx_data *tx, struct sk_buff *skb, struct ieee80211_tx_info *info, struct tid_ampdu_tx *tid_tx, int tid)



{
	bool queued = false;
	bool reset_agg_timer = false;
	struct sk_buff *purge_skb = NULL;

	if (test_bit(HT_AGG_STATE_OPERATIONAL, &tid_tx->state)) {
		info->flags |= IEEE80211_TX_CTL_AMPDU;
		reset_agg_timer = true;
	} else if (test_bit(HT_AGG_STATE_WANT_START, &tid_tx->state)) {
		
	} else if (!tx->sta->sta.txq[tid]) {
		spin_lock(&tx->sta->lock);
		
		tid_tx = rcu_dereference_protected_tid_tx(tx->sta, tid);

		if (!tid_tx) {
			
		} else if (test_bit(HT_AGG_STATE_OPERATIONAL, &tid_tx->state)) {
			info->flags |= IEEE80211_TX_CTL_AMPDU;
			reset_agg_timer = true;
		} else {
			queued = true;
			if (info->flags & IEEE80211_TX_CTL_NO_PS_BUFFER) {
				clear_sta_flag(tx->sta, WLAN_STA_SP);
				ps_dbg(tx->sta->sdata, "STA %pM aid %d: SP frame queued, close the SP w/o telling the peer\n", tx->sta->sta.addr, tx->sta->sta.aid);

			}
			info->control.vif = &tx->sdata->vif;
			info->control.flags |= IEEE80211_TX_INTCFL_NEED_TXPROCESSING;
			info->flags &= ~IEEE80211_TX_TEMPORARY_FLAGS;
			__skb_queue_tail(&tid_tx->pending, skb);
			if (skb_queue_len(&tid_tx->pending) > STA_MAX_TX_BUFFER)
				purge_skb = __skb_dequeue(&tid_tx->pending);
		}
		spin_unlock(&tx->sta->lock);

		if (purge_skb)
			ieee80211_free_txskb(&tx->local->hw, purge_skb);
	}

	
	if (reset_agg_timer)
		tid_tx->last_tx = jiffies;

	return queued;
}


static ieee80211_tx_result ieee80211_tx_prepare(struct ieee80211_sub_if_data *sdata, struct ieee80211_tx_data *tx, struct sta_info *sta, struct sk_buff *skb)


{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_hdr *hdr;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	int tid;

	memset(tx, 0, sizeof(*tx));
	tx->skb = skb;
	tx->local = local;
	tx->sdata = sdata;
	__skb_queue_head_init(&tx->skbs);

	
	info->control.flags &= ~IEEE80211_TX_INTCFL_NEED_TXPROCESSING;

	hdr = (struct ieee80211_hdr *) skb->data;

	if (likely(sta)) {
		if (!IS_ERR(sta))
			tx->sta = sta;
	} else {
		if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN) {
			tx->sta = rcu_dereference(sdata->u.vlan.sta);
			if (!tx->sta && sdata->wdev.use_4addr)
				return TX_DROP;
		} else if (tx->sdata->control_port_protocol == tx->skb->protocol) {
			tx->sta = sta_info_get_bss(sdata, hdr->addr1);
		}
		if (!tx->sta && !is_multicast_ether_addr(hdr->addr1))
			tx->sta = sta_info_get(sdata, hdr->addr1);
	}

	if (tx->sta && ieee80211_is_data_qos(hdr->frame_control) && !ieee80211_is_qos_nullfunc(hdr->frame_control) && ieee80211_hw_check(&local->hw, AMPDU_AGGREGATION) && !ieee80211_hw_check(&local->hw, TX_AMPDU_SETUP_IN_HW)) {


		struct tid_ampdu_tx *tid_tx;

		tid = ieee80211_get_tid(hdr);

		tid_tx = rcu_dereference(tx->sta->ampdu_mlme.tid_tx[tid]);
		if (tid_tx) {
			bool queued;

			queued = ieee80211_tx_prep_agg(tx, skb, info, tid_tx, tid);

			if (unlikely(queued))
				return TX_QUEUED;
		}
	}

	if (is_multicast_ether_addr(hdr->addr1)) {
		tx->flags &= ~IEEE80211_TX_UNICAST;
		info->flags |= IEEE80211_TX_CTL_NO_ACK;
	} else tx->flags |= IEEE80211_TX_UNICAST;

	if (!(info->flags & IEEE80211_TX_CTL_DONTFRAG)) {
		if (!(tx->flags & IEEE80211_TX_UNICAST) || skb->len + FCS_LEN <= local->hw.wiphy->frag_threshold || info->flags & IEEE80211_TX_CTL_AMPDU)

			info->flags |= IEEE80211_TX_CTL_DONTFRAG;
	}

	if (!tx->sta)
		info->flags |= IEEE80211_TX_CTL_CLEAR_PS_FILT;
	else if (test_and_clear_sta_flag(tx->sta, WLAN_STA_CLEAR_PS_FILT)) {
		info->flags |= IEEE80211_TX_CTL_CLEAR_PS_FILT;
		ieee80211_check_fast_xmit(tx->sta);
	}

	info->flags |= IEEE80211_TX_CTL_FIRST_FRAGMENT;

	return TX_CONTINUE;
}

static struct txq_info *ieee80211_get_txq(struct ieee80211_local *local, struct ieee80211_vif *vif, struct sta_info *sta, struct sk_buff *skb)


{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_txq *txq = NULL;

	if ((info->flags & IEEE80211_TX_CTL_SEND_AFTER_DTIM) || (info->control.flags & IEEE80211_TX_CTRL_PS_RESPONSE))
		return NULL;

	if (!(info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP) && unlikely(!ieee80211_is_data_present(hdr->frame_control))) {
		if ((!ieee80211_is_mgmt(hdr->frame_control) || ieee80211_is_bufferable_mmpdu(hdr->frame_control) || vif->type == NL80211_IFTYPE_STATION) && sta && sta->uploaded) {


			
			txq = sta->sta.txq[IEEE80211_NUM_TIDS];
		}
	} else if (sta) {
		u8 tid = skb->priority & IEEE80211_QOS_CTL_TID_MASK;

		if (!sta->uploaded)
			return NULL;

		txq = sta->sta.txq[tid];
	} else if (vif) {
		txq = vif->txq;
	}

	if (!txq)
		return NULL;

	return to_txq_info(txq);
}

static void ieee80211_set_skb_enqueue_time(struct sk_buff *skb)
{
	IEEE80211_SKB_CB(skb)->control.enqueue_time = codel_get_time();
}

static u32 codel_skb_len_func(const struct sk_buff *skb)
{
	return skb->len;
}

static codel_time_t codel_skb_time_func(const struct sk_buff *skb)
{
	const struct ieee80211_tx_info *info;

	info = (const struct ieee80211_tx_info *)skb->cb;
	return info->control.enqueue_time;
}

static struct sk_buff *codel_dequeue_func(struct codel_vars *cvars, void *ctx)
{
	struct ieee80211_local *local;
	struct txq_info *txqi;
	struct fq *fq;
	struct fq_flow *flow;

	txqi = ctx;
	local = vif_to_sdata(txqi->txq.vif)->local;
	fq = &local->fq;

	if (cvars == &txqi->def_cvars)
		flow = &txqi->tin.default_flow;
	else flow = &fq->flows[cvars - local->cvars];

	return fq_flow_dequeue(fq, flow);
}

static void codel_drop_func(struct sk_buff *skb, void *ctx)
{
	struct ieee80211_local *local;
	struct ieee80211_hw *hw;
	struct txq_info *txqi;

	txqi = ctx;
	local = vif_to_sdata(txqi->txq.vif)->local;
	hw = &local->hw;

	ieee80211_free_txskb(hw, skb);
}

static struct sk_buff *fq_tin_dequeue_func(struct fq *fq, struct fq_tin *tin, struct fq_flow *flow)

{
	struct ieee80211_local *local;
	struct txq_info *txqi;
	struct codel_vars *cvars;
	struct codel_params *cparams;
	struct codel_stats *cstats;

	local = container_of(fq, struct ieee80211_local, fq);
	txqi = container_of(tin, struct txq_info, tin);
	cstats = &txqi->cstats;

	if (txqi->txq.sta) {
		struct sta_info *sta = container_of(txqi->txq.sta, struct sta_info, sta);
		cparams = &sta->cparams;
	} else {
		cparams = &local->cparams;
	}

	if (flow == &tin->default_flow)
		cvars = &txqi->def_cvars;
	else cvars = &local->cvars[flow - fq->flows];

	return codel_dequeue(txqi, &flow->backlog, cparams, cvars, cstats, codel_skb_len_func, codel_skb_time_func, codel_drop_func, codel_dequeue_func);







}

static void fq_skb_free_func(struct fq *fq, struct fq_tin *tin, struct fq_flow *flow, struct sk_buff *skb)


{
	struct ieee80211_local *local;

	local = container_of(fq, struct ieee80211_local, fq);
	ieee80211_free_txskb(&local->hw, skb);
}

static void ieee80211_txq_enqueue(struct ieee80211_local *local, struct txq_info *txqi, struct sk_buff *skb)

{
	struct fq *fq = &local->fq;
	struct fq_tin *tin = &txqi->tin;
	u32 flow_idx = fq_flow_idx(fq, skb);

	ieee80211_set_skb_enqueue_time(skb);

	spin_lock_bh(&fq->lock);
	
	if (unlikely(txqi->txq.tid == IEEE80211_NUM_TIDS)) {
		IEEE80211_SKB_CB(skb)->control.flags |= IEEE80211_TX_INTCFL_NEED_TXPROCESSING;
		__skb_queue_tail(&txqi->frags, skb);
	} else {
		fq_tin_enqueue(fq, tin, flow_idx, skb, fq_skb_free_func);
	}
	spin_unlock_bh(&fq->lock);
}

static bool fq_vlan_filter_func(struct fq *fq, struct fq_tin *tin, struct fq_flow *flow, struct sk_buff *skb, void *data)

{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	return info->control.vif == data;
}

void ieee80211_txq_remove_vlan(struct ieee80211_local *local, struct ieee80211_sub_if_data *sdata)
{
	struct fq *fq = &local->fq;
	struct txq_info *txqi;
	struct fq_tin *tin;
	struct ieee80211_sub_if_data *ap;

	if (WARN_ON(sdata->vif.type != NL80211_IFTYPE_AP_VLAN))
		return;

	ap = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);

	if (!ap->vif.txq)
		return;

	txqi = to_txq_info(ap->vif.txq);
	tin = &txqi->tin;

	spin_lock_bh(&fq->lock);
	fq_tin_filter(fq, tin, fq_vlan_filter_func, &sdata->vif, fq_skb_free_func);
	spin_unlock_bh(&fq->lock);
}

void ieee80211_txq_init(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct txq_info *txqi, int tid)

{
	fq_tin_init(&txqi->tin);
	codel_vars_init(&txqi->def_cvars);
	codel_stats_init(&txqi->cstats);
	__skb_queue_head_init(&txqi->frags);
	INIT_LIST_HEAD(&txqi->schedule_order);

	txqi->txq.vif = &sdata->vif;

	if (!sta) {
		sdata->vif.txq = &txqi->txq;
		txqi->txq.tid = 0;
		txqi->txq.ac = IEEE80211_AC_BE;

		return;
	}

	if (tid == IEEE80211_NUM_TIDS) {
		if (sdata->vif.type == NL80211_IFTYPE_STATION) {
			
			if (!ieee80211_hw_check(&sdata->local->hw, STA_MMPDU_TXQ))
				return;
		} else if (!ieee80211_hw_check(&sdata->local->hw, BUFF_MMPDU_TXQ)) {
			
			return;
		}
		txqi->txq.ac = IEEE80211_AC_VO;
	} else {
		txqi->txq.ac = ieee80211_ac_from_tid(tid);
	}

	txqi->txq.sta = &sta->sta;
	txqi->txq.tid = tid;
	sta->sta.txq[tid] = &txqi->txq;
}

void ieee80211_txq_purge(struct ieee80211_local *local, struct txq_info *txqi)
{
	struct fq *fq = &local->fq;
	struct fq_tin *tin = &txqi->tin;

	spin_lock_bh(&fq->lock);
	fq_tin_reset(fq, tin, fq_skb_free_func);
	ieee80211_purge_tx_queue(&local->hw, &txqi->frags);
	spin_unlock_bh(&fq->lock);

	spin_lock_bh(&local->active_txq_lock[txqi->txq.ac]);
	list_del_init(&txqi->schedule_order);
	spin_unlock_bh(&local->active_txq_lock[txqi->txq.ac]);
}

void ieee80211_txq_set_params(struct ieee80211_local *local)
{
	if (local->hw.wiphy->txq_limit)
		local->fq.limit = local->hw.wiphy->txq_limit;
	else local->hw.wiphy->txq_limit = local->fq.limit;

	if (local->hw.wiphy->txq_memory_limit)
		local->fq.memory_limit = local->hw.wiphy->txq_memory_limit;
	else local->hw.wiphy->txq_memory_limit = local->fq.memory_limit;

	if (local->hw.wiphy->txq_quantum)
		local->fq.quantum = local->hw.wiphy->txq_quantum;
	else local->hw.wiphy->txq_quantum = local->fq.quantum;
}

int ieee80211_txq_setup_flows(struct ieee80211_local *local)
{
	struct fq *fq = &local->fq;
	int ret;
	int i;
	bool supp_vht = false;
	enum nl80211_band band;

	if (!local->ops->wake_tx_queue)
		return 0;

	ret = fq_init(fq, 4096);
	if (ret)
		return ret;

	
	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		struct ieee80211_supported_band *sband;

		sband = local->hw.wiphy->bands[band];
		if (!sband)
			continue;

		supp_vht = supp_vht || sband->vht_cap.vht_supported;
	}

	if (!supp_vht)
		fq->memory_limit = 4 << 20; 

	codel_params_init(&local->cparams);
	local->cparams.interval = MS2TIME(100);
	local->cparams.target = MS2TIME(20);
	local->cparams.ecn = true;

	local->cvars = kcalloc(fq->flows_cnt, sizeof(local->cvars[0]), GFP_KERNEL);
	if (!local->cvars) {
		spin_lock_bh(&fq->lock);
		fq_reset(fq, fq_skb_free_func);
		spin_unlock_bh(&fq->lock);
		return -ENOMEM;
	}

	for (i = 0; i < fq->flows_cnt; i++)
		codel_vars_init(&local->cvars[i]);

	ieee80211_txq_set_params(local);

	return 0;
}

void ieee80211_txq_teardown_flows(struct ieee80211_local *local)
{
	struct fq *fq = &local->fq;

	if (!local->ops->wake_tx_queue)
		return;

	kfree(local->cvars);
	local->cvars = NULL;

	spin_lock_bh(&fq->lock);
	fq_reset(fq, fq_skb_free_func);
	spin_unlock_bh(&fq->lock);
}

static bool ieee80211_queue_skb(struct ieee80211_local *local, struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct sk_buff *skb)


{
	struct ieee80211_vif *vif;
	struct txq_info *txqi;

	if (!local->ops->wake_tx_queue || sdata->vif.type == NL80211_IFTYPE_MONITOR)
		return false;

	if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
		sdata = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);

	vif = &sdata->vif;
	txqi = ieee80211_get_txq(local, vif, sta, skb);

	if (!txqi)
		return false;

	ieee80211_txq_enqueue(local, txqi, skb);

	schedule_and_wake_txq(local, txqi);

	return true;
}

static bool ieee80211_tx_frags(struct ieee80211_local *local, struct ieee80211_vif *vif, struct sta_info *sta, struct sk_buff_head *skbs, bool txpending)



{
	struct ieee80211_tx_control control = {};
	struct sk_buff *skb, *tmp;
	unsigned long flags;

	skb_queue_walk_safe(skbs, skb, tmp) {
		struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
		int q = info->hw_queue;


		if (WARN_ON_ONCE(q >= local->hw.queues)) {
			__skb_unlink(skb, skbs);
			ieee80211_free_txskb(&local->hw, skb);
			continue;
		}


		spin_lock_irqsave(&local->queue_stop_reason_lock, flags);
		if (local->queue_stop_reasons[q] || (!txpending && !skb_queue_empty(&local->pending[q]))) {
			if (unlikely(info->flags & IEEE80211_TX_INTFL_OFFCHAN_TX_OK)) {
				if (local->queue_stop_reasons[q] & ~BIT(IEEE80211_QUEUE_STOP_REASON_OFFCHANNEL)) {
					
					spin_unlock_irqrestore( &local->queue_stop_reason_lock, flags);

					ieee80211_purge_tx_queue(&local->hw, skbs);
					return true;
				}
			} else {

				
				if (txpending)
					skb_queue_splice_init(skbs, &local->pending[q]);
				else skb_queue_splice_tail_init(skbs, &local->pending[q]);


				spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);
				return false;
			}
		}
		spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

		info->control.vif = vif;
		control.sta = sta ? &sta->sta : NULL;

		__skb_unlink(skb, skbs);
		drv_tx(local, &control, skb);
	}

	return true;
}


static bool __ieee80211_tx(struct ieee80211_local *local, struct sk_buff_head *skbs, int led_len, struct sta_info *sta, bool txpending)

{
	struct ieee80211_tx_info *info;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_vif *vif;
	struct sk_buff *skb;
	bool result;
	__le16 fc;

	if (WARN_ON(skb_queue_empty(skbs)))
		return true;

	skb = skb_peek(skbs);
	fc = ((struct ieee80211_hdr *)skb->data)->frame_control;
	info = IEEE80211_SKB_CB(skb);
	sdata = vif_to_sdata(info->control.vif);
	if (sta && !sta->uploaded)
		sta = NULL;

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_MONITOR:
		if (sdata->u.mntr.flags & MONITOR_FLAG_ACTIVE) {
			vif = &sdata->vif;
			break;
		}
		sdata = rcu_dereference(local->monitor_sdata);
		if (sdata) {
			vif = &sdata->vif;
			info->hw_queue = vif->hw_queue[skb_get_queue_mapping(skb)];
		} else if (ieee80211_hw_check(&local->hw, QUEUE_CONTROL)) {
			ieee80211_purge_tx_queue(&local->hw, skbs);
			return true;
		} else vif = NULL;
		break;
	case NL80211_IFTYPE_AP_VLAN:
		sdata = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);
		fallthrough;
	default:
		vif = &sdata->vif;
		break;
	}

	result = ieee80211_tx_frags(local, vif, sta, skbs, txpending);

	ieee80211_tpt_led_trig_tx(local, fc, led_len);

	WARN_ON_ONCE(!skb_queue_empty(skbs));

	return result;
}


static int invoke_tx_handlers_early(struct ieee80211_tx_data *tx)
{
	ieee80211_tx_result res = TX_DROP;







	CALL_TXH(ieee80211_tx_h_dynamic_ps);
	CALL_TXH(ieee80211_tx_h_check_assoc);
	CALL_TXH(ieee80211_tx_h_ps_buf);
	CALL_TXH(ieee80211_tx_h_check_control_port_protocol);
	CALL_TXH(ieee80211_tx_h_select_key);
	if (!ieee80211_hw_check(&tx->local->hw, HAS_RATE_CONTROL))
		CALL_TXH(ieee80211_tx_h_rate_ctrl);

 txh_done:
	if (unlikely(res == TX_DROP)) {
		I802_DEBUG_INC(tx->local->tx_handlers_drop);
		if (tx->skb)
			ieee80211_free_txskb(&tx->local->hw, tx->skb);
		else ieee80211_purge_tx_queue(&tx->local->hw, &tx->skbs);
		return -1;
	} else if (unlikely(res == TX_QUEUED)) {
		I802_DEBUG_INC(tx->local->tx_handlers_queued);
		return -1;
	}

	return 0;
}


static int invoke_tx_handlers_late(struct ieee80211_tx_data *tx)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
	ieee80211_tx_result res = TX_CONTINUE;

	if (unlikely(info->flags & IEEE80211_TX_INTFL_RETRANSMISSION)) {
		__skb_queue_tail(&tx->skbs, tx->skb);
		tx->skb = NULL;
		goto txh_done;
	}

	CALL_TXH(ieee80211_tx_h_michael_mic_add);
	CALL_TXH(ieee80211_tx_h_sequence);
	CALL_TXH(ieee80211_tx_h_fragment);
	
	CALL_TXH(ieee80211_tx_h_stats);
	CALL_TXH(ieee80211_tx_h_encrypt);
	if (!ieee80211_hw_check(&tx->local->hw, HAS_RATE_CONTROL))
		CALL_TXH(ieee80211_tx_h_calculate_duration);


 txh_done:
	if (unlikely(res == TX_DROP)) {
		I802_DEBUG_INC(tx->local->tx_handlers_drop);
		if (tx->skb)
			ieee80211_free_txskb(&tx->local->hw, tx->skb);
		else ieee80211_purge_tx_queue(&tx->local->hw, &tx->skbs);
		return -1;
	} else if (unlikely(res == TX_QUEUED)) {
		I802_DEBUG_INC(tx->local->tx_handlers_queued);
		return -1;
	}

	return 0;
}

static int invoke_tx_handlers(struct ieee80211_tx_data *tx)
{
	int r = invoke_tx_handlers_early(tx);

	if (r)
		return r;
	return invoke_tx_handlers_late(tx);
}

bool ieee80211_tx_prepare_skb(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct sk_buff *skb, int band, struct ieee80211_sta **sta)

{
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_data tx;
	struct sk_buff *skb2;

	if (ieee80211_tx_prepare(sdata, &tx, NULL, skb) == TX_DROP)
		return false;

	info->band = band;
	info->control.vif = vif;
	info->hw_queue = vif->hw_queue[skb_get_queue_mapping(skb)];

	if (invoke_tx_handlers(&tx))
		return false;

	if (sta) {
		if (tx.sta)
			*sta = &tx.sta->sta;
		else *sta = NULL;
	}

	
	skb2 = __skb_dequeue(&tx.skbs);
	if (WARN_ON(skb2 != skb || !skb_queue_empty(&tx.skbs))) {
		ieee80211_free_txskb(hw, skb2);
		ieee80211_purge_tx_queue(hw, &tx.skbs);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(ieee80211_tx_prepare_skb);


static bool ieee80211_tx(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct sk_buff *skb, bool txpending)

{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_tx_data tx;
	ieee80211_tx_result res_prepare;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	bool result = true;
	int led_len;

	if (unlikely(skb->len < 10)) {
		dev_kfree_skb(skb);
		return true;
	}

	
	led_len = skb->len;
	res_prepare = ieee80211_tx_prepare(sdata, &tx, sta, skb);

	if (unlikely(res_prepare == TX_DROP)) {
		ieee80211_free_txskb(&local->hw, skb);
		return true;
	} else if (unlikely(res_prepare == TX_QUEUED)) {
		return true;
	}

	
	if (!(info->flags & IEEE80211_TX_CTL_TX_OFFCHAN) || !ieee80211_hw_check(&local->hw, QUEUE_CONTROL))
		info->hw_queue = sdata->vif.hw_queue[skb_get_queue_mapping(skb)];

	if (invoke_tx_handlers_early(&tx))
		return true;

	if (ieee80211_queue_skb(local, sdata, tx.sta, tx.skb))
		return true;

	if (!invoke_tx_handlers_late(&tx))
		result = __ieee80211_tx(local, &tx.skbs, led_len, tx.sta, txpending);

	return result;
}



enum ieee80211_encrypt {
	ENCRYPT_NO, ENCRYPT_MGMT, ENCRYPT_DATA, };



static int ieee80211_skb_resize(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, int head_need, enum ieee80211_encrypt encrypt)


{
	struct ieee80211_local *local = sdata->local;
	bool enc_tailroom;
	int tail_need = 0;

	enc_tailroom = encrypt == ENCRYPT_MGMT || (encrypt == ENCRYPT_DATA && sdata->crypto_tx_tailroom_needed_cnt);


	if (enc_tailroom) {
		tail_need = IEEE80211_ENCRYPT_TAILROOM;
		tail_need -= skb_tailroom(skb);
		tail_need = max_t(int, tail_need, 0);
	}

	if (skb_cloned(skb) && (!ieee80211_hw_check(&local->hw, SUPPORTS_CLONED_SKBS) || !skb_clone_writable(skb, ETH_HLEN) || enc_tailroom))

		I802_DEBUG_INC(local->tx_expand_skb_head_cloned);
	else if (head_need || tail_need)
		I802_DEBUG_INC(local->tx_expand_skb_head);
	else return 0;

	if (pskb_expand_head(skb, head_need, tail_need, GFP_ATOMIC)) {
		wiphy_debug(local->hw.wiphy, "failed to reallocate TX buffer\n");
		return -ENOMEM;
	}

	return 0;
}

void ieee80211_xmit(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct sk_buff *skb)
{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	int headroom;
	enum ieee80211_encrypt encrypt;

	if (info->flags & IEEE80211_TX_INTFL_DONT_ENCRYPT)
		encrypt = ENCRYPT_NO;
	else if (ieee80211_is_mgmt(hdr->frame_control))
		encrypt = ENCRYPT_MGMT;
	else encrypt = ENCRYPT_DATA;

	headroom = local->tx_headroom;
	if (encrypt != ENCRYPT_NO)
		headroom += sdata->encrypt_headroom;
	headroom -= skb_headroom(skb);
	headroom = max_t(int, 0, headroom);

	if (ieee80211_skb_resize(sdata, skb, headroom, encrypt)) {
		ieee80211_free_txskb(&local->hw, skb);
		return;
	}

	
	hdr = (struct ieee80211_hdr *) skb->data;
	info->control.vif = &sdata->vif;

	if (ieee80211_vif_is_mesh(&sdata->vif)) {
		if (ieee80211_is_data(hdr->frame_control) && is_unicast_ether_addr(hdr->addr1)) {
			if (mesh_nexthop_resolve(sdata, skb))
				return; 
		} else {
			ieee80211_mps_set_frame_flags(sdata, NULL, hdr);
		}
	}

	ieee80211_set_qos_hdr(sdata, skb);
	ieee80211_tx(sdata, sta, skb, false);
}

bool ieee80211_parse_tx_radiotap(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_radiotap_iterator iterator;
	struct ieee80211_radiotap_header *rthdr = (struct ieee80211_radiotap_header *) skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_supported_band *sband = local->hw.wiphy->bands[info->band];
	int ret = ieee80211_radiotap_iterator_init(&iterator, rthdr, skb->len, NULL);
	u16 txflags;
	u16 rate = 0;
	bool rate_found = false;
	u8 rate_retries = 0;
	u16 rate_flags = 0;
	u8 mcs_known, mcs_flags, mcs_bw;
	u16 vht_known;
	u8 vht_mcs = 0, vht_nss = 0;
	int i;

	
	if (unlikely(skb->len < sizeof(struct ieee80211_radiotap_header)))
		return false; 

	
	if (unlikely(rthdr->it_version))
		return false; 

	
	if (unlikely(skb->len < ieee80211_get_radiotap_len(skb->data)))
		return false; 

	info->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT | IEEE80211_TX_CTL_DONTFRAG;

	

	while (!ret) {
		ret = ieee80211_radiotap_iterator_next(&iterator);

		if (ret)
			continue;

		
		switch (iterator.this_arg_index) {
		
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS) {
				
				if (skb->len < (iterator._max_length + FCS_LEN))
					return false;

				skb_trim(skb, skb->len - FCS_LEN);
			}
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_WEP)
				info->flags &= ~IEEE80211_TX_INTFL_DONT_ENCRYPT;
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FRAG)
				info->flags &= ~IEEE80211_TX_CTL_DONTFRAG;
			break;

		case IEEE80211_RADIOTAP_TX_FLAGS:
			txflags = get_unaligned_le16(iterator.this_arg);
			if (txflags & IEEE80211_RADIOTAP_F_TX_NOACK)
				info->flags |= IEEE80211_TX_CTL_NO_ACK;
			if (txflags & IEEE80211_RADIOTAP_F_TX_NOSEQNO)
				info->control.flags |= IEEE80211_TX_CTRL_NO_SEQNO;
			if (txflags & IEEE80211_RADIOTAP_F_TX_ORDER)
				info->control.flags |= IEEE80211_TX_CTRL_DONT_REORDER;
			break;

		case IEEE80211_RADIOTAP_RATE:
			rate = *iterator.this_arg;
			rate_flags = 0;
			rate_found = true;
			break;

		case IEEE80211_RADIOTAP_DATA_RETRIES:
			rate_retries = *iterator.this_arg;
			break;

		case IEEE80211_RADIOTAP_MCS:
			mcs_known = iterator.this_arg[0];
			mcs_flags = iterator.this_arg[1];
			if (!(mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS))
				break;

			rate_found = true;
			rate = iterator.this_arg[2];
			rate_flags = IEEE80211_TX_RC_MCS;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI && mcs_flags & IEEE80211_RADIOTAP_MCS_SGI)
				rate_flags |= IEEE80211_TX_RC_SHORT_GI;

			mcs_bw = mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW && mcs_bw == IEEE80211_RADIOTAP_MCS_BW_40)
				rate_flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC && mcs_flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC)
				info->flags |= IEEE80211_TX_CTL_LDPC;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				u8 stbc = u8_get_bits(mcs_flags, IEEE80211_RADIOTAP_MCS_STBC_MASK);

				info->flags |= u32_encode_bits(stbc, IEEE80211_TX_CTL_STBC);

			}
			break;

		case IEEE80211_RADIOTAP_VHT:
			vht_known = get_unaligned_le16(iterator.this_arg);
			rate_found = true;

			rate_flags = IEEE80211_TX_RC_VHT_MCS;
			if ((vht_known & IEEE80211_RADIOTAP_VHT_KNOWN_GI) && (iterator.this_arg[2] & IEEE80211_RADIOTAP_VHT_FLAG_SGI))

				rate_flags |= IEEE80211_TX_RC_SHORT_GI;
			if (vht_known & IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH) {
				if (iterator.this_arg[3] == 1)
					rate_flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;
				else if (iterator.this_arg[3] == 4)
					rate_flags |= IEEE80211_TX_RC_80_MHZ_WIDTH;
				else if (iterator.this_arg[3] == 11)
					rate_flags |= IEEE80211_TX_RC_160_MHZ_WIDTH;
			}

			vht_mcs = iterator.this_arg[4] >> 4;
			vht_nss = iterator.this_arg[4] & 0xF;
			break;

		

		default:
			break;
		}
	}

	if (ret != -ENOENT) 
		return false;

	if (rate_found) {
		info->control.flags |= IEEE80211_TX_CTRL_RATE_INJECT;

		for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
			info->control.rates[i].idx = -1;
			info->control.rates[i].flags = 0;
			info->control.rates[i].count = 0;
		}

		if (rate_flags & IEEE80211_TX_RC_MCS) {
			info->control.rates[0].idx = rate;
		} else if (rate_flags & IEEE80211_TX_RC_VHT_MCS) {
			ieee80211_rate_set_vht(info->control.rates, vht_mcs, vht_nss);
		} else {
			for (i = 0; i < sband->n_bitrates; i++) {
				if (rate * 5 != sband->bitrates[i].bitrate)
					continue;

				info->control.rates[0].idx = i;
				break;
			}
		}

		if (info->control.rates[0].idx < 0)
			info->control.flags &= ~IEEE80211_TX_CTRL_RATE_INJECT;

		info->control.rates[0].flags = rate_flags;
		info->control.rates[0].count = min_t(u8, rate_retries + 1, local->hw.max_rate_tries);
	}

	return true;
}

netdev_tx_t ieee80211_monitor_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_chanctx_conf *chanctx_conf;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr;
	struct ieee80211_sub_if_data *tmp_sdata, *sdata;
	struct cfg80211_chan_def *chandef;
	u16 len_rthdr;
	int hdrlen;

	memset(info, 0, sizeof(*info));
	info->flags = IEEE80211_TX_CTL_REQ_TX_STATUS | IEEE80211_TX_CTL_INJECTED;

	
	if (!ieee80211_parse_tx_radiotap(skb, dev))
		goto fail;

	
	len_rthdr = ieee80211_get_radiotap_len(skb->data);

	
	skb_set_mac_header(skb, len_rthdr);
	
	skb_set_network_header(skb, len_rthdr);
	skb_set_transport_header(skb, len_rthdr);

	if (skb->len < len_rthdr + 2)
		goto fail;

	hdr = (struct ieee80211_hdr *)(skb->data + len_rthdr);
	hdrlen = ieee80211_hdrlen(hdr->frame_control);

	if (skb->len < len_rthdr + hdrlen)
		goto fail;

	
	if (ieee80211_is_data(hdr->frame_control) && skb->len >= len_rthdr + hdrlen + sizeof(rfc1042_header) + 2) {
		u8 *payload = (u8 *)hdr + hdrlen;

		if (ether_addr_equal(payload, rfc1042_header))
			skb->protocol = cpu_to_be16((payload[6] << 8) | payload[7]);
	}

	rcu_read_lock();

	
	sdata = IEEE80211_DEV_TO_SUB_IF(dev);

	list_for_each_entry_rcu(tmp_sdata, &local->interfaces, list) {
		if (!ieee80211_sdata_running(tmp_sdata))
			continue;
		if (tmp_sdata->vif.type == NL80211_IFTYPE_MONITOR || tmp_sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
			continue;
		if (ether_addr_equal(tmp_sdata->vif.addr, hdr->addr2)) {
			sdata = tmp_sdata;
			break;
		}
	}

	chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
	if (!chanctx_conf) {
		tmp_sdata = rcu_dereference(local->monitor_sdata);
		if (tmp_sdata)
			chanctx_conf = rcu_dereference(tmp_sdata->vif.chanctx_conf);
	}

	if (chanctx_conf)
		chandef = &chanctx_conf->def;
	else if (!local->use_chanctx)
		chandef = &local->_oper_chandef;
	else goto fail_rcu;

	
	if (!cfg80211_reg_can_beacon(local->hw.wiphy, chandef, sdata->vif.type))
		goto fail_rcu;

	info->band = chandef->chan->band;

	
	ieee80211_select_queue_80211(sdata, skb, hdr);
	skb_set_queue_mapping(skb, ieee80211_ac_from_tid(skb->priority));

	
	skb_pull(skb, len_rthdr);

	ieee80211_xmit(sdata, NULL, skb);
	rcu_read_unlock();

	return NETDEV_TX_OK;

fail_rcu:
	rcu_read_unlock();
fail:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK; 
}

static inline bool ieee80211_is_tdls_setup(struct sk_buff *skb)
{
	u16 ethertype = (skb->data[12] << 8) | skb->data[13];

	return ethertype == ETH_P_TDLS && skb->len > 14 && skb->data[14] == WLAN_TDLS_SNAP_RFTYPE;

}

int ieee80211_lookup_ra_sta(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, struct sta_info **sta_out)

{
	struct sta_info *sta;

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_AP_VLAN:
		sta = rcu_dereference(sdata->u.vlan.sta);
		if (sta) {
			*sta_out = sta;
			return 0;
		} else if (sdata->wdev.use_4addr) {
			return -ENOLINK;
		}
		fallthrough;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_OCB:
	case NL80211_IFTYPE_ADHOC:
		if (is_multicast_ether_addr(skb->data)) {
			*sta_out = ERR_PTR(-ENOENT);
			return 0;
		}
		sta = sta_info_get_bss(sdata, skb->data);
		break;

	case NL80211_IFTYPE_MESH_POINT:
		
		*sta_out = NULL;
		return 0;

	case NL80211_IFTYPE_STATION:
		if (sdata->wdev.wiphy->flags & WIPHY_FLAG_SUPPORTS_TDLS) {
			sta = sta_info_get(sdata, skb->data);
			if (sta && test_sta_flag(sta, WLAN_STA_TDLS_PEER)) {
				if (test_sta_flag(sta, WLAN_STA_TDLS_PEER_AUTH)) {
					*sta_out = sta;
					return 0;
				}

				
				if (!ieee80211_is_tdls_setup(skb))
					return -EINVAL;
			}

		}

		sta = sta_info_get(sdata, sdata->u.mgd.bssid);
		if (!sta)
			return -ENOLINK;
		break;
	default:
		return -EINVAL;
	}

	*sta_out = sta ?: ERR_PTR(-ENOENT);
	return 0;
}

static u16 ieee80211_store_ack_skb(struct ieee80211_local *local, struct sk_buff *skb, u32 *info_flags, u64 *cookie)


{
	struct sk_buff *ack_skb;
	u16 info_id = 0;

	if (skb->sk)
		ack_skb = skb_clone_sk(skb);
	else ack_skb = skb_clone(skb, GFP_ATOMIC);

	if (ack_skb) {
		unsigned long flags;
		int id;

		spin_lock_irqsave(&local->ack_status_lock, flags);
		id = idr_alloc(&local->ack_status_frames, ack_skb, 1, 0x2000, GFP_ATOMIC);
		spin_unlock_irqrestore(&local->ack_status_lock, flags);

		if (id >= 0) {
			info_id = id;
			*info_flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;
			if (cookie) {
				*cookie = ieee80211_mgmt_tx_cookie(local);
				IEEE80211_SKB_CB(ack_skb)->ack.cookie = *cookie;
			}
		} else {
			kfree_skb(ack_skb);
		}
	}

	return info_id;
}


static struct sk_buff *ieee80211_build_hdr(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, u32 info_flags, struct sta_info *sta, u32 ctrl_flags, u64 *cookie)


{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_tx_info *info;
	int head_need;
	u16 ethertype, hdrlen,  meshhdrlen = 0;
	__le16 fc;
	struct ieee80211_hdr hdr;
	struct ieee80211s_hdr mesh_hdr __maybe_unused;
	struct mesh_path __maybe_unused *mppath = NULL, *mpath = NULL;
	const u8 *encaps_data;
	int encaps_len, skip_header_bytes;
	bool wme_sta = false, authorized = false;
	bool tdls_peer;
	bool multicast;
	u16 info_id = 0;
	struct ieee80211_chanctx_conf *chanctx_conf;
	struct ieee80211_sub_if_data *ap_sdata;
	enum nl80211_band band;
	int ret;

	if (IS_ERR(sta))
		sta = NULL;


	if (local->force_tx_status)
		info_flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;


	
	ethertype = (skb->data[12] << 8) | skb->data[13];
	fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_AP_VLAN:
		if (sdata->wdev.use_4addr) {
			fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);
			
			memcpy(hdr.addr1, sta->sta.addr, ETH_ALEN);
			memcpy(hdr.addr2, sdata->vif.addr, ETH_ALEN);
			memcpy(hdr.addr3, skb->data, ETH_ALEN);
			memcpy(hdr.addr4, skb->data + ETH_ALEN, ETH_ALEN);
			hdrlen = 30;
			authorized = test_sta_flag(sta, WLAN_STA_AUTHORIZED);
			wme_sta = sta->sta.wme;
		}
		ap_sdata = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);
		chanctx_conf = rcu_dereference(ap_sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		band = chanctx_conf->def.chan->band;
		if (sdata->wdev.use_4addr)
			break;
		fallthrough;
	case NL80211_IFTYPE_AP:
		if (sdata->vif.type == NL80211_IFTYPE_AP)
			chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS);
		
		memcpy(hdr.addr1, skb->data, ETH_ALEN);
		memcpy(hdr.addr2, sdata->vif.addr, ETH_ALEN);
		memcpy(hdr.addr3, skb->data + ETH_ALEN, ETH_ALEN);
		hdrlen = 24;
		band = chanctx_conf->def.chan->band;
		break;

	case NL80211_IFTYPE_MESH_POINT:
		if (!is_multicast_ether_addr(skb->data)) {
			struct sta_info *next_hop;
			bool mpp_lookup = true;

			mpath = mesh_path_lookup(sdata, skb->data);
			if (mpath) {
				mpp_lookup = false;
				next_hop = rcu_dereference(mpath->next_hop);
				if (!next_hop || !(mpath->flags & (MESH_PATH_ACTIVE | MESH_PATH_RESOLVING)))

					mpp_lookup = true;
			}

			if (mpp_lookup) {
				mppath = mpp_path_lookup(sdata, skb->data);
				if (mppath)
					mppath->exp_time = jiffies;
			}

			if (mppath && mpath)
				mesh_path_del(sdata, mpath->dst);
		}

		
		if (ether_addr_equal(sdata->vif.addr, skb->data + ETH_ALEN) && !(mppath && !ether_addr_equal(mppath->mpp, skb->data))) {
			hdrlen = ieee80211_fill_mesh_addresses(&hdr, &fc, skb->data, skb->data + ETH_ALEN);
			meshhdrlen = ieee80211_new_mesh_header(sdata, &mesh_hdr, NULL, NULL);
		} else {
			
			const u8 *mesh_da = skb->data;

			if (mppath)
				mesh_da = mppath->mpp;
			else if (mpath)
				mesh_da = mpath->dst;

			hdrlen = ieee80211_fill_mesh_addresses(&hdr, &fc, mesh_da, sdata->vif.addr);
			if (is_multicast_ether_addr(mesh_da))
				
				meshhdrlen = ieee80211_new_mesh_header( sdata, &mesh_hdr, skb->data + ETH_ALEN, NULL);

			else  meshhdrlen = ieee80211_new_mesh_header( sdata, &mesh_hdr, skb->data, skb->data + ETH_ALEN);




		}
		chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		band = chanctx_conf->def.chan->band;

		
		if ((ctrl_flags & IEEE80211_TX_CTRL_SKIP_MPATH_LOOKUP) && is_zero_ether_addr(hdr.addr1))
			memcpy(hdr.addr1, skb->data, ETH_ALEN);
		break;

	case NL80211_IFTYPE_STATION:
		
		tdls_peer = test_sta_flag(sta, WLAN_STA_TDLS_PEER);

		if (tdls_peer) {
			
			memcpy(hdr.addr1, skb->data, ETH_ALEN);
			memcpy(hdr.addr2, skb->data + ETH_ALEN, ETH_ALEN);
			memcpy(hdr.addr3, sdata->u.mgd.bssid, ETH_ALEN);
			hdrlen = 24;
		}  else if (sdata->u.mgd.use_4addr && cpu_to_be16(ethertype) != sdata->control_port_protocol) {
			fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);
			
			memcpy(hdr.addr1, sdata->u.mgd.bssid, ETH_ALEN);
			memcpy(hdr.addr2, sdata->vif.addr, ETH_ALEN);
			memcpy(hdr.addr3, skb->data, ETH_ALEN);
			memcpy(hdr.addr4, skb->data + ETH_ALEN, ETH_ALEN);
			hdrlen = 30;
		} else {
			fc |= cpu_to_le16(IEEE80211_FCTL_TODS);
			
			memcpy(hdr.addr1, sdata->u.mgd.bssid, ETH_ALEN);
			memcpy(hdr.addr2, skb->data + ETH_ALEN, ETH_ALEN);
			memcpy(hdr.addr3, skb->data, ETH_ALEN);
			hdrlen = 24;
		}
		chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		band = chanctx_conf->def.chan->band;
		break;
	case NL80211_IFTYPE_OCB:
		
		memcpy(hdr.addr1, skb->data, ETH_ALEN);
		memcpy(hdr.addr2, skb->data + ETH_ALEN, ETH_ALEN);
		eth_broadcast_addr(hdr.addr3);
		hdrlen = 24;
		chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		band = chanctx_conf->def.chan->band;
		break;
	case NL80211_IFTYPE_ADHOC:
		
		memcpy(hdr.addr1, skb->data, ETH_ALEN);
		memcpy(hdr.addr2, skb->data + ETH_ALEN, ETH_ALEN);
		memcpy(hdr.addr3, sdata->u.ibss.bssid, ETH_ALEN);
		hdrlen = 24;
		chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (!chanctx_conf) {
			ret = -ENOTCONN;
			goto free;
		}
		band = chanctx_conf->def.chan->band;
		break;
	default:
		ret = -EINVAL;
		goto free;
	}

	multicast = is_multicast_ether_addr(hdr.addr1);

	
	if (sta) {
		authorized = test_sta_flag(sta, WLAN_STA_AUTHORIZED);
		wme_sta = sta->sta.wme;
	} else if (ieee80211_vif_is_mesh(&sdata->vif)) {
		
		wme_sta = true;
	}

	
	if (wme_sta) {
		fc |= cpu_to_le16(IEEE80211_STYPE_QOS_DATA);
		hdrlen += 2;
	}

	
	if (unlikely(!ieee80211_vif_is_mesh(&sdata->vif) && (sdata->vif.type != NL80211_IFTYPE_OCB) && !multicast && !authorized && (cpu_to_be16(ethertype) != sdata->control_port_protocol || !ether_addr_equal(sdata->vif.addr, skb->data + ETH_ALEN)))) {




		net_info_ratelimited("%s: dropped frame to %pM (unauthorized port)\n", sdata->name, hdr.addr1);


		I802_DEBUG_INC(local->tx_handlers_drop_unauth_port);

		ret = -EPERM;
		goto free;
	}

	if (unlikely(!multicast && ((skb->sk && skb_shinfo(skb)->tx_flags & SKBTX_WIFI_STATUS) || ctrl_flags & IEEE80211_TX_CTL_REQ_TX_STATUS)))

		info_id = ieee80211_store_ack_skb(local, skb, &info_flags, cookie);

	
	if (skb_shared(skb)) {
		struct sk_buff *tmp_skb = skb;

		
		WARN_ON(info_id);

		skb = skb_clone(skb, GFP_ATOMIC);
		kfree_skb(tmp_skb);

		if (!skb) {
			ret = -ENOMEM;
			goto free;
		}
	}

	hdr.frame_control = fc;
	hdr.duration_id = 0;
	hdr.seq_ctrl = 0;

	skip_header_bytes = ETH_HLEN;
	if (ethertype == ETH_P_AARP || ethertype == ETH_P_IPX) {
		encaps_data = bridge_tunnel_header;
		encaps_len = sizeof(bridge_tunnel_header);
		skip_header_bytes -= 2;
	} else if (ethertype >= ETH_P_802_3_MIN) {
		encaps_data = rfc1042_header;
		encaps_len = sizeof(rfc1042_header);
		skip_header_bytes -= 2;
	} else {
		encaps_data = NULL;
		encaps_len = 0;
	}

	skb_pull(skb, skip_header_bytes);
	head_need = hdrlen + encaps_len + meshhdrlen - skb_headroom(skb);

	

	if (head_need > 0 || skb_cloned(skb)) {
		head_need += sdata->encrypt_headroom;
		head_need += local->tx_headroom;
		head_need = max_t(int, 0, head_need);
		if (ieee80211_skb_resize(sdata, skb, head_need, ENCRYPT_DATA)) {
			ieee80211_free_txskb(&local->hw, skb);
			skb = NULL;
			return ERR_PTR(-ENOMEM);
		}
	}

	if (encaps_data)
		memcpy(skb_push(skb, encaps_len), encaps_data, encaps_len);


	if (meshhdrlen > 0)
		memcpy(skb_push(skb, meshhdrlen), &mesh_hdr, meshhdrlen);


	if (ieee80211_is_data_qos(fc)) {
		__le16 *qos_control;

		qos_control = skb_push(skb, 2);
		memcpy(skb_push(skb, hdrlen - 2), &hdr, hdrlen - 2);
		
		*qos_control = 0;
	} else memcpy(skb_push(skb, hdrlen), &hdr, hdrlen);

	skb_reset_mac_header(skb);

	info = IEEE80211_SKB_CB(skb);
	memset(info, 0, sizeof(*info));

	info->flags = info_flags;
	info->ack_frame_id = info_id;
	info->band = band;
	info->control.flags = ctrl_flags;

	return skb;
 free:
	kfree_skb(skb);
	return ERR_PTR(ret);
}



void ieee80211_check_fast_xmit(struct sta_info *sta)
{
	struct ieee80211_fast_tx build = {}, *fast_tx = NULL, *old;
	struct ieee80211_local *local = sta->local;
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_hdr *hdr = (void *)build.hdr;
	struct ieee80211_chanctx_conf *chanctx_conf;
	__le16 fc;

	if (!ieee80211_hw_check(&local->hw, SUPPORT_FAST_XMIT))
		return;

	
	spin_lock_bh(&sta->lock);
	if (ieee80211_hw_check(&local->hw, SUPPORTS_PS) && !ieee80211_hw_check(&local->hw, SUPPORTS_DYNAMIC_PS) && sdata->vif.type == NL80211_IFTYPE_STATION)

		goto out;

	if (!test_sta_flag(sta, WLAN_STA_AUTHORIZED))
		goto out;

	if (test_sta_flag(sta, WLAN_STA_PS_STA) || test_sta_flag(sta, WLAN_STA_PS_DRIVER) || test_sta_flag(sta, WLAN_STA_PS_DELIVER) || test_sta_flag(sta, WLAN_STA_CLEAR_PS_FILT))


		goto out;

	if (sdata->noack_map)
		goto out;

	
	if (local->hw.wiphy->frag_threshold != (u32)-1 && !ieee80211_hw_check(&local->hw, SUPPORTS_TX_FRAG))
		goto out;

	rcu_read_lock();
	chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
	if (!chanctx_conf) {
		rcu_read_unlock();
		goto out;
	}
	build.band = chanctx_conf->def.chan->band;
	rcu_read_unlock();

	fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_ADHOC:
		
		build.da_offs = offsetof(struct ieee80211_hdr, addr1);
		build.sa_offs = offsetof(struct ieee80211_hdr, addr2);
		memcpy(hdr->addr3, sdata->u.ibss.bssid, ETH_ALEN);
		build.hdr_len = 24;
		break;
	case NL80211_IFTYPE_STATION:
		if (test_sta_flag(sta, WLAN_STA_TDLS_PEER)) {
			
			build.da_offs = offsetof(struct ieee80211_hdr, addr1);
			build.sa_offs = offsetof(struct ieee80211_hdr, addr2);
			memcpy(hdr->addr3, sdata->u.mgd.bssid, ETH_ALEN);
			build.hdr_len = 24;
			break;
		}

		if (sdata->u.mgd.use_4addr) {
			
			fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);
			
			memcpy(hdr->addr1, sdata->u.mgd.bssid, ETH_ALEN);
			memcpy(hdr->addr2, sdata->vif.addr, ETH_ALEN);
			build.da_offs = offsetof(struct ieee80211_hdr, addr3);
			build.sa_offs = offsetof(struct ieee80211_hdr, addr4);
			build.hdr_len = 30;
			break;
		}
		fc |= cpu_to_le16(IEEE80211_FCTL_TODS);
		
		memcpy(hdr->addr1, sdata->u.mgd.bssid, ETH_ALEN);
		build.da_offs = offsetof(struct ieee80211_hdr, addr3);
		build.sa_offs = offsetof(struct ieee80211_hdr, addr2);
		build.hdr_len = 24;
		break;
	case NL80211_IFTYPE_AP_VLAN:
		if (sdata->wdev.use_4addr) {
			fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS);
			
			memcpy(hdr->addr1, sta->sta.addr, ETH_ALEN);
			memcpy(hdr->addr2, sdata->vif.addr, ETH_ALEN);
			build.da_offs = offsetof(struct ieee80211_hdr, addr3);
			build.sa_offs = offsetof(struct ieee80211_hdr, addr4);
			build.hdr_len = 30;
			break;
		}
		fallthrough;
	case NL80211_IFTYPE_AP:
		fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS);
		
		build.da_offs = offsetof(struct ieee80211_hdr, addr1);
		memcpy(hdr->addr2, sdata->vif.addr, ETH_ALEN);
		build.sa_offs = offsetof(struct ieee80211_hdr, addr3);
		build.hdr_len = 24;
		break;
	default:
		
		goto out;
	}

	if (sta->sta.wme) {
		build.hdr_len += 2;
		fc |= cpu_to_le16(IEEE80211_STYPE_QOS_DATA);
	}

	
	build.key = rcu_access_pointer(sta->ptk[sta->ptk_idx]);
	if (!build.key)
		build.key = rcu_access_pointer(sdata->default_unicast_key);
	if (build.key) {
		bool gen_iv, iv_spc, mmic;

		gen_iv = build.key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_IV;
		iv_spc = build.key->conf.flags & IEEE80211_KEY_FLAG_PUT_IV_SPACE;
		mmic = build.key->conf.flags & (IEEE80211_KEY_FLAG_GENERATE_MMIC | IEEE80211_KEY_FLAG_PUT_MIC_SPACE);


		
		if (!(build.key->flags & KEY_FLAG_UPLOADED_TO_HARDWARE))
			goto out;

		
		if (build.key->flags & KEY_FLAG_TAINTED)
			goto out;

		switch (build.key->conf.cipher) {
		case WLAN_CIPHER_SUITE_CCMP:
		case WLAN_CIPHER_SUITE_CCMP_256:
			if (gen_iv)
				build.pn_offs = build.hdr_len;
			if (gen_iv || iv_spc)
				build.hdr_len += IEEE80211_CCMP_HDR_LEN;
			break;
		case WLAN_CIPHER_SUITE_GCMP:
		case WLAN_CIPHER_SUITE_GCMP_256:
			if (gen_iv)
				build.pn_offs = build.hdr_len;
			if (gen_iv || iv_spc)
				build.hdr_len += IEEE80211_GCMP_HDR_LEN;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			
			if (mmic || gen_iv)
				goto out;
			if (iv_spc)
				build.hdr_len += IEEE80211_TKIP_IV_LEN;
			break;
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			
			if (gen_iv)
				goto out;
			if (iv_spc)
				build.hdr_len += IEEE80211_WEP_IV_LEN;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
		case WLAN_CIPHER_SUITE_BIP_CMAC_256:
		case WLAN_CIPHER_SUITE_BIP_GMAC_128:
		case WLAN_CIPHER_SUITE_BIP_GMAC_256:
			WARN(1, "management cipher suite 0x%x enabled for data\n", build.key->conf.cipher);

			goto out;
		default:
			
			if (WARN_ON(gen_iv))
				goto out;
			
			if (!(build.key->flags & KEY_FLAG_CIPHER_SCHEME))
				break;
			
			if (iv_spc && build.key->conf.iv_len > IEEE80211_FAST_XMIT_MAX_IV)
				goto out;
			if (iv_spc)
				build.hdr_len += build.key->conf.iv_len;
		}

		fc |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);
	}

	hdr->frame_control = fc;

	memcpy(build.hdr + build.hdr_len, rfc1042_header,  sizeof(rfc1042_header));
	build.hdr_len += sizeof(rfc1042_header);

	fast_tx = kmemdup(&build, sizeof(build), GFP_ATOMIC);
	
	if (!fast_tx)
		goto out;

 out:
	
	old = rcu_dereference_protected(sta->fast_tx, lockdep_is_held(&sta->lock));
	rcu_assign_pointer(sta->fast_tx, fast_tx);
	if (old)
		kfree_rcu(old, rcu_head);
	spin_unlock_bh(&sta->lock);
}

void ieee80211_check_fast_xmit_all(struct ieee80211_local *local)
{
	struct sta_info *sta;

	rcu_read_lock();
	list_for_each_entry_rcu(sta, &local->sta_list, list)
		ieee80211_check_fast_xmit(sta);
	rcu_read_unlock();
}

void ieee80211_check_fast_xmit_iface(struct ieee80211_sub_if_data *sdata)
{
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;

	rcu_read_lock();

	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		if (sdata != sta->sdata && (!sta->sdata->bss || sta->sdata->bss != sdata->bss))
			continue;
		ieee80211_check_fast_xmit(sta);
	}

	rcu_read_unlock();
}

void ieee80211_clear_fast_xmit(struct sta_info *sta)
{
	struct ieee80211_fast_tx *fast_tx;

	spin_lock_bh(&sta->lock);
	fast_tx = rcu_dereference_protected(sta->fast_tx, lockdep_is_held(&sta->lock));
	RCU_INIT_POINTER(sta->fast_tx, NULL);
	spin_unlock_bh(&sta->lock);

	if (fast_tx)
		kfree_rcu(fast_tx, rcu_head);
}

static bool ieee80211_amsdu_realloc_pad(struct ieee80211_local *local, struct sk_buff *skb, int headroom)
{
	if (skb_headroom(skb) < headroom) {
		I802_DEBUG_INC(local->tx_expand_skb_head);

		if (pskb_expand_head(skb, headroom, 0, GFP_ATOMIC)) {
			wiphy_debug(local->hw.wiphy, "failed to reallocate TX buffer\n");
			return false;
		}
	}

	return true;
}

static bool ieee80211_amsdu_prepare_head(struct ieee80211_sub_if_data *sdata, struct ieee80211_fast_tx *fast_tx, struct sk_buff *skb)

{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr;
	struct ethhdr *amsdu_hdr;
	int hdr_len = fast_tx->hdr_len - sizeof(rfc1042_header);
	int subframe_len = skb->len - hdr_len;
	void *data;
	u8 *qc, *h_80211_src, *h_80211_dst;
	const u8 *bssid;

	if (info->flags & IEEE80211_TX_CTL_RATE_CTRL_PROBE)
		return false;

	if (info->control.flags & IEEE80211_TX_CTRL_AMSDU)
		return true;

	if (!ieee80211_amsdu_realloc_pad(local, skb, sizeof(*amsdu_hdr)))
		return false;

	data = skb_push(skb, sizeof(*amsdu_hdr));
	memmove(data, data + sizeof(*amsdu_hdr), hdr_len);
	hdr = data;
	amsdu_hdr = data + hdr_len;
	
	h_80211_src = data + fast_tx->sa_offs;
	h_80211_dst = data + fast_tx->da_offs;

	amsdu_hdr->h_proto = cpu_to_be16(subframe_len);
	ether_addr_copy(amsdu_hdr->h_source, h_80211_src);
	ether_addr_copy(amsdu_hdr->h_dest, h_80211_dst);

	
	switch (sdata->vif.type) {
	case NL80211_IFTYPE_STATION:
		bssid = sdata->u.mgd.bssid;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
		bssid = sdata->vif.addr;
		break;
	default:
		bssid = NULL;
	}

	if (bssid && ieee80211_has_fromds(hdr->frame_control))
		ether_addr_copy(h_80211_src, bssid);

	if (bssid && ieee80211_has_tods(hdr->frame_control))
		ether_addr_copy(h_80211_dst, bssid);

	qc = ieee80211_get_qos_ctl(hdr);
	*qc |= IEEE80211_QOS_CTL_A_MSDU_PRESENT;

	info->control.flags |= IEEE80211_TX_CTRL_AMSDU;

	return true;
}

static bool ieee80211_amsdu_aggregate(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct ieee80211_fast_tx *fast_tx, struct sk_buff *skb)


{
	struct ieee80211_local *local = sdata->local;
	struct fq *fq = &local->fq;
	struct fq_tin *tin;
	struct fq_flow *flow;
	u8 tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
	struct ieee80211_txq *txq = sta->sta.txq[tid];
	struct txq_info *txqi;
	struct sk_buff **frag_tail, *head;
	int subframe_len = skb->len - ETH_ALEN;
	u8 max_subframes = sta->sta.max_amsdu_subframes;
	int max_frags = local->hw.max_tx_fragments;
	int max_amsdu_len = sta->sta.max_amsdu_len;
	int orig_truesize;
	u32 flow_idx;
	__be16 len;
	void *data;
	bool ret = false;
	unsigned int orig_len;
	int n = 2, nfrags, pad = 0;
	u16 hdrlen;

	if (!ieee80211_hw_check(&local->hw, TX_AMSDU))
		return false;

	if (skb_is_gso(skb))
		return false;

	if (!txq)
		return false;

	txqi = to_txq_info(txq);
	if (test_bit(IEEE80211_TXQ_NO_AMSDU, &txqi->flags))
		return false;

	if (sta->sta.max_rc_amsdu_len)
		max_amsdu_len = min_t(int, max_amsdu_len, sta->sta.max_rc_amsdu_len);

	if (sta->sta.max_tid_amsdu_len[tid])
		max_amsdu_len = min_t(int, max_amsdu_len, sta->sta.max_tid_amsdu_len[tid]);

	flow_idx = fq_flow_idx(fq, skb);

	spin_lock_bh(&fq->lock);

	

	tin = &txqi->tin;
	flow = fq_flow_classify(fq, tin, flow_idx, skb);
	head = skb_peek_tail(&flow->queue);
	if (!head || skb_is_gso(head))
		goto out;

	orig_truesize = head->truesize;
	orig_len = head->len;

	if (skb->len + head->len > max_amsdu_len)
		goto out;

	nfrags = 1 + skb_shinfo(skb)->nr_frags;
	nfrags += 1 + skb_shinfo(head)->nr_frags;
	frag_tail = &skb_shinfo(head)->frag_list;
	while (*frag_tail) {
		nfrags += 1 + skb_shinfo(*frag_tail)->nr_frags;
		frag_tail = &(*frag_tail)->next;
		n++;
	}

	if (max_subframes && n > max_subframes)
		goto out;

	if (max_frags && nfrags > max_frags)
		goto out;

	if (!drv_can_aggregate_in_amsdu(local, head, skb))
		goto out;

	if (!ieee80211_amsdu_prepare_head(sdata, fast_tx, head))
		goto out;

	
	hdrlen = fast_tx->hdr_len - sizeof(rfc1042_header);
	if ((head->len - hdrlen) & 3)
		pad = 4 - ((head->len - hdrlen) & 3);

	if (!ieee80211_amsdu_realloc_pad(local, skb, sizeof(rfc1042_header) + 2 + pad))
		goto out_recalc;

	ret = true;
	data = skb_push(skb, ETH_ALEN + 2);
	memmove(data, data + ETH_ALEN + 2, 2 * ETH_ALEN);

	data += 2 * ETH_ALEN;
	len = cpu_to_be16(subframe_len);
	memcpy(data, &len, 2);
	memcpy(data + 2, rfc1042_header, sizeof(rfc1042_header));

	memset(skb_push(skb, pad), 0, pad);

	head->len += skb->len;
	head->data_len += skb->len;
	*frag_tail = skb;

out_recalc:
	fq->memory_usage += head->truesize - orig_truesize;
	if (head->len != orig_len) {
		flow->backlog += head->len - orig_len;
		tin->backlog_bytes += head->len - orig_len;
	}
out:
	spin_unlock_bh(&fq->lock);

	return ret;
}


static void ieee80211_xmit_fast_finish(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, u8 pn_offs, struct ieee80211_key *key, struct sk_buff *skb)


{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (void *)skb->data;
	u8 tid = IEEE80211_NUM_TIDS;

	if (key)
		info->control.hw_key = &key->conf;

	dev_sw_netstats_tx_add(skb->dev, 1, skb->len);

	if (hdr->frame_control & cpu_to_le16(IEEE80211_STYPE_QOS_DATA)) {
		tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
		hdr->seq_ctrl = ieee80211_tx_next_seq(sta, tid);
	} else {
		info->flags |= IEEE80211_TX_CTL_ASSIGN_SEQ;
		hdr->seq_ctrl = cpu_to_le16(sdata->sequence_number);
		sdata->sequence_number += 0x10;
	}

	if (skb_shinfo(skb)->gso_size)
		sta->tx_stats.msdu[tid] += DIV_ROUND_UP(skb->len, skb_shinfo(skb)->gso_size);
	else sta->tx_stats.msdu[tid]++;

	info->hw_queue = sdata->vif.hw_queue[skb_get_queue_mapping(skb)];

	
	sta->tx_stats.bytes[skb_get_queue_mapping(skb)] += skb->len;
	sta->tx_stats.packets[skb_get_queue_mapping(skb)]++;

	if (pn_offs) {
		u64 pn;
		u8 *crypto_hdr = skb->data + pn_offs;

		switch (key->conf.cipher) {
		case WLAN_CIPHER_SUITE_CCMP:
		case WLAN_CIPHER_SUITE_CCMP_256:
		case WLAN_CIPHER_SUITE_GCMP:
		case WLAN_CIPHER_SUITE_GCMP_256:
			pn = atomic64_inc_return(&key->conf.tx_pn);
			crypto_hdr[0] = pn;
			crypto_hdr[1] = pn >> 8;
			crypto_hdr[3] = 0x20 | (key->conf.keyidx << 6);
			crypto_hdr[4] = pn >> 16;
			crypto_hdr[5] = pn >> 24;
			crypto_hdr[6] = pn >> 32;
			crypto_hdr[7] = pn >> 40;
			break;
		}
	}
}

static bool ieee80211_xmit_fast(struct ieee80211_sub_if_data *sdata, struct sta_info *sta, struct ieee80211_fast_tx *fast_tx, struct sk_buff *skb)


{
	struct ieee80211_local *local = sdata->local;
	u16 ethertype = (skb->data[12] << 8) | skb->data[13];
	int extra_head = fast_tx->hdr_len - (ETH_HLEN - 2);
	int hw_headroom = sdata->local->hw.extra_tx_headroom;
	struct ethhdr eth;
	struct ieee80211_tx_info *info;
	struct ieee80211_hdr *hdr = (void *)fast_tx->hdr;
	struct ieee80211_tx_data tx;
	ieee80211_tx_result r;
	struct tid_ampdu_tx *tid_tx = NULL;
	u8 tid = IEEE80211_NUM_TIDS;

	
	if (cpu_to_be16(ethertype) == sdata->control_port_protocol)
		return false;

	
	if (ethertype < ETH_P_802_3_MIN)
		return false;

	
	if (skb->sk && skb_shinfo(skb)->tx_flags & SKBTX_WIFI_STATUS)
		return false;

	if (hdr->frame_control & cpu_to_le16(IEEE80211_STYPE_QOS_DATA)) {
		tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
		tid_tx = rcu_dereference(sta->ampdu_mlme.tid_tx[tid]);
		if (tid_tx) {
			if (!test_bit(HT_AGG_STATE_OPERATIONAL, &tid_tx->state))
				return false;
			if (tid_tx->timeout)
				tid_tx->last_tx = jiffies;
		}
	}

	

	if (skb_shared(skb)) {
		struct sk_buff *tmp_skb = skb;

		skb = skb_clone(skb, GFP_ATOMIC);
		kfree_skb(tmp_skb);

		if (!skb)
			return true;
	}

	if ((hdr->frame_control & cpu_to_le16(IEEE80211_STYPE_QOS_DATA)) && ieee80211_amsdu_aggregate(sdata, sta, fast_tx, skb))
		return true;

	
	if (unlikely(ieee80211_skb_resize(sdata, skb, max_t(int, extra_head + hw_headroom - skb_headroom(skb), 0), ENCRYPT_NO))) {


		kfree_skb(skb);
		return true;
	}

	memcpy(&eth, skb->data, ETH_HLEN - 2);
	hdr = skb_push(skb, extra_head);
	memcpy(skb->data, fast_tx->hdr, fast_tx->hdr_len);
	memcpy(skb->data + fast_tx->da_offs, eth.h_dest, ETH_ALEN);
	memcpy(skb->data + fast_tx->sa_offs, eth.h_source, ETH_ALEN);

	info = IEEE80211_SKB_CB(skb);
	memset(info, 0, sizeof(*info));
	info->band = fast_tx->band;
	info->control.vif = &sdata->vif;
	info->flags = IEEE80211_TX_CTL_FIRST_FRAGMENT | IEEE80211_TX_CTL_DONTFRAG | (tid_tx ? IEEE80211_TX_CTL_AMPDU : 0);

	info->control.flags = IEEE80211_TX_CTRL_FAST_XMIT;


	if (local->force_tx_status)
		info->flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;


	if (hdr->frame_control & cpu_to_le16(IEEE80211_STYPE_QOS_DATA)) {
		tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
		*ieee80211_get_qos_ctl(hdr) = tid;
	}

	__skb_queue_head_init(&tx.skbs);

	tx.flags = IEEE80211_TX_UNICAST;
	tx.local = local;
	tx.sdata = sdata;
	tx.sta = sta;
	tx.key = fast_tx->key;

	if (!ieee80211_hw_check(&local->hw, HAS_RATE_CONTROL)) {
		tx.skb = skb;
		r = ieee80211_tx_h_rate_ctrl(&tx);
		skb = tx.skb;
		tx.skb = NULL;

		if (r != TX_CONTINUE) {
			if (r != TX_QUEUED)
				kfree_skb(skb);
			return true;
		}
	}

	if (ieee80211_queue_skb(local, sdata, sta, skb))
		return true;

	ieee80211_xmit_fast_finish(sdata, sta, fast_tx->pn_offs, fast_tx->key, skb);

	if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
		sdata = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);

	__skb_queue_tail(&tx.skbs, skb);
	ieee80211_tx_frags(local, &sdata->vif, sta, &tx.skbs, false);
	return true;
}

struct sk_buff *ieee80211_tx_dequeue(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct txq_info *txqi = container_of(txq, struct txq_info, txq);
	struct ieee80211_hdr *hdr;
	struct sk_buff *skb = NULL;
	struct fq *fq = &local->fq;
	struct fq_tin *tin = &txqi->tin;
	struct ieee80211_tx_info *info;
	struct ieee80211_tx_data tx;
	ieee80211_tx_result r;
	struct ieee80211_vif *vif = txq->vif;

	WARN_ON_ONCE(softirq_count() == 0);

	if (!ieee80211_txq_airtime_check(hw, txq))
		return NULL;

begin:
	spin_lock_bh(&fq->lock);

	if (test_bit(IEEE80211_TXQ_STOP, &txqi->flags) || test_bit(IEEE80211_TXQ_STOP_NETIF_TX, &txqi->flags))
		goto out;

	if (vif->txqs_stopped[txq->ac]) {
		set_bit(IEEE80211_TXQ_STOP_NETIF_TX, &txqi->flags);
		goto out;
	}

	
	skb = __skb_dequeue(&txqi->frags);
	if (unlikely(skb)) {
		if (!(IEEE80211_SKB_CB(skb)->control.flags & IEEE80211_TX_INTCFL_NEED_TXPROCESSING))
			goto out;
		IEEE80211_SKB_CB(skb)->control.flags &= ~IEEE80211_TX_INTCFL_NEED_TXPROCESSING;
	} else {
		skb = fq_tin_dequeue(fq, tin, fq_tin_dequeue_func);
	}

	if (!skb)
		goto out;

	spin_unlock_bh(&fq->lock);

	hdr = (struct ieee80211_hdr *)skb->data;
	info = IEEE80211_SKB_CB(skb);

	memset(&tx, 0, sizeof(tx));
	__skb_queue_head_init(&tx.skbs);
	tx.local = local;
	tx.skb = skb;
	tx.sdata = vif_to_sdata(info->control.vif);

	if (txq->sta) {
		tx.sta = container_of(txq->sta, struct sta_info, sta);
		
		if (unlikely(!(info->flags & IEEE80211_TX_CTL_INJECTED) && ieee80211_is_data(hdr->frame_control) && !ieee80211_vif_is_mesh(&tx.sdata->vif) && tx.sdata->vif.type != NL80211_IFTYPE_OCB && !is_multicast_ether_addr(hdr->addr1) && !test_sta_flag(tx.sta, WLAN_STA_AUTHORIZED) && (!(info->control.flags & IEEE80211_TX_CTRL_PORT_CTRL_PROTO) || !ether_addr_equal(tx.sdata->vif.addr, hdr->addr2)))) {








			I802_DEBUG_INC(local->tx_handlers_drop_unauth_port);
			ieee80211_free_txskb(&local->hw, skb);
			goto begin;
		}
	}

	
	r = ieee80211_tx_h_select_key(&tx);
	if (r != TX_CONTINUE) {
		ieee80211_free_txskb(&local->hw, skb);
		goto begin;
	}

	if (test_bit(IEEE80211_TXQ_AMPDU, &txqi->flags))
		info->flags |= IEEE80211_TX_CTL_AMPDU;
	else info->flags &= ~IEEE80211_TX_CTL_AMPDU;

	if (info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP)
		goto encap_out;

	if (info->control.flags & IEEE80211_TX_CTRL_FAST_XMIT) {
		struct sta_info *sta = container_of(txq->sta, struct sta_info, sta);
		u8 pn_offs = 0;

		if (tx.key && (tx.key->conf.flags & IEEE80211_KEY_FLAG_GENERATE_IV))
			pn_offs = ieee80211_hdrlen(hdr->frame_control);

		ieee80211_xmit_fast_finish(sta->sdata, sta, pn_offs, tx.key, skb);
	} else {
		if (invoke_tx_handlers_late(&tx))
			goto begin;

		skb = __skb_dequeue(&tx.skbs);

		if (!skb_queue_empty(&tx.skbs)) {
			spin_lock_bh(&fq->lock);
			skb_queue_splice_tail(&tx.skbs, &txqi->frags);
			spin_unlock_bh(&fq->lock);
		}
	}

	if (skb_has_frag_list(skb) && !ieee80211_hw_check(&local->hw, TX_FRAG_LIST)) {
		if (skb_linearize(skb)) {
			ieee80211_free_txskb(&local->hw, skb);
			goto begin;
		}
	}

	switch (tx.sdata->vif.type) {
	case NL80211_IFTYPE_MONITOR:
		if (tx.sdata->u.mntr.flags & MONITOR_FLAG_ACTIVE) {
			vif = &tx.sdata->vif;
			break;
		}
		tx.sdata = rcu_dereference(local->monitor_sdata);
		if (tx.sdata) {
			vif = &tx.sdata->vif;
			info->hw_queue = vif->hw_queue[skb_get_queue_mapping(skb)];
		} else if (ieee80211_hw_check(&local->hw, QUEUE_CONTROL)) {
			ieee80211_free_txskb(&local->hw, skb);
			goto begin;
		} else {
			vif = NULL;
		}
		break;
	case NL80211_IFTYPE_AP_VLAN:
		tx.sdata = container_of(tx.sdata->bss, struct ieee80211_sub_if_data, u.ap);
		fallthrough;
	default:
		vif = &tx.sdata->vif;
		break;
	}

encap_out:
	IEEE80211_SKB_CB(skb)->control.vif = vif;

	if (vif && wiphy_ext_feature_isset(local->hw.wiphy, NL80211_EXT_FEATURE_AQL)) {
		bool ampdu = txq->ac != IEEE80211_AC_VO;
		u32 airtime;

		airtime = ieee80211_calc_expected_tx_airtime(hw, vif, txq->sta, skb->len, ampdu);
		if (airtime) {
			airtime = ieee80211_info_set_tx_time_est(info, airtime);
			ieee80211_sta_update_pending_airtime(local, tx.sta, txq->ac, airtime, false);


		}
	}

	return skb;

out:
	spin_unlock_bh(&fq->lock);

	return skb;
}
EXPORT_SYMBOL(ieee80211_tx_dequeue);

struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw, u8 ac)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_txq *ret = NULL;
	struct txq_info *txqi = NULL, *head = NULL;
	bool found_eligible_txq = false;

	spin_lock_bh(&local->active_txq_lock[ac]);

 begin:
	txqi = list_first_entry_or_null(&local->active_txqs[ac], struct txq_info, schedule_order);

	if (!txqi)
		goto out;

	if (txqi == head) {
		if (!found_eligible_txq)
			goto out;
		else found_eligible_txq = false;
	}

	if (!head)
		head = txqi;

	if (txqi->txq.sta) {
		struct sta_info *sta = container_of(txqi->txq.sta, struct sta_info, sta);
		bool aql_check = ieee80211_txq_airtime_check(hw, &txqi->txq);
		s64 deficit = sta->airtime[txqi->txq.ac].deficit;

		if (aql_check)
			found_eligible_txq = true;

		if (deficit < 0)
			sta->airtime[txqi->txq.ac].deficit += sta->airtime_weight;

		if (deficit < 0 || !aql_check) {
			list_move_tail(&txqi->schedule_order, &local->active_txqs[txqi->txq.ac]);
			goto begin;
		}
	}


	if (txqi->schedule_round == local->schedule_round[ac])
		goto out;

	list_del_init(&txqi->schedule_order);
	txqi->schedule_round = local->schedule_round[ac];
	ret = &txqi->txq;

out:
	spin_unlock_bh(&local->active_txq_lock[ac]);
	return ret;
}
EXPORT_SYMBOL(ieee80211_next_txq);

void __ieee80211_schedule_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq, bool force)

{
	struct ieee80211_local *local = hw_to_local(hw);
	struct txq_info *txqi = to_txq_info(txq);

	spin_lock_bh(&local->active_txq_lock[txq->ac]);

	if (list_empty(&txqi->schedule_order) && (force || !skb_queue_empty(&txqi->frags) || txqi->tin.backlog_packets)) {

		
		if (txqi->txq.sta && local->airtime_flags && wiphy_ext_feature_isset(local->hw.wiphy, NL80211_EXT_FEATURE_AIRTIME_FAIRNESS))

			list_add(&txqi->schedule_order, &local->active_txqs[txq->ac]);
		else list_add_tail(&txqi->schedule_order, &local->active_txqs[txq->ac]);

	}

	spin_unlock_bh(&local->active_txq_lock[txq->ac]);
}
EXPORT_SYMBOL(__ieee80211_schedule_txq);

DEFINE_STATIC_KEY_FALSE(aql_disable);

bool ieee80211_txq_airtime_check(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct sta_info *sta;
	struct ieee80211_local *local = hw_to_local(hw);

	if (!wiphy_ext_feature_isset(local->hw.wiphy, NL80211_EXT_FEATURE_AQL))
		return true;

	if (static_branch_unlikely(&aql_disable))
		return true;

	if (!txq->sta)
		return true;

	if (unlikely(txq->tid == IEEE80211_NUM_TIDS))
		return true;

	sta = container_of(txq->sta, struct sta_info, sta);
	if (atomic_read(&sta->airtime[txq->ac].aql_tx_pending) < sta->airtime[txq->ac].aql_limit_low)
		return true;

	if (atomic_read(&local->aql_total_pending_airtime) < local->aql_threshold && atomic_read(&sta->airtime[txq->ac].aql_tx_pending) < sta->airtime[txq->ac].aql_limit_high)


		return true;

	return false;
}
EXPORT_SYMBOL(ieee80211_txq_airtime_check);

bool ieee80211_txq_may_transmit(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct txq_info *iter, *tmp, *txqi = to_txq_info(txq);
	struct sta_info *sta;
	u8 ac = txq->ac;

	spin_lock_bh(&local->active_txq_lock[ac]);

	if (!txqi->txq.sta)
		goto out;

	if (list_empty(&txqi->schedule_order))
		goto out;

	list_for_each_entry_safe(iter, tmp, &local->active_txqs[ac], schedule_order) {
		if (iter == txqi)
			break;

		if (!iter->txq.sta) {
			list_move_tail(&iter->schedule_order, &local->active_txqs[ac]);
			continue;
		}
		sta = container_of(iter->txq.sta, struct sta_info, sta);
		if (sta->airtime[ac].deficit < 0)
			sta->airtime[ac].deficit += sta->airtime_weight;
		list_move_tail(&iter->schedule_order, &local->active_txqs[ac]);
	}

	sta = container_of(txqi->txq.sta, struct sta_info, sta);
	if (sta->airtime[ac].deficit >= 0)
		goto out;

	sta->airtime[ac].deficit += sta->airtime_weight;
	list_move_tail(&txqi->schedule_order, &local->active_txqs[ac]);
	spin_unlock_bh(&local->active_txq_lock[ac]);

	return false;
out:
	if (!list_empty(&txqi->schedule_order))
		list_del_init(&txqi->schedule_order);
	spin_unlock_bh(&local->active_txq_lock[ac]);

	return true;
}
EXPORT_SYMBOL(ieee80211_txq_may_transmit);

void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac)
{
	struct ieee80211_local *local = hw_to_local(hw);

	spin_lock_bh(&local->active_txq_lock[ac]);
	local->schedule_round[ac]++;
	spin_unlock_bh(&local->active_txq_lock[ac]);
}
EXPORT_SYMBOL(ieee80211_txq_schedule_start);

void __ieee80211_subif_start_xmit(struct sk_buff *skb, struct net_device *dev, u32 info_flags, u32 ctrl_flags, u64 *cookie)



{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;
	struct sk_buff *next;

	if (unlikely(skb->len < ETH_HLEN)) {
		kfree_skb(skb);
		return;
	}

	rcu_read_lock();

	if (ieee80211_lookup_ra_sta(sdata, skb, &sta))
		goto out_free;

	if (IS_ERR(sta))
		sta = NULL;

	if (local->ops->wake_tx_queue) {
		u16 queue = __ieee80211_select_queue(sdata, sta, skb);
		skb_set_queue_mapping(skb, queue);
		skb_get_hash(skb);
	}

	if (sta) {
		struct ieee80211_fast_tx *fast_tx;

		sk_pacing_shift_update(skb->sk, sdata->local->hw.tx_sk_pacing_shift);

		fast_tx = rcu_dereference(sta->fast_tx);

		if (fast_tx && ieee80211_xmit_fast(sdata, sta, fast_tx, skb))
			goto out;
	}

	if (skb_is_gso(skb)) {
		struct sk_buff *segs;

		segs = skb_gso_segment(skb, 0);
		if (IS_ERR(segs)) {
			goto out_free;
		} else if (segs) {
			consume_skb(skb);
			skb = segs;
		}
	} else {
		
		if (skb_linearize(skb)) {
			kfree_skb(skb);
			goto out;
		}

		
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			skb_set_transport_header(skb, skb_checksum_start_offset(skb));
			if (skb_checksum_help(skb))
				goto out_free;
		}
	}

	skb_list_walk_safe(skb, skb, next) {
		skb_mark_not_on_list(skb);

		if (skb->protocol == sdata->control_port_protocol)
			ctrl_flags |= IEEE80211_TX_CTRL_SKIP_MPATH_LOOKUP;

		skb = ieee80211_build_hdr(sdata, skb, info_flags, sta, ctrl_flags, cookie);
		if (IS_ERR(skb)) {
			kfree_skb_list(next);
			goto out;
		}

		dev_sw_netstats_tx_add(dev, 1, skb->len);

		ieee80211_xmit(sdata, sta, skb);
	}
	goto out;
 out_free:
	kfree_skb(skb);
 out:
	rcu_read_unlock();
}

static int ieee80211_change_da(struct sk_buff *skb, struct sta_info *sta)
{
	struct ethhdr *eth;
	int err;

	err = skb_ensure_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	eth = (void *)skb->data;
	ether_addr_copy(eth->h_dest, sta->sta.addr);

	return 0;
}

static bool ieee80211_multicast_to_unicast(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	const struct ethhdr *eth = (void *)skb->data;
	const struct vlan_ethhdr *ethvlan = (void *)skb->data;
	__be16 ethertype;

	if (likely(!is_multicast_ether_addr(eth->h_dest)))
		return false;

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_AP_VLAN:
		if (sdata->u.vlan.sta)
			return false;
		if (sdata->wdev.use_4addr)
			return false;
		fallthrough;
	case NL80211_IFTYPE_AP:
		
		if (!sdata->bss->multicast_to_unicast)
			return false;
		break;
	default:
		return false;
	}

	
	ethertype = eth->h_proto;
	if (ethertype == htons(ETH_P_8021Q) && skb->len >= VLAN_ETH_HLEN)
		ethertype = ethvlan->h_vlan_encapsulated_proto;
	switch (ethertype) {
	case htons(ETH_P_ARP):
	case htons(ETH_P_IP):
	case htons(ETH_P_IPV6):
		break;
	default:
		return false;
	}

	return true;
}

static void ieee80211_convert_to_unicast(struct sk_buff *skb, struct net_device *dev, struct sk_buff_head *queue)

{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	const struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct sta_info *sta, *first = NULL;
	struct sk_buff *cloned_skb;

	rcu_read_lock();

	list_for_each_entry_rcu(sta, &local->sta_list, list) {
		if (sdata != sta->sdata)
			
			continue;
		if (unlikely(ether_addr_equal(eth->h_source, sta->sta.addr)))
			
			continue;
		if (!first) {
			first = sta;
			continue;
		}
		cloned_skb = skb_clone(skb, GFP_ATOMIC);
		if (!cloned_skb)
			goto multicast;
		if (unlikely(ieee80211_change_da(cloned_skb, sta))) {
			dev_kfree_skb(cloned_skb);
			goto multicast;
		}
		__skb_queue_tail(queue, cloned_skb);
	}

	if (likely(first)) {
		if (unlikely(ieee80211_change_da(skb, first)))
			goto multicast;
		__skb_queue_tail(queue, skb);
	} else {
		
		kfree_skb(skb);
		skb = NULL;
	}

	goto out;
multicast:
	__skb_queue_purge(queue);
	__skb_queue_tail(queue, skb);
out:
	rcu_read_unlock();
}


netdev_tx_t ieee80211_subif_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	if (unlikely(ieee80211_multicast_to_unicast(skb, dev))) {
		struct sk_buff_head queue;

		__skb_queue_head_init(&queue);
		ieee80211_convert_to_unicast(skb, dev, &queue);
		while ((skb = __skb_dequeue(&queue)))
			__ieee80211_subif_start_xmit(skb, dev, 0, 0, NULL);
	} else {
		__ieee80211_subif_start_xmit(skb, dev, 0, 0, NULL);
	}

	return NETDEV_TX_OK;
}

static bool ieee80211_tx_8023(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, int led_len, struct sta_info *sta, bool txpending)


{
	struct ieee80211_local *local = sdata->local;
	struct ieee80211_tx_control control = {};
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_sta *pubsta = NULL;
	unsigned long flags;
	int q = info->hw_queue;

	if (sta)
		sk_pacing_shift_update(skb->sk, local->hw.tx_sk_pacing_shift);

	if (ieee80211_queue_skb(local, sdata, sta, skb))
		return true;

	spin_lock_irqsave(&local->queue_stop_reason_lock, flags);

	if (local->queue_stop_reasons[q] || (!txpending && !skb_queue_empty(&local->pending[q]))) {
		if (txpending)
			skb_queue_head(&local->pending[q], skb);
		else skb_queue_tail(&local->pending[q], skb);

		spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

		return false;
	}

	spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

	if (sta && sta->uploaded)
		pubsta = &sta->sta;

	control.sta = pubsta;

	drv_tx(local, &control, skb);

	return true;
}

static void ieee80211_8023_xmit(struct ieee80211_sub_if_data *sdata, struct net_device *dev, struct sta_info *sta, struct ieee80211_key *key, struct sk_buff *skb)

{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_local *local = sdata->local;
	struct tid_ampdu_tx *tid_tx;
	u8 tid;

	if (local->ops->wake_tx_queue) {
		u16 queue = __ieee80211_select_queue(sdata, sta, skb);
		skb_set_queue_mapping(skb, queue);
		skb_get_hash(skb);
	}

	if (unlikely(test_bit(SCAN_SW_SCANNING, &local->scanning)) && test_bit(SDATA_STATE_OFFCHANNEL, &sdata->state))
		goto out_free;

	memset(info, 0, sizeof(*info));

	tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
	tid_tx = rcu_dereference(sta->ampdu_mlme.tid_tx[tid]);
	if (tid_tx) {
		if (!test_bit(HT_AGG_STATE_OPERATIONAL, &tid_tx->state)) {
			
			__ieee80211_subif_start_xmit(skb, dev, 0, 0, NULL);
			return;
		}

		info->flags |= IEEE80211_TX_CTL_AMPDU;
		if (tid_tx->timeout)
			tid_tx->last_tx = jiffies;
	}

	if (unlikely(skb->sk && skb_shinfo(skb)->tx_flags & SKBTX_WIFI_STATUS))
		info->ack_frame_id = ieee80211_store_ack_skb(local, skb, &info->flags, NULL);

	info->hw_queue = sdata->vif.hw_queue[skb_get_queue_mapping(skb)];

	dev_sw_netstats_tx_add(dev, 1, skb->len);

	sta->tx_stats.bytes[skb_get_queue_mapping(skb)] += skb->len;
	sta->tx_stats.packets[skb_get_queue_mapping(skb)]++;

	if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
		sdata = container_of(sdata->bss, struct ieee80211_sub_if_data, u.ap);

	info->flags |= IEEE80211_TX_CTL_HW_80211_ENCAP;
	info->control.vif = &sdata->vif;

	if (key)
		info->control.hw_key = &key->conf;

	ieee80211_tx_8023(sdata, skb, skb->len, sta, false);

	return;

out_free:
	kfree_skb(skb);
}

netdev_tx_t ieee80211_subif_start_xmit_8023(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ethhdr *ehdr = (struct ethhdr *)skb->data;
	struct ieee80211_key *key;
	struct sta_info *sta;

	if (unlikely(skb->len < ETH_HLEN)) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	rcu_read_lock();

	if (ieee80211_lookup_ra_sta(sdata, skb, &sta)) {
		kfree_skb(skb);
		goto out;
	}

	if (unlikely(IS_ERR_OR_NULL(sta) || !sta->uploaded || !test_sta_flag(sta, WLAN_STA_AUTHORIZED) || sdata->control_port_protocol == ehdr->h_proto))

		goto skip_offload;

	key = rcu_dereference(sta->ptk[sta->ptk_idx]);
	if (!key)
		key = rcu_dereference(sdata->default_unicast_key);

	if (key && (!(key->flags & KEY_FLAG_UPLOADED_TO_HARDWARE) || key->conf.cipher == WLAN_CIPHER_SUITE_TKIP))
		goto skip_offload;

	ieee80211_8023_xmit(sdata, dev, sta, key, skb);
	goto out;

skip_offload:
	ieee80211_subif_start_xmit(skb, dev);
out:
	rcu_read_unlock();

	return NETDEV_TX_OK;
}

struct sk_buff * ieee80211_build_data_template(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, u32 info_flags)

{
	struct ieee80211_hdr *hdr;
	struct ieee80211_tx_data tx = {
		.local = sdata->local, .sdata = sdata, };

	struct sta_info *sta;

	rcu_read_lock();

	if (ieee80211_lookup_ra_sta(sdata, skb, &sta)) {
		kfree_skb(skb);
		skb = ERR_PTR(-EINVAL);
		goto out;
	}

	skb = ieee80211_build_hdr(sdata, skb, info_flags, sta, 0, NULL);
	if (IS_ERR(skb))
		goto out;

	hdr = (void *)skb->data;
	tx.sta = sta_info_get(sdata, hdr->addr1);
	tx.skb = skb;

	if (ieee80211_tx_h_select_key(&tx) != TX_CONTINUE) {
		rcu_read_unlock();
		kfree_skb(skb);
		return ERR_PTR(-EINVAL);
	}

out:
	rcu_read_unlock();
	return skb;
}


void ieee80211_clear_tx_pending(struct ieee80211_local *local)
{
	struct sk_buff *skb;
	int i;

	for (i = 0; i < local->hw.queues; i++) {
		while ((skb = skb_dequeue(&local->pending[i])) != NULL)
			ieee80211_free_txskb(&local->hw, skb);
	}
}


static bool ieee80211_tx_pending_skb(struct ieee80211_local *local, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;
	struct ieee80211_hdr *hdr;
	bool result;
	struct ieee80211_chanctx_conf *chanctx_conf;

	sdata = vif_to_sdata(info->control.vif);

	if (info->control.flags & IEEE80211_TX_INTCFL_NEED_TXPROCESSING) {
		chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);
		if (unlikely(!chanctx_conf)) {
			dev_kfree_skb(skb);
			return true;
		}
		info->band = chanctx_conf->def.chan->band;
		result = ieee80211_tx(sdata, NULL, skb, true);
	} else if (info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP) {
		if (ieee80211_lookup_ra_sta(sdata, skb, &sta)) {
			dev_kfree_skb(skb);
			return true;
		}

		if (IS_ERR(sta) || (sta && !sta->uploaded))
			sta = NULL;

		result = ieee80211_tx_8023(sdata, skb, skb->len, sta, true);
	} else {
		struct sk_buff_head skbs;

		__skb_queue_head_init(&skbs);
		__skb_queue_tail(&skbs, skb);

		hdr = (struct ieee80211_hdr *)skb->data;
		sta = sta_info_get(sdata, hdr->addr1);

		result = __ieee80211_tx(local, &skbs, skb->len, sta, true);
	}

	return result;
}


void ieee80211_tx_pending(struct tasklet_struct *t)
{
	struct ieee80211_local *local = from_tasklet(local, t, tx_pending_tasklet);
	unsigned long flags;
	int i;
	bool txok;

	rcu_read_lock();

	spin_lock_irqsave(&local->queue_stop_reason_lock, flags);
	for (i = 0; i < local->hw.queues; i++) {
		
		if (local->queue_stop_reasons[i] || skb_queue_empty(&local->pending[i]))
			continue;

		while (!skb_queue_empty(&local->pending[i])) {
			struct sk_buff *skb = __skb_dequeue(&local->pending[i]);
			struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

			if (WARN_ON(!info->control.vif)) {
				ieee80211_free_txskb(&local->hw, skb);
				continue;
			}

			spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

			txok = ieee80211_tx_pending_skb(local, skb);
			spin_lock_irqsave(&local->queue_stop_reason_lock, flags);
			if (!txok)
				break;
		}

		if (skb_queue_empty(&local->pending[i]))
			ieee80211_propagate_queue_wake(local, i);
	}
	spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

	rcu_read_unlock();
}



static void __ieee80211_beacon_add_tim(struct ieee80211_sub_if_data *sdata, struct ps_data *ps, struct sk_buff *skb, bool is_template)

{
	u8 *pos, *tim;
	int aid0 = 0;
	int i, have_bits = 0, n1, n2;

	
	if (atomic_read(&ps->num_sta_ps) > 0)
		
		have_bits = !bitmap_empty((unsigned long *)ps->tim, IEEE80211_MAX_AID+1);
	if (!is_template) {
		if (ps->dtim_count == 0)
			ps->dtim_count = sdata->vif.bss_conf.dtim_period - 1;
		else ps->dtim_count--;
	}

	tim = pos = skb_put(skb, 6);
	*pos++ = WLAN_EID_TIM;
	*pos++ = 4;
	*pos++ = ps->dtim_count;
	*pos++ = sdata->vif.bss_conf.dtim_period;

	if (ps->dtim_count == 0 && !skb_queue_empty(&ps->bc_buf))
		aid0 = 1;

	ps->dtim_bc_mc = aid0 == 1;

	if (have_bits) {
		
		n1 = 0;
		for (i = 0; i < IEEE80211_MAX_TIM_LEN; i++) {
			if (ps->tim[i]) {
				n1 = i & 0xfe;
				break;
			}
		}
		n2 = n1;
		for (i = IEEE80211_MAX_TIM_LEN - 1; i >= n1; i--) {
			if (ps->tim[i]) {
				n2 = i;
				break;
			}
		}

		
		*pos++ = n1 | aid0;
		
		skb_put(skb, n2 - n1);
		memcpy(pos, ps->tim + n1, n2 - n1 + 1);

		tim[1] = n2 - n1 + 4;
	} else {
		*pos++ = aid0; 
		*pos++ = 0; 
	}
}

static int ieee80211_beacon_add_tim(struct ieee80211_sub_if_data *sdata, struct ps_data *ps, struct sk_buff *skb, bool is_template)

{
	struct ieee80211_local *local = sdata->local;

	
	if (local->tim_in_locked_section) {
		__ieee80211_beacon_add_tim(sdata, ps, skb, is_template);
	} else {
		spin_lock_bh(&local->tim_lock);
		__ieee80211_beacon_add_tim(sdata, ps, skb, is_template);
		spin_unlock_bh(&local->tim_lock);
	}

	return 0;
}

static void ieee80211_set_beacon_cntdwn(struct ieee80211_sub_if_data *sdata, struct beacon_data *beacon)
{
	struct probe_resp *resp;
	u8 *beacon_data;
	size_t beacon_data_len;
	int i;
	u8 count = beacon->cntdwn_current_counter;

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_AP:
		beacon_data = beacon->tail;
		beacon_data_len = beacon->tail_len;
		break;
	case NL80211_IFTYPE_ADHOC:
		beacon_data = beacon->head;
		beacon_data_len = beacon->head_len;
		break;
	case NL80211_IFTYPE_MESH_POINT:
		beacon_data = beacon->head;
		beacon_data_len = beacon->head_len;
		break;
	default:
		return;
	}

	rcu_read_lock();
	for (i = 0; i < IEEE80211_MAX_CNTDWN_COUNTERS_NUM; ++i) {
		resp = rcu_dereference(sdata->u.ap.probe_resp);

		if (beacon->cntdwn_counter_offsets[i]) {
			if (WARN_ON_ONCE(beacon->cntdwn_counter_offsets[i] >= beacon_data_len)) {
				rcu_read_unlock();
				return;
			}

			beacon_data[beacon->cntdwn_counter_offsets[i]] = count;
		}

		if (sdata->vif.type == NL80211_IFTYPE_AP && resp)
			resp->data[resp->cntdwn_counter_offsets[i]] = count;
	}
	rcu_read_unlock();
}

static u8 __ieee80211_beacon_update_cntdwn(struct beacon_data *beacon)
{
	beacon->cntdwn_current_counter--;

	
	WARN_ON_ONCE(!beacon->cntdwn_current_counter);

	return beacon->cntdwn_current_counter;
}

u8 ieee80211_beacon_update_cntdwn(struct ieee80211_vif *vif)
{
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);
	struct beacon_data *beacon = NULL;
	u8 count = 0;

	rcu_read_lock();

	if (sdata->vif.type == NL80211_IFTYPE_AP)
		beacon = rcu_dereference(sdata->u.ap.beacon);
	else if (sdata->vif.type == NL80211_IFTYPE_ADHOC)
		beacon = rcu_dereference(sdata->u.ibss.presp);
	else if (ieee80211_vif_is_mesh(&sdata->vif))
		beacon = rcu_dereference(sdata->u.mesh.beacon);

	if (!beacon)
		goto unlock;

	count = __ieee80211_beacon_update_cntdwn(beacon);

unlock:
	rcu_read_unlock();
	return count;
}
EXPORT_SYMBOL(ieee80211_beacon_update_cntdwn);

void ieee80211_beacon_set_cntdwn(struct ieee80211_vif *vif, u8 counter)
{
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);
	struct beacon_data *beacon = NULL;

	rcu_read_lock();

	if (sdata->vif.type == NL80211_IFTYPE_AP)
		beacon = rcu_dereference(sdata->u.ap.beacon);
	else if (sdata->vif.type == NL80211_IFTYPE_ADHOC)
		beacon = rcu_dereference(sdata->u.ibss.presp);
	else if (ieee80211_vif_is_mesh(&sdata->vif))
		beacon = rcu_dereference(sdata->u.mesh.beacon);

	if (!beacon)
		goto unlock;

	if (counter < beacon->cntdwn_current_counter)
		beacon->cntdwn_current_counter = counter;

unlock:
	rcu_read_unlock();
}
EXPORT_SYMBOL(ieee80211_beacon_set_cntdwn);

bool ieee80211_beacon_cntdwn_is_complete(struct ieee80211_vif *vif)
{
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);
	struct beacon_data *beacon = NULL;
	u8 *beacon_data;
	size_t beacon_data_len;
	int ret = false;

	if (!ieee80211_sdata_running(sdata))
		return false;

	rcu_read_lock();
	if (vif->type == NL80211_IFTYPE_AP) {
		struct ieee80211_if_ap *ap = &sdata->u.ap;

		beacon = rcu_dereference(ap->beacon);
		if (WARN_ON(!beacon || !beacon->tail))
			goto out;
		beacon_data = beacon->tail;
		beacon_data_len = beacon->tail_len;
	} else if (vif->type == NL80211_IFTYPE_ADHOC) {
		struct ieee80211_if_ibss *ifibss = &sdata->u.ibss;

		beacon = rcu_dereference(ifibss->presp);
		if (!beacon)
			goto out;

		beacon_data = beacon->head;
		beacon_data_len = beacon->head_len;
	} else if (vif->type == NL80211_IFTYPE_MESH_POINT) {
		struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;

		beacon = rcu_dereference(ifmsh->beacon);
		if (!beacon)
			goto out;

		beacon_data = beacon->head;
		beacon_data_len = beacon->head_len;
	} else {
		WARN_ON(1);
		goto out;
	}

	if (!beacon->cntdwn_counter_offsets[0])
		goto out;

	if (WARN_ON_ONCE(beacon->cntdwn_counter_offsets[0] > beacon_data_len))
		goto out;

	if (beacon_data[beacon->cntdwn_counter_offsets[0]] == 1)
		ret = true;

 out:
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(ieee80211_beacon_cntdwn_is_complete);

static int ieee80211_beacon_protect(struct sk_buff *skb, struct ieee80211_local *local, struct ieee80211_sub_if_data *sdata)

{
	ieee80211_tx_result res;
	struct ieee80211_tx_data tx;
	struct sk_buff *check_skb;

	memset(&tx, 0, sizeof(tx));
	tx.key = rcu_dereference(sdata->default_beacon_key);
	if (!tx.key)
		return 0;
	tx.local = local;
	tx.sdata = sdata;
	__skb_queue_head_init(&tx.skbs);
	__skb_queue_tail(&tx.skbs, skb);
	res = ieee80211_tx_h_encrypt(&tx);
	check_skb = __skb_dequeue(&tx.skbs);
	
	WARN_ON(check_skb != skb);
	if (WARN_ON_ONCE(res != TX_CONTINUE))
		return -EINVAL;

	return 0;
}

static struct sk_buff * __ieee80211_beacon_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_mutable_offsets *offs, bool is_template)



{
	struct ieee80211_local *local = hw_to_local(hw);
	struct beacon_data *beacon = NULL;
	struct sk_buff *skb = NULL;
	struct ieee80211_tx_info *info;
	struct ieee80211_sub_if_data *sdata = NULL;
	enum nl80211_band band;
	struct ieee80211_tx_rate_control txrc;
	struct ieee80211_chanctx_conf *chanctx_conf;
	int csa_off_base = 0;

	rcu_read_lock();

	sdata = vif_to_sdata(vif);
	chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);

	if (!ieee80211_sdata_running(sdata) || !chanctx_conf)
		goto out;

	if (offs)
		memset(offs, 0, sizeof(*offs));

	if (sdata->vif.type == NL80211_IFTYPE_AP) {
		struct ieee80211_if_ap *ap = &sdata->u.ap;

		beacon = rcu_dereference(ap->beacon);
		if (beacon) {
			if (beacon->cntdwn_counter_offsets[0]) {
				if (!is_template)
					ieee80211_beacon_update_cntdwn(vif);

				ieee80211_set_beacon_cntdwn(sdata, beacon);
			}

			
			skb = dev_alloc_skb(local->tx_headroom + beacon->head_len + beacon->tail_len + 256 + local->hw.extra_beacon_tailroom);


			if (!skb)
				goto out;

			skb_reserve(skb, local->tx_headroom);
			skb_put_data(skb, beacon->head, beacon->head_len);

			ieee80211_beacon_add_tim(sdata, &ap->ps, skb, is_template);

			if (offs) {
				offs->tim_offset = beacon->head_len;
				offs->tim_length = skb->len - beacon->head_len;

				
				csa_off_base = skb->len;
			}

			if (beacon->tail)
				skb_put_data(skb, beacon->tail, beacon->tail_len);

			if (ieee80211_beacon_protect(skb, local, sdata) < 0)
				goto out;
		} else goto out;
	} else if (sdata->vif.type == NL80211_IFTYPE_ADHOC) {
		struct ieee80211_if_ibss *ifibss = &sdata->u.ibss;
		struct ieee80211_hdr *hdr;

		beacon = rcu_dereference(ifibss->presp);
		if (!beacon)
			goto out;

		if (beacon->cntdwn_counter_offsets[0]) {
			if (!is_template)
				__ieee80211_beacon_update_cntdwn(beacon);

			ieee80211_set_beacon_cntdwn(sdata, beacon);
		}

		skb = dev_alloc_skb(local->tx_headroom + beacon->head_len + local->hw.extra_beacon_tailroom);
		if (!skb)
			goto out;
		skb_reserve(skb, local->tx_headroom);
		skb_put_data(skb, beacon->head, beacon->head_len);

		hdr = (struct ieee80211_hdr *) skb->data;
		hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON);
	} else if (ieee80211_vif_is_mesh(&sdata->vif)) {
		struct ieee80211_if_mesh *ifmsh = &sdata->u.mesh;

		beacon = rcu_dereference(ifmsh->beacon);
		if (!beacon)
			goto out;

		if (beacon->cntdwn_counter_offsets[0]) {
			if (!is_template)
				
				__ieee80211_beacon_update_cntdwn(beacon);

			ieee80211_set_beacon_cntdwn(sdata, beacon);
		}

		if (ifmsh->sync_ops)
			ifmsh->sync_ops->adjust_tsf(sdata, beacon);

		skb = dev_alloc_skb(local->tx_headroom + beacon->head_len + 256 + beacon->tail_len + local->hw.extra_beacon_tailroom);



		if (!skb)
			goto out;
		skb_reserve(skb, local->tx_headroom);
		skb_put_data(skb, beacon->head, beacon->head_len);
		ieee80211_beacon_add_tim(sdata, &ifmsh->ps, skb, is_template);

		if (offs) {
			offs->tim_offset = beacon->head_len;
			offs->tim_length = skb->len - beacon->head_len;
		}

		skb_put_data(skb, beacon->tail, beacon->tail_len);
	} else {
		WARN_ON(1);
		goto out;
	}

	
	if (offs && beacon) {
		int i;

		for (i = 0; i < IEEE80211_MAX_CNTDWN_COUNTERS_NUM; i++) {
			u16 csa_off = beacon->cntdwn_counter_offsets[i];

			if (!csa_off)
				continue;

			offs->cntdwn_counter_offs[i] = csa_off_base + csa_off;
		}
	}

	band = chanctx_conf->def.chan->band;

	info = IEEE80211_SKB_CB(skb);

	info->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;
	info->flags |= IEEE80211_TX_CTL_NO_ACK;
	info->band = band;

	memset(&txrc, 0, sizeof(txrc));
	txrc.hw = hw;
	txrc.sband = local->hw.wiphy->bands[band];
	txrc.bss_conf = &sdata->vif.bss_conf;
	txrc.skb = skb;
	txrc.reported_rate.idx = -1;
	if (sdata->beacon_rate_set && sdata->beacon_rateidx_mask[band])
		txrc.rate_idx_mask = sdata->beacon_rateidx_mask[band];
	else txrc.rate_idx_mask = sdata->rc_rateidx_mask[band];
	txrc.bss = true;
	rate_control_get_rate(sdata, NULL, &txrc);

	info->control.vif = vif;

	info->flags |= IEEE80211_TX_CTL_CLEAR_PS_FILT | IEEE80211_TX_CTL_ASSIGN_SEQ | IEEE80211_TX_CTL_FIRST_FRAGMENT;

 out:
	rcu_read_unlock();
	return skb;

}

struct sk_buff * ieee80211_beacon_get_template(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_mutable_offsets *offs)


{
	return __ieee80211_beacon_get(hw, vif, offs, true);
}
EXPORT_SYMBOL(ieee80211_beacon_get_template);

struct sk_buff *ieee80211_beacon_get_tim(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 *tim_offset, u16 *tim_length)

{
	struct ieee80211_mutable_offsets offs = {};
	struct sk_buff *bcn = __ieee80211_beacon_get(hw, vif, &offs, false);
	struct sk_buff *copy;
	struct ieee80211_supported_band *sband;
	int shift;

	if (!bcn)
		return bcn;

	if (tim_offset)
		*tim_offset = offs.tim_offset;

	if (tim_length)
		*tim_length = offs.tim_length;

	if (ieee80211_hw_check(hw, BEACON_TX_STATUS) || !hw_to_local(hw)->monitors)
		return bcn;

	
	copy = skb_copy(bcn, GFP_ATOMIC);
	if (!copy)
		return bcn;

	shift = ieee80211_vif_get_shift(vif);
	sband = ieee80211_get_sband(vif_to_sdata(vif));
	if (!sband)
		return bcn;

	ieee80211_tx_monitor(hw_to_local(hw), copy, sband, 1, shift, false, NULL);

	return bcn;
}
EXPORT_SYMBOL(ieee80211_beacon_get_tim);

struct sk_buff *ieee80211_proberesp_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct ieee80211_if_ap *ap = NULL;
	struct sk_buff *skb = NULL;
	struct probe_resp *presp = NULL;
	struct ieee80211_hdr *hdr;
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);

	if (sdata->vif.type != NL80211_IFTYPE_AP)
		return NULL;

	rcu_read_lock();

	ap = &sdata->u.ap;
	presp = rcu_dereference(ap->probe_resp);
	if (!presp)
		goto out;

	skb = dev_alloc_skb(presp->len);
	if (!skb)
		goto out;

	skb_put_data(skb, presp->data, presp->len);

	hdr = (struct ieee80211_hdr *) skb->data;
	memset(hdr->addr1, 0, sizeof(hdr->addr1));

out:
	rcu_read_unlock();
	return skb;
}
EXPORT_SYMBOL(ieee80211_proberesp_get);

struct sk_buff *ieee80211_get_fils_discovery_tmpl(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct sk_buff *skb = NULL;
	struct fils_discovery_data *tmpl = NULL;
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);

	if (sdata->vif.type != NL80211_IFTYPE_AP)
		return NULL;

	rcu_read_lock();
	tmpl = rcu_dereference(sdata->u.ap.fils_discovery);
	if (!tmpl) {
		rcu_read_unlock();
		return NULL;
	}

	skb = dev_alloc_skb(sdata->local->hw.extra_tx_headroom + tmpl->len);
	if (skb) {
		skb_reserve(skb, sdata->local->hw.extra_tx_headroom);
		skb_put_data(skb, tmpl->data, tmpl->len);
	}

	rcu_read_unlock();
	return skb;
}
EXPORT_SYMBOL(ieee80211_get_fils_discovery_tmpl);

struct sk_buff * ieee80211_get_unsol_bcast_probe_resp_tmpl(struct ieee80211_hw *hw, struct ieee80211_vif *vif)

{
	struct sk_buff *skb = NULL;
	struct unsol_bcast_probe_resp_data *tmpl = NULL;
	struct ieee80211_sub_if_data *sdata = vif_to_sdata(vif);

	if (sdata->vif.type != NL80211_IFTYPE_AP)
		return NULL;

	rcu_read_lock();
	tmpl = rcu_dereference(sdata->u.ap.unsol_bcast_probe_resp);
	if (!tmpl) {
		rcu_read_unlock();
		return NULL;
	}

	skb = dev_alloc_skb(sdata->local->hw.extra_tx_headroom + tmpl->len);
	if (skb) {
		skb_reserve(skb, sdata->local->hw.extra_tx_headroom);
		skb_put_data(skb, tmpl->data, tmpl->len);
	}

	rcu_read_unlock();
	return skb;
}
EXPORT_SYMBOL(ieee80211_get_unsol_bcast_probe_resp_tmpl);

struct sk_buff *ieee80211_pspoll_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_managed *ifmgd;
	struct ieee80211_pspoll *pspoll;
	struct ieee80211_local *local;
	struct sk_buff *skb;

	if (WARN_ON(vif->type != NL80211_IFTYPE_STATION))
		return NULL;

	sdata = vif_to_sdata(vif);
	ifmgd = &sdata->u.mgd;
	local = sdata->local;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*pspoll));
	if (!skb)
		return NULL;

	skb_reserve(skb, local->hw.extra_tx_headroom);

	pspoll = skb_put_zero(skb, sizeof(*pspoll));
	pspoll->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_PSPOLL);
	pspoll->aid = cpu_to_le16(sdata->vif.bss_conf.aid);

	
	pspoll->aid |= cpu_to_le16(1 << 15 | 1 << 14);

	memcpy(pspoll->bssid, ifmgd->bssid, ETH_ALEN);
	memcpy(pspoll->ta, vif->addr, ETH_ALEN);

	return skb;
}
EXPORT_SYMBOL(ieee80211_pspoll_get);

struct sk_buff *ieee80211_nullfunc_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, bool qos_ok)

{
	struct ieee80211_hdr_3addr *nullfunc;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_managed *ifmgd;
	struct ieee80211_local *local;
	struct sk_buff *skb;
	bool qos = false;

	if (WARN_ON(vif->type != NL80211_IFTYPE_STATION))
		return NULL;

	sdata = vif_to_sdata(vif);
	ifmgd = &sdata->u.mgd;
	local = sdata->local;

	if (qos_ok) {
		struct sta_info *sta;

		rcu_read_lock();
		sta = sta_info_get(sdata, ifmgd->bssid);
		qos = sta && sta->sta.wme;
		rcu_read_unlock();
	}

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*nullfunc) + 2);
	if (!skb)
		return NULL;

	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = skb_put_zero(skb, sizeof(*nullfunc));
	nullfunc->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC | IEEE80211_FCTL_TODS);

	if (qos) {
		__le16 qoshdr = cpu_to_le16(7);

		BUILD_BUG_ON((IEEE80211_STYPE_QOS_NULLFUNC | IEEE80211_STYPE_NULLFUNC) != IEEE80211_STYPE_QOS_NULLFUNC);

		nullfunc->frame_control |= cpu_to_le16(IEEE80211_STYPE_QOS_NULLFUNC);
		skb->priority = 7;
		skb_set_queue_mapping(skb, IEEE80211_AC_VO);
		skb_put_data(skb, &qoshdr, sizeof(qoshdr));
	}

	memcpy(nullfunc->addr1, ifmgd->bssid, ETH_ALEN);
	memcpy(nullfunc->addr2, vif->addr, ETH_ALEN);
	memcpy(nullfunc->addr3, ifmgd->bssid, ETH_ALEN);

	return skb;
}
EXPORT_SYMBOL(ieee80211_nullfunc_get);

struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw, const u8 *src_addr, const u8 *ssid, size_t ssid_len, size_t tailroom)


{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_hdr_3addr *hdr;
	struct sk_buff *skb;
	size_t ie_ssid_len;
	u8 *pos;

	ie_ssid_len = 2 + ssid_len;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*hdr) + ie_ssid_len + tailroom);
	if (!skb)
		return NULL;

	skb_reserve(skb, local->hw.extra_tx_headroom);

	hdr = skb_put_zero(skb, sizeof(*hdr));
	hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
	eth_broadcast_addr(hdr->addr1);
	memcpy(hdr->addr2, src_addr, ETH_ALEN);
	eth_broadcast_addr(hdr->addr3);

	pos = skb_put(skb, ie_ssid_len);
	*pos++ = WLAN_EID_SSID;
	*pos++ = ssid_len;
	if (ssid_len)
		memcpy(pos, ssid, ssid_len);
	pos += ssid_len;

	return skb;
}
EXPORT_SYMBOL(ieee80211_probereq_get);

void ieee80211_rts_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, const void *frame, size_t frame_len, const struct ieee80211_tx_info *frame_txctl, struct ieee80211_rts *rts)


{
	const struct ieee80211_hdr *hdr = frame;

	rts->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_RTS);
	rts->duration = ieee80211_rts_duration(hw, vif, frame_len, frame_txctl);
	memcpy(rts->ra, hdr->addr1, sizeof(rts->ra));
	memcpy(rts->ta, hdr->addr2, sizeof(rts->ta));
}
EXPORT_SYMBOL(ieee80211_rts_get);

void ieee80211_ctstoself_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, const void *frame, size_t frame_len, const struct ieee80211_tx_info *frame_txctl, struct ieee80211_cts *cts)


{
	const struct ieee80211_hdr *hdr = frame;

	cts->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CTS);
	cts->duration = ieee80211_ctstoself_duration(hw, vif, frame_len, frame_txctl);
	memcpy(cts->ra, hdr->addr1, sizeof(cts->ra));
}
EXPORT_SYMBOL(ieee80211_ctstoself_get);

struct sk_buff * ieee80211_get_buffered_bc(struct ieee80211_hw *hw, struct ieee80211_vif *vif)

{
	struct ieee80211_local *local = hw_to_local(hw);
	struct sk_buff *skb = NULL;
	struct ieee80211_tx_data tx;
	struct ieee80211_sub_if_data *sdata;
	struct ps_data *ps;
	struct ieee80211_tx_info *info;
	struct ieee80211_chanctx_conf *chanctx_conf;

	sdata = vif_to_sdata(vif);

	rcu_read_lock();
	chanctx_conf = rcu_dereference(sdata->vif.chanctx_conf);

	if (!chanctx_conf)
		goto out;

	if (sdata->vif.type == NL80211_IFTYPE_AP) {
		struct beacon_data *beacon = rcu_dereference(sdata->u.ap.beacon);

		if (!beacon || !beacon->head)
			goto out;

		ps = &sdata->u.ap.ps;
	} else if (ieee80211_vif_is_mesh(&sdata->vif)) {
		ps = &sdata->u.mesh.ps;
	} else {
		goto out;
	}

	if (ps->dtim_count != 0 || !ps->dtim_bc_mc)
		goto out; 

	while (1) {
		skb = skb_dequeue(&ps->bc_buf);
		if (!skb)
			goto out;
		local->total_ps_buffered--;

		if (!skb_queue_empty(&ps->bc_buf) && skb->len >= 2) {
			struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
			
			hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		}

		if (sdata->vif.type == NL80211_IFTYPE_AP)
			sdata = IEEE80211_DEV_TO_SUB_IF(skb->dev);
		if (!ieee80211_tx_prepare(sdata, &tx, NULL, skb))
			break;
		ieee80211_free_txskb(hw, skb);
	}

	info = IEEE80211_SKB_CB(skb);

	tx.flags |= IEEE80211_TX_PS_BUFFERED;
	info->band = chanctx_conf->def.chan->band;

	if (invoke_tx_handlers(&tx))
		skb = NULL;
 out:
	rcu_read_unlock();

	return skb;
}
EXPORT_SYMBOL(ieee80211_get_buffered_bc);

int ieee80211_reserve_tid(struct ieee80211_sta *pubsta, u8 tid)
{
	struct sta_info *sta = container_of(pubsta, struct sta_info, sta);
	struct ieee80211_sub_if_data *sdata = sta->sdata;
	struct ieee80211_local *local = sdata->local;
	int ret;
	u32 queues;

	lockdep_assert_held(&local->sta_mtx);

	
	switch (sdata->vif.type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	if (WARN_ON(tid >= IEEE80211_NUM_UPS))
		return -EINVAL;

	if (sta->reserved_tid == tid) {
		ret = 0;
		goto out;
	}

	if (sta->reserved_tid != IEEE80211_TID_UNRESERVED) {
		sdata_err(sdata, "TID reservation already active\n");
		ret = -EALREADY;
		goto out;
	}

	ieee80211_stop_vif_queues(sdata->local, sdata, IEEE80211_QUEUE_STOP_REASON_RESERVE_TID);

	synchronize_net();

	
	if (ieee80211_hw_check(&local->hw, AMPDU_AGGREGATION)) {
		set_sta_flag(sta, WLAN_STA_BLOCK_BA);
		__ieee80211_stop_tx_ba_session(sta, tid, AGG_STOP_LOCAL_REQUEST);
	}

	queues = BIT(sdata->vif.hw_queue[ieee802_1d_to_ac[tid]]);
	__ieee80211_flush_queues(local, sdata, queues, false);

	sta->reserved_tid = tid;

	ieee80211_wake_vif_queues(local, sdata, IEEE80211_QUEUE_STOP_REASON_RESERVE_TID);

	if (ieee80211_hw_check(&local->hw, AMPDU_AGGREGATION))
		clear_sta_flag(sta, WLAN_STA_BLOCK_BA);

	ret = 0;
 out:
	return ret;
}
EXPORT_SYMBOL(ieee80211_reserve_tid);

void ieee80211_unreserve_tid(struct ieee80211_sta *pubsta, u8 tid)
{
	struct sta_info *sta = container_of(pubsta, struct sta_info, sta);
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	lockdep_assert_held(&sdata->local->sta_mtx);

	
	switch (sdata->vif.type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
		break;
	default:
		WARN_ON(1);
		return;
	}

	if (tid != sta->reserved_tid) {
		sdata_err(sdata, "TID to unreserve (%d) isn't reserved\n", tid);
		return;
	}

	sta->reserved_tid = IEEE80211_TID_UNRESERVED;
}
EXPORT_SYMBOL(ieee80211_unreserve_tid);

void __ieee80211_tx_skb_tid_band(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb, int tid, enum nl80211_band band)

{
	int ac = ieee80211_ac_from_tid(tid);

	skb_reset_mac_header(skb);
	skb_set_queue_mapping(skb, ac);
	skb->priority = tid;

	skb->dev = sdata->dev;

	
	local_bh_disable();
	IEEE80211_SKB_CB(skb)->band = band;
	ieee80211_xmit(sdata, NULL, skb);
	local_bh_enable();
}

int ieee80211_tx_control_port(struct wiphy *wiphy, struct net_device *dev, const u8 *buf, size_t len, const u8 *dest, __be16 proto, bool unencrypted, u64 *cookie)


{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct sta_info *sta;
	struct sk_buff *skb;
	struct ethhdr *ehdr;
	u32 ctrl_flags = 0;
	u32 flags = 0;

	
	if (proto != sdata->control_port_protocol && proto != cpu_to_be16(ETH_P_PREAUTH))
		return -EINVAL;

	if (proto == sdata->control_port_protocol)
		ctrl_flags |= IEEE80211_TX_CTRL_PORT_CTRL_PROTO | IEEE80211_TX_CTRL_SKIP_MPATH_LOOKUP;

	if (unencrypted)
		flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;

	if (cookie)
		ctrl_flags |= IEEE80211_TX_CTL_REQ_TX_STATUS;

	flags |= IEEE80211_TX_INTFL_NL80211_FRAME_TX;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(struct ethhdr) + len);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, local->hw.extra_tx_headroom + sizeof(struct ethhdr));

	skb_put_data(skb, buf, len);

	ehdr = skb_push(skb, sizeof(struct ethhdr));
	memcpy(ehdr->h_dest, dest, ETH_ALEN);
	memcpy(ehdr->h_source, sdata->vif.addr, ETH_ALEN);
	ehdr->h_proto = proto;

	skb->dev = dev;
	skb->protocol = proto;
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	
	rcu_read_lock();

	if (ieee80211_lookup_ra_sta(sdata, skb, &sta) == 0 && !IS_ERR(sta)) {
		u16 queue = __ieee80211_select_queue(sdata, sta, skb);

		skb_set_queue_mapping(skb, queue);
		skb_get_hash(skb);
	}

	rcu_read_unlock();

	
	mutex_lock(&local->mtx);

	local_bh_disable();
	__ieee80211_subif_start_xmit(skb, skb->dev, flags, ctrl_flags, cookie);
	local_bh_enable();

	mutex_unlock(&local->mtx);

	return 0;
}

int ieee80211_probe_mesh_link(struct wiphy *wiphy, struct net_device *dev, const u8 *buf, size_t len)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	struct sk_buff *skb;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + len + 30 + 18);

	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, local->hw.extra_tx_headroom);
	skb_put_data(skb, buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_802_3);
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	local_bh_disable();
	__ieee80211_subif_start_xmit(skb, skb->dev, 0, IEEE80211_TX_CTRL_SKIP_MPATH_LOOKUP, NULL);

	local_bh_enable();

	return 0;
}
