
































COVERAGE_DEFINE(flow_extract);
COVERAGE_DEFINE(miniflow_malloc);


const uint8_t flow_segment_u64s[4] = {
    FLOW_SEGMENT_1_ENDS_AT / sizeof(uint64_t), FLOW_SEGMENT_2_ENDS_AT / sizeof(uint64_t), FLOW_SEGMENT_3_ENDS_AT / sizeof(uint64_t), FLOW_U64S };




int flow_vlan_limit = FLOW_MAX_VLAN_HEADERS;















ASSERT_SEQUENTIAL_SAME_WORD(nw_frag, nw_tos);
ASSERT_SEQUENTIAL_SAME_WORD(nw_tos, nw_ttl);
ASSERT_SEQUENTIAL_SAME_WORD(nw_ttl, nw_proto);


BUILD_ASSERT_DECL(offsetof(struct flow, tcp_flags) % 8 == 4);







ASSERT_SEQUENTIAL_SAME_WORD(tp_src, tp_dst);


static inline const void * data_pull(const void **datap, size_t *sizep, size_t size)
{
    const char *data = *datap;
    *datap = data + size;
    *sizep -= size;
    return data;
}


static inline const void * data_try_pull(const void **datap, size_t *sizep, size_t size)
{
    return OVS_LIKELY(*sizep >= size) ? data_pull(datap, sizep, size) : NULL;
}


struct mf_ctx {
    struct flowmap map;
    uint64_t *data;
    uint64_t * const end;
};





BUILD_MESSAGE("FLOW_WC_SEQ changed: miniflow_extract() will have runtime " "assertions enabled. Consider updating FLOW_WC_SEQ after " "testing")
































































































































































static inline int parse_mpls(const void **datap, size_t *sizep)
{
    const struct mpls_hdr *mh;
    int count = 0;

    while ((mh = data_try_pull(datap, sizep, sizeof *mh))) {
        count++;
        if (mh->mpls_lse.lo & htons(1 << MPLS_BOS_SHIFT)) {
            break;
        }
    }
    return MIN(count, FLOW_MAX_MPLS_LABELS);
}


static inline ALWAYS_INLINE size_t parse_vlan(const void **datap, size_t *sizep, union flow_vlan_hdr *vlan_hdrs)
{
    const ovs_be16 *eth_type;

    data_pull(datap, sizep, ETH_ADDR_LEN * 2);

    eth_type = *datap;

    size_t n;
    for (n = 0; eth_type_vlan(*eth_type) && n < flow_vlan_limit; n++) {
        if (OVS_UNLIKELY(*sizep < sizeof(ovs_be32) + sizeof(ovs_be16))) {
            break;
        }

        memset(vlan_hdrs + n, 0, sizeof(union flow_vlan_hdr));
        const ovs_16aligned_be32 *qp = data_pull(datap, sizep, sizeof *qp);
        vlan_hdrs[n].qtag = get_16aligned_be32(qp);
        vlan_hdrs[n].tci |= htons(VLAN_CFI);
        eth_type = *datap;
    }
    return n;
}

static inline ALWAYS_INLINE ovs_be16 parse_ethertype(const void **datap, size_t *sizep)
{
    const struct llc_snap_header *llc;
    ovs_be16 proto;

    proto = *(ovs_be16 *) data_pull(datap, sizep, sizeof proto);
    if (OVS_LIKELY(ntohs(proto) >= ETH_TYPE_MIN)) {
        return proto;
    }

    if (OVS_UNLIKELY(*sizep < sizeof *llc)) {
        return htons(FLOW_DL_TYPE_NONE);
    }

    llc = *datap;
    if (OVS_UNLIKELY(llc->llc.llc_dsap != LLC_DSAP_SNAP || llc->llc.llc_ssap != LLC_SSAP_SNAP || llc->llc.llc_cntl != LLC_CNTL_SNAP || memcmp(llc->snap.snap_org, SNAP_ORG_ETHERNET, sizeof llc->snap.snap_org))) {



        return htons(FLOW_DL_TYPE_NONE);
    }

    data_pull(datap, sizep, sizeof *llc);

    if (OVS_LIKELY(ntohs(llc->snap.snap_type) >= ETH_TYPE_MIN)) {
        return llc->snap.snap_type;
    }

    return htons(FLOW_DL_TYPE_NONE);
}


static inline bool parse_icmpv6(const void **datap, size_t *sizep, const struct icmp6_data_header *icmp6, ovs_be32 *rso_flags, const struct in6_addr **nd_target, struct eth_addr arp_buf[2], uint8_t *opt_type)



{
    if (icmp6->icmp6_base.icmp6_code != 0 || (icmp6->icmp6_base.icmp6_type != ND_NEIGHBOR_SOLICIT && icmp6->icmp6_base.icmp6_type != ND_NEIGHBOR_ADVERT)) {

        return false;
    }

    arp_buf[0] = eth_addr_zero;
    arp_buf[1] = eth_addr_zero;
    *opt_type = 0;

    *rso_flags = get_16aligned_be32(icmp6->icmp6_data.be32);

    *nd_target = data_try_pull(datap, sizep, sizeof **nd_target);
    if (OVS_UNLIKELY(!*nd_target)) {
        return true;
    }

    while (*sizep >= 8) {
        
        const struct ovs_nd_lla_opt *lla_opt = *datap;
        int opt_len = lla_opt->len * ND_LLA_OPT_LEN;

        if (!opt_len || opt_len > *sizep) {
            return true;
        }

        
        if (lla_opt->type == ND_OPT_SOURCE_LINKADDR && opt_len == 8) {
            if (OVS_LIKELY(eth_addr_is_zero(arp_buf[0]))) {
                arp_buf[0] = lla_opt->mac;
                
                if (*opt_type == 0) {
                    *opt_type = lla_opt->type;
                }
            } else {
                goto invalid;
            }
        } else if (lla_opt->type == ND_OPT_TARGET_LINKADDR && opt_len == 8) {
            if (OVS_LIKELY(eth_addr_is_zero(arp_buf[1]))) {
                arp_buf[1] = lla_opt->mac;
                
                if (*opt_type == 0) {
                    *opt_type = lla_opt->type;
                }
            } else {
                goto invalid;
            }
        }

        if (OVS_UNLIKELY(!data_try_pull(datap, sizep, opt_len))) {
            return true;
        }
    }
    return true;

invalid:
    *nd_target = NULL;
    arp_buf[0] = eth_addr_zero;
    arp_buf[1] = eth_addr_zero;
    return true;
}

static inline bool parse_ipv6_ext_hdrs__(const void **datap, size_t *sizep, uint8_t *nw_proto, uint8_t *nw_frag, const struct ovs_16aligned_ip6_frag **frag_hdr)


{
    *frag_hdr = NULL;
    while (1) {
        if (OVS_LIKELY((*nw_proto != IPPROTO_HOPOPTS)
                       && (*nw_proto != IPPROTO_ROUTING)
                       && (*nw_proto != IPPROTO_DSTOPTS)
                       && (*nw_proto != IPPROTO_AH)
                       && (*nw_proto != IPPROTO_FRAGMENT))) {
            
            return true;
        }

        
        if (OVS_UNLIKELY(*sizep < 8)) {
            return false;
        }

        if ((*nw_proto == IPPROTO_HOPOPTS)
            || (*nw_proto == IPPROTO_ROUTING)
            || (*nw_proto == IPPROTO_DSTOPTS)) {
            
            const struct ip6_ext *ext_hdr = *datap;
            *nw_proto = ext_hdr->ip6e_nxt;
            if (OVS_UNLIKELY(!data_try_pull(datap, sizep, (ext_hdr->ip6e_len + 1) * 8))) {
                return false;
            }
        } else if (*nw_proto == IPPROTO_AH) {
            
            const struct ip6_ext *ext_hdr = *datap;
            *nw_proto = ext_hdr->ip6e_nxt;
            if (OVS_UNLIKELY(!data_try_pull(datap, sizep, (ext_hdr->ip6e_len + 2) * 4))) {
                return false;
            }
        } else if (*nw_proto == IPPROTO_FRAGMENT) {
            *frag_hdr = *datap;

            *nw_proto = (*frag_hdr)->ip6f_nxt;
            if (!data_try_pull(datap, sizep, sizeof **frag_hdr)) {
                return false;
            }

            
            if ((*frag_hdr)->ip6f_offlg != htons(0)) {
                *nw_frag = FLOW_NW_FRAG_ANY;
                if (((*frag_hdr)->ip6f_offlg & IP6F_OFF_MASK) != htons(0)) {
                    *nw_frag |= FLOW_NW_FRAG_LATER;
                    *nw_proto = IPPROTO_FRAGMENT;
                    return true;
                }
            }
        }
    }
}


bool parse_ipv6_ext_hdrs(const void **datap, size_t *sizep, uint8_t *nw_proto, uint8_t *nw_frag, const struct ovs_16aligned_ip6_frag **frag_hdr)


{
    return parse_ipv6_ext_hdrs__(datap, sizep, nw_proto, nw_frag, frag_hdr);
}

bool parse_nsh(const void **datap, size_t *sizep, struct ovs_key_nsh *key)
{
    const struct nsh_hdr *nsh = (const struct nsh_hdr *) *datap;
    uint8_t version, length, flags, ttl;

    
    if (OVS_UNLIKELY(*sizep < NSH_BASE_HDR_LEN)) {
        return false;
    }

    version = nsh_get_ver(nsh);
    flags = nsh_get_flags(nsh);
    length = nsh_hdr_len(nsh);
    ttl = nsh_get_ttl(nsh);

    if (OVS_UNLIKELY(length > *sizep || version != 0)) {
        return false;
    }

    key->flags = flags;
    key->ttl = ttl;
    key->mdtype = nsh->md_type;
    key->np = nsh->next_proto;
    key->path_hdr = nsh_get_path_hdr(nsh);

    switch (key->mdtype) {
        case NSH_M_TYPE1:
            if (length != NSH_M_TYPE1_LEN) {
                return false;
            }
            for (size_t i = 0; i < 4; i++) {
                key->context[i] = get_16aligned_be32(&nsh->md1.context[i]);
            }
            break;
        case NSH_M_TYPE2:
            
            if (length < NSH_BASE_HDR_LEN) {
                return false;
            }

            memset(key->context, 0, sizeof(key->context));
            break;
        default:
            
            memset(key->context, 0, sizeof(key->context));
            break;
    }

    data_pull(datap, sizep, length);

    return true;
}


void flow_extract(struct dp_packet *packet, struct flow *flow)
{
    struct {
        struct miniflow mf;
        uint64_t buf[FLOW_U64S];
    } m;

    COVERAGE_INC(flow_extract);

    miniflow_extract(packet, &m.mf);
    miniflow_expand(&m.mf, flow);
}

static inline bool ipv4_sanity_check(const struct ip_header *nh, size_t size, int *ip_lenp, uint16_t *tot_lenp)

{
    int ip_len;
    uint16_t tot_len;

    if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
        return false;
    }
    ip_len = IP_IHL(nh->ip_ihl_ver) * 4;

    if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN || size < ip_len)) {
        return false;
    }

    tot_len = ntohs(nh->ip_tot_len);
    if (OVS_UNLIKELY(tot_len > size || ip_len > tot_len || size - tot_len > UINT8_MAX)) {
        return false;
    }

    *ip_lenp = ip_len;
    *tot_lenp = tot_len;

    return true;
}

static inline uint8_t ipv4_get_nw_frag(const struct ip_header *nh)
{
    uint8_t nw_frag = 0;

    if (OVS_UNLIKELY(IP_IS_FRAGMENT(nh->ip_frag_off))) {
        nw_frag = FLOW_NW_FRAG_ANY;
        if (nh->ip_frag_off & htons(IP_FRAG_OFF_MASK)) {
            nw_frag |= FLOW_NW_FRAG_LATER;
        }
    }

    return nw_frag;
}

static inline bool ipv6_sanity_check(const struct ovs_16aligned_ip6_hdr *nh, size_t size)
{
    uint16_t plen;

    if (OVS_UNLIKELY(size < sizeof *nh)) {
        return false;
    }

    plen = ntohs(nh->ip6_plen);
    if (OVS_UNLIKELY(plen + IPV6_HEADER_LEN > size)) {
        return false;
    }
    
    if (OVS_UNLIKELY(size - (plen + IPV6_HEADER_LEN) > UINT8_MAX)) {
        return false;
    }

    return true;
}


void miniflow_extract(struct dp_packet *packet, struct miniflow *dst)
{
    
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    const struct pkt_metadata *md = &packet->md;
    const void *data = dp_packet_data(packet);
    size_t size = dp_packet_size(packet);
    ovs_be32 packet_type = packet->packet_type;
    uint64_t *values = miniflow_values(dst);
    struct mf_ctx mf = { FLOWMAP_EMPTY_INITIALIZER, values, values + FLOW_U64S };
    const char *frame;
    ovs_be16 dl_type = OVS_BE16_MAX;
    uint8_t nw_frag, nw_tos, nw_ttl, nw_proto;
    uint8_t *ct_nw_proto_p = NULL;
    ovs_be16 ct_tp_src = 0, ct_tp_dst = 0;

    
    if (flow_tnl_dst_is_set(&md->tunnel)) {
        miniflow_push_words(mf, tunnel, &md->tunnel, offsetof(struct flow_tnl, metadata) / sizeof(uint64_t));


        if (!(md->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (md->tunnel.metadata.present.map) {
                miniflow_push_words(mf, tunnel.metadata, &md->tunnel.metadata, sizeof md->tunnel.metadata / sizeof(uint64_t));

            }
        } else {
            if (md->tunnel.metadata.present.len) {
                miniflow_push_words(mf, tunnel.metadata.present, &md->tunnel.metadata.present, 1);
                miniflow_push_words(mf, tunnel.metadata.opts.gnv, md->tunnel.metadata.opts.gnv, DIV_ROUND_UP(md->tunnel.metadata.present.len, sizeof(uint64_t)));


            }
        }
    }
    if (md->skb_priority || md->pkt_mark) {
        miniflow_push_uint32(mf, skb_priority, md->skb_priority);
        miniflow_push_uint32(mf, pkt_mark, md->pkt_mark);
    }
    miniflow_push_uint32(mf, dp_hash, md->dp_hash);
    miniflow_push_uint32(mf, in_port, odp_to_u32(md->in_port.odp_port));
    if (md->ct_state) {
        miniflow_push_uint32(mf, recirc_id, md->recirc_id);
        miniflow_push_uint8(mf, ct_state, md->ct_state);
        ct_nw_proto_p = miniflow_pointer(mf, ct_nw_proto);
        miniflow_push_uint8(mf, ct_nw_proto, 0);
        miniflow_push_uint16(mf, ct_zone, md->ct_zone);
        miniflow_push_uint32(mf, ct_mark, md->ct_mark);
        miniflow_push_be32(mf, packet_type, packet_type);
        if (!ovs_u128_is_zero(md->ct_label)) {
            miniflow_push_words(mf, ct_label, &md->ct_label, sizeof md->ct_label / sizeof(uint64_t));
        }
    } else {
        if (md->recirc_id) {
            miniflow_push_uint32(mf, recirc_id, md->recirc_id);
            miniflow_pad_to_64(mf, recirc_id);
        }
        miniflow_pad_from_64(mf, packet_type);
        miniflow_push_be32(mf, packet_type, packet_type);
    }

    
    frame = data;
    dp_packet_reset_offsets(packet);

    if (packet_type == htonl(PT_ETH)) {
        
        if (OVS_UNLIKELY(size < sizeof(struct eth_header))) {
            goto out;
        } else {
            
            ASSERT_SEQUENTIAL(dl_dst, dl_src);
            miniflow_push_macs(mf, dl_dst, data);

            
            union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS];
            size_t num_vlans = parse_vlan(&data, &size, vlans);

            dl_type = parse_ethertype(&data, &size);
            miniflow_push_be16(mf, dl_type, dl_type);
            miniflow_pad_to_64(mf, dl_type);
            if (num_vlans > 0) {
                miniflow_push_words_32(mf, vlans, vlans, num_vlans);
            }

        }
    } else {
        
        dl_type = pt_ns_type_be(packet_type);
        miniflow_pad_from_64(mf, dl_type);
        miniflow_push_be16(mf, dl_type, dl_type);
        
        miniflow_pad_to_64(mf, dl_type);
    }

    
    if (OVS_UNLIKELY(eth_type_mpls(dl_type))) {
        int count;
        const void *mpls = data;

        packet->l2_5_ofs = (char *)data - frame;
        count = parse_mpls(&data, &size);
        miniflow_push_words_32(mf, mpls_lse, mpls, count);
    }

    
    packet->l3_ofs = (char *)data - frame;

    nw_frag = 0;
    if (OVS_LIKELY(dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh = data;
        int ip_len;
        uint16_t tot_len;

        if (OVS_UNLIKELY(!ipv4_sanity_check(nh, size, &ip_len, &tot_len))) {
            goto out;
        }
        dp_packet_set_l2_pad_size(packet, size - tot_len);
        size = tot_len;   

        
        miniflow_push_words(mf, nw_src, &nh->ip_src, 1);
        if (ct_nw_proto_p && !md->ct_orig_tuple_ipv6) {
            *ct_nw_proto_p = md->ct_orig_tuple.ipv4.ipv4_proto;
            if (*ct_nw_proto_p) {
                miniflow_push_words(mf, ct_nw_src, &md->ct_orig_tuple.ipv4.ipv4_src, 1);
                ct_tp_src = md->ct_orig_tuple.ipv4.src_port;
                ct_tp_dst = md->ct_orig_tuple.ipv4.dst_port;
            }
        }

        miniflow_push_be32(mf, ipv6_label, 0); 

        nw_tos = nh->ip_tos;
        nw_ttl = nh->ip_ttl;
        nw_proto = nh->ip_proto;
        nw_frag = ipv4_get_nw_frag(nh);
        data_pull(&data, &size, ip_len);
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *nh = data;
        ovs_be32 tc_flow;
        uint16_t plen;

        if (OVS_UNLIKELY(!ipv6_sanity_check(nh, size))) {
            goto out;
        }
        data_pull(&data, &size, sizeof *nh);

        plen = ntohs(nh->ip6_plen);
        dp_packet_set_l2_pad_size(packet, size - plen);
        size = plen;   

        miniflow_push_words(mf, ipv6_src, &nh->ip6_src, sizeof nh->ip6_src / 8);
        miniflow_push_words(mf, ipv6_dst, &nh->ip6_dst, sizeof nh->ip6_dst / 8);
        if (ct_nw_proto_p && md->ct_orig_tuple_ipv6) {
            *ct_nw_proto_p = md->ct_orig_tuple.ipv6.ipv6_proto;
            if (*ct_nw_proto_p) {
                miniflow_push_words(mf, ct_ipv6_src, &md->ct_orig_tuple.ipv6.ipv6_src, 2 * sizeof md->ct_orig_tuple.ipv6.ipv6_src / 8);


                ct_tp_src = md->ct_orig_tuple.ipv6.src_port;
                ct_tp_dst = md->ct_orig_tuple.ipv6.dst_port;
            }
        }

        tc_flow = get_16aligned_be32(&nh->ip6_flow);
        nw_tos = ntohl(tc_flow) >> 20;
        nw_ttl = nh->ip6_hlim;
        nw_proto = nh->ip6_nxt;

        const struct ovs_16aligned_ip6_frag *frag_hdr;
        if (!parse_ipv6_ext_hdrs__(&data, &size, &nw_proto, &nw_frag, &frag_hdr)) {
            goto out;
        }

        
        ASSERT_SEQUENTIAL(ipv6_label, nw_frag);
        ovs_be32 label = tc_flow & htonl(IPV6_LABEL_MASK);
        miniflow_push_be32(mf, ipv6_label, label);
    } else {
        if (dl_type == htons(ETH_TYPE_ARP) || dl_type == htons(ETH_TYPE_RARP)) {
            struct eth_addr arp_buf[2];
            const struct arp_eth_header *arp = (const struct arp_eth_header *)
                data_try_pull(&data, &size, ARP_ETH_HEADER_LEN);

            if (OVS_LIKELY(arp) && OVS_LIKELY(arp->ar_hrd == htons(1))
                && OVS_LIKELY(arp->ar_pro == htons(ETH_TYPE_IP))
                && OVS_LIKELY(arp->ar_hln == ETH_ADDR_LEN)
                && OVS_LIKELY(arp->ar_pln == 4)) {
                miniflow_push_be32(mf, nw_src, get_16aligned_be32(&arp->ar_spa));
                miniflow_push_be32(mf, nw_dst, get_16aligned_be32(&arp->ar_tpa));

                
                if (OVS_LIKELY(ntohs(arp->ar_op) <= 0xff)) {
                    miniflow_push_be32(mf, ipv6_label, 0); 
                    miniflow_push_be32(mf, nw_frag, htonl(ntohs(arp->ar_op)));
                }

                
                ASSERT_SEQUENTIAL(arp_sha, arp_tha);

                arp_buf[0] = arp->ar_sha;
                arp_buf[1] = arp->ar_tha;
                miniflow_push_macs(mf, arp_sha, arp_buf);
                miniflow_pad_to_64(mf, arp_tha);
            }
        } else if (dl_type == htons(ETH_TYPE_NSH)) {
            struct ovs_key_nsh nsh;

            if (OVS_LIKELY(parse_nsh(&data, &size, &nsh))) {
                miniflow_push_words(mf, nsh, &nsh, sizeof(struct ovs_key_nsh) / sizeof(uint64_t));

            }
        }
        goto out;
    }

    packet->l4_ofs = (char *)data - frame;
    miniflow_push_be32(mf, nw_frag, bytes_to_be32(nw_frag, nw_tos, nw_ttl, nw_proto));

    if (OVS_LIKELY(!(nw_frag & FLOW_NW_FRAG_LATER))) {
        if (OVS_LIKELY(nw_proto == IPPROTO_TCP)) {
            if (OVS_LIKELY(size >= TCP_HEADER_LEN)) {
                const struct tcp_header *tcp = data;

                miniflow_push_be32(mf, arp_tha.ea[2], 0);
                miniflow_push_be32(mf, tcp_flags, TCP_FLAGS_BE32(tcp->tcp_ctl));
                miniflow_push_be16(mf, tp_src, tcp->tcp_src);
                miniflow_push_be16(mf, tp_dst, tcp->tcp_dst);
                miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_UDP)) {
            if (OVS_LIKELY(size >= UDP_HEADER_LEN)) {
                const struct udp_header *udp = data;

                miniflow_push_be16(mf, tp_src, udp->udp_src);
                miniflow_push_be16(mf, tp_dst, udp->udp_dst);
                miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_SCTP)) {
            if (OVS_LIKELY(size >= SCTP_HEADER_LEN)) {
                const struct sctp_header *sctp = data;

                miniflow_push_be16(mf, tp_src, sctp->sctp_src);
                miniflow_push_be16(mf, tp_dst, sctp->sctp_dst);
                miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMP)) {
            if (OVS_LIKELY(size >= ICMP_HEADER_LEN)) {
                const struct icmp_header *icmp = data;

                miniflow_push_be16(mf, tp_src, htons(icmp->icmp_type));
                miniflow_push_be16(mf, tp_dst, htons(icmp->icmp_code));
                miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_IGMP)) {
            if (OVS_LIKELY(size >= IGMP_HEADER_LEN)) {
                const struct igmp_header *igmp = data;

                miniflow_push_be16(mf, tp_src, htons(igmp->igmp_type));
                miniflow_push_be16(mf, tp_dst, htons(igmp->igmp_code));
                miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
                miniflow_push_be32(mf, igmp_group_ip4, get_16aligned_be32(&igmp->group));
                miniflow_pad_to_64(mf, igmp_group_ip4);
            }
        } else if (OVS_LIKELY(nw_proto == IPPROTO_ICMPV6)) {
            if (OVS_LIKELY(size >= sizeof(struct icmp6_data_header))) {
                const struct in6_addr *nd_target;
                struct eth_addr arp_buf[2];
                
                uint8_t opt_type;
                
                ovs_be32 rso_flags;
                const struct icmp6_data_header *icmp6;

                icmp6 = data_pull(&data, &size, sizeof *icmp6);
                if (parse_icmpv6(&data, &size, icmp6, &rso_flags, &nd_target, arp_buf, &opt_type)) {
                    if (nd_target) {
                        miniflow_push_words(mf, nd_target, nd_target, sizeof *nd_target / sizeof(uint64_t));
                    }
                    miniflow_push_macs(mf, arp_sha, arp_buf);
                    
                    if (opt_type != 0) {
                        miniflow_push_be16(mf, tcp_flags, htons(opt_type));
                        
                        miniflow_pad_to_64(mf, tcp_flags);
                    } else {
                        
                        miniflow_pad_to_64(mf, arp_tha);
                    }
                    miniflow_push_be16(mf, tp_src, htons(icmp6->icmp6_base.icmp6_type));
                    miniflow_push_be16(mf, tp_dst, htons(icmp6->icmp6_base.icmp6_code));
                    miniflow_pad_to_64(mf, tp_dst);
                    
                    miniflow_push_be32(mf, igmp_group_ip4, rso_flags);
                    miniflow_pad_to_64(mf, igmp_group_ip4);
                } else {
                    
                    miniflow_push_be16(mf, tp_src, htons(icmp6->icmp6_base.icmp6_type));
                    miniflow_push_be16(mf, tp_dst, htons(icmp6->icmp6_base.icmp6_code));
                    miniflow_push_be16(mf, ct_tp_src, ct_tp_src);
                    miniflow_push_be16(mf, ct_tp_dst, ct_tp_dst);
                }
            }
        }
    }
 out:
    dst->map = mf.map;
}

static ovs_be16 parse_dl_type(const void **datap, size_t *sizep)
{
    union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS];

    parse_vlan(datap, sizep, vlans);

    return parse_ethertype(datap, sizep);
}


uint16_t parse_tcp_flags(struct dp_packet *packet)
{
    const void *data = dp_packet_data(packet);
    const char *frame = (const char *)data;
    size_t size = dp_packet_size(packet);
    ovs_be16 dl_type;
    uint8_t nw_frag = 0, nw_proto = 0;

    if (!dp_packet_is_eth(packet)) {
        return 0;
    }

    dp_packet_reset_offsets(packet);

    dl_type = parse_dl_type(&data, &size);
    if (OVS_UNLIKELY(eth_type_mpls(dl_type))) {
        packet->l2_5_ofs = (char *)data - frame;
    }
    packet->l3_ofs = (char *)data - frame;
    if (OVS_LIKELY(dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh = data;
        int ip_len;
        uint16_t tot_len;

        if (OVS_UNLIKELY(!ipv4_sanity_check(nh, size, &ip_len, &tot_len))) {
            return 0;
        }
        dp_packet_set_l2_pad_size(packet, size - tot_len);
        nw_proto = nh->ip_proto;
        nw_frag = ipv4_get_nw_frag(nh);

        size = tot_len;   
        data_pull(&data, &size, ip_len);
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *nh = data;
        uint16_t plen;

        if (OVS_UNLIKELY(!ipv6_sanity_check(nh, size))) {
            return 0;
        }
        data_pull(&data, &size, sizeof *nh);

        plen = ntohs(nh->ip6_plen); 
        dp_packet_set_l2_pad_size(packet, size - plen);
        size = plen;
        const struct ovs_16aligned_ip6_frag *frag_hdr;
        nw_proto = nh->ip6_nxt;
        if (!parse_ipv6_ext_hdrs__(&data, &size, &nw_proto, &nw_frag, &frag_hdr)) {
            return 0;
        }
    } else {
        return 0;
    }

    packet->l4_ofs = (uint16_t)((char *)data - frame);
    if (!(nw_frag & FLOW_NW_FRAG_LATER) && nw_proto == IPPROTO_TCP && size >= TCP_HEADER_LEN) {
        const struct tcp_header *tcp = data;

        return TCP_FLAGS(tcp->tcp_ctl);
    }

    return 0;
}


void flow_zero_wildcards(struct flow *flow, const struct flow_wildcards *wildcards)
{
    uint64_t *flow_u64 = (uint64_t *) flow;
    const uint64_t *wc_u64 = (const uint64_t *) &wildcards->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        flow_u64[i] &= wc_u64[i];
    }
}

void flow_unwildcard_tp_ports(const struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->nw_proto != IPPROTO_ICMP) {
        memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
        memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
    } else {
        wc->masks.tp_src = htons(0xff);
        wc->masks.tp_dst = htons(0xff);
    }
}


void flow_get_metadata(const struct flow *flow, struct match *flow_metadata)
{
    int i;

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    match_init_catchall(flow_metadata);
    if (flow->tunnel.tun_id != htonll(0)) {
        match_set_tun_id(flow_metadata, flow->tunnel.tun_id);
    }
    if (flow->tunnel.flags & FLOW_TNL_PUB_F_MASK) {
        match_set_tun_flags(flow_metadata, flow->tunnel.flags & FLOW_TNL_PUB_F_MASK);
    }
    if (flow->tunnel.ip_src) {
        match_set_tun_src(flow_metadata, flow->tunnel.ip_src);
    }
    if (flow->tunnel.ip_dst) {
        match_set_tun_dst(flow_metadata, flow->tunnel.ip_dst);
    }
    if (ipv6_addr_is_set(&flow->tunnel.ipv6_src)) {
        match_set_tun_ipv6_src(flow_metadata, &flow->tunnel.ipv6_src);
    }
    if (ipv6_addr_is_set(&flow->tunnel.ipv6_dst)) {
        match_set_tun_ipv6_dst(flow_metadata, &flow->tunnel.ipv6_dst);
    }
    if (flow->tunnel.gbp_id != htons(0)) {
        match_set_tun_gbp_id(flow_metadata, flow->tunnel.gbp_id);
    }
    if (flow->tunnel.gbp_flags) {
        match_set_tun_gbp_flags(flow_metadata, flow->tunnel.gbp_flags);
    }
    if (flow->tunnel.erspan_ver) {
        match_set_tun_erspan_ver(flow_metadata, flow->tunnel.erspan_ver);
    }
    if (flow->tunnel.erspan_idx) {
        match_set_tun_erspan_idx(flow_metadata, flow->tunnel.erspan_idx);
    }
    if (flow->tunnel.erspan_dir) {
        match_set_tun_erspan_dir(flow_metadata, flow->tunnel.erspan_dir);
    }
    if (flow->tunnel.erspan_hwid) {
        match_set_tun_erspan_hwid(flow_metadata, flow->tunnel.erspan_hwid);
    }
    if (flow->tunnel.gtpu_flags) {
        match_set_tun_gtpu_flags(flow_metadata, flow->tunnel.gtpu_flags);
    }
    if (flow->tunnel.gtpu_msgtype) {
        match_set_tun_gtpu_msgtype(flow_metadata, flow->tunnel.gtpu_msgtype);
    }
    tun_metadata_get_fmd(&flow->tunnel, flow_metadata);
    if (flow->metadata != htonll(0)) {
        match_set_metadata(flow_metadata, flow->metadata);
    }

    for (i = 0; i < FLOW_N_REGS; i++) {
        if (flow->regs[i]) {
            match_set_reg(flow_metadata, i, flow->regs[i]);
        }
    }

    if (flow->pkt_mark != 0) {
        match_set_pkt_mark(flow_metadata, flow->pkt_mark);
    }

    match_set_in_port(flow_metadata, flow->in_port.ofp_port);
    if (flow->packet_type != htonl(PT_ETH)) {
        match_set_packet_type(flow_metadata, flow->packet_type);
    }

    if (flow->ct_state != 0) {
        match_set_ct_state(flow_metadata, flow->ct_state);
        
        match_set_dl_type(flow_metadata, flow->dl_type);
        if (is_ct_valid(flow, NULL, NULL) && flow->ct_nw_proto != 0) {
            if (flow->dl_type == htons(ETH_TYPE_IP)) {
                match_set_ct_nw_src(flow_metadata, flow->ct_nw_src);
                match_set_ct_nw_dst(flow_metadata, flow->ct_nw_dst);
                match_set_ct_nw_proto(flow_metadata, flow->ct_nw_proto);
                match_set_ct_tp_src(flow_metadata, flow->ct_tp_src);
                match_set_ct_tp_dst(flow_metadata, flow->ct_tp_dst);
            } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
                match_set_ct_ipv6_src(flow_metadata, &flow->ct_ipv6_src);
                match_set_ct_ipv6_dst(flow_metadata, &flow->ct_ipv6_dst);
                match_set_ct_nw_proto(flow_metadata, flow->ct_nw_proto);
                match_set_ct_tp_src(flow_metadata, flow->ct_tp_src);
                match_set_ct_tp_dst(flow_metadata, flow->ct_tp_dst);
            }
        }
    }
    if (flow->ct_zone != 0) {
        match_set_ct_zone(flow_metadata, flow->ct_zone);
    }
    if (flow->ct_mark != 0) {
        match_set_ct_mark(flow_metadata, flow->ct_mark);
    }
    if (!ovs_u128_is_zero(flow->ct_label)) {
        match_set_ct_label(flow_metadata, flow->ct_label);
    }
}

const char * ct_state_to_string(uint32_t state)
{
    switch (state) {

        CS_STATES  default:

        return NULL;
    }
}

uint32_t ct_state_from_string(const char *s)
{



    CS_STATES  return 0;

}


bool parse_ct_state(const char *state_str, uint32_t default_state, uint32_t *ct_state, struct ds *ds)

{
    uint32_t state = default_state;
    char *state_s = xstrdup(state_str);
    char *save_ptr = NULL;

    for (char *cs = strtok_r(state_s, ", ", &save_ptr); cs;
         cs = strtok_r(NULL, ", ", &save_ptr)) {
        uint32_t bit = ct_state_from_string(cs);
        if (!bit) {
            ds_put_format(ds, "%s: unknown connection tracking state flag", cs);
            free(state_s);
            return false;
        }
        state |= bit;
    }

    *ct_state = state;
    free(state_s);

    return true;
}


bool validate_ct_state(uint32_t state, struct ds *ds)
{
    bool valid_ct_state = true;
    struct ds d_str = DS_EMPTY_INITIALIZER;

    format_flags(&d_str, ct_state_to_string, state, '|');

    if (state && !(state & CS_TRACKED)) {
        ds_put_format(ds, "%s: invalid connection state: " "If \"trk\" is unset, no other flags are set\n", ds_cstr(&d_str));

        valid_ct_state = false;
    }
    if (state & CS_INVALID && state & ~(CS_TRACKED | CS_INVALID)) {
        ds_put_format(ds, "%s: invalid connection state: " "when \"inv\" is set, only \"trk\" may also be set\n", ds_cstr(&d_str));

        valid_ct_state = false;
    }
    if (state & CS_NEW && state & CS_ESTABLISHED) {
        ds_put_format(ds, "%s: invalid connection state: " "\"new\" and \"est\" are mutually exclusive\n", ds_cstr(&d_str));

        valid_ct_state = false;
    }
    if (state & CS_NEW && state & CS_REPLY_DIR) {
        ds_put_format(ds, "%s: invalid connection state: " "\"new\" and \"rpy\" are mutually exclusive\n", ds_cstr(&d_str));

        valid_ct_state = false;
    }

    ds_destroy(&d_str);
    return valid_ct_state;
}


void flow_clear_conntrack(struct flow *flow)
{
    flow->ct_state = 0;
    flow->ct_zone = 0;
    flow->ct_mark = 0;
    flow->ct_label = OVS_U128_ZERO;

    flow->ct_nw_proto = 0;
    flow->ct_tp_src = 0;
    flow->ct_tp_dst = 0;
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        flow->ct_nw_src = 0;
        flow->ct_nw_dst = 0;
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        memset(&flow->ct_ipv6_src, 0, sizeof flow->ct_ipv6_src);
        memset(&flow->ct_ipv6_dst, 0, sizeof flow->ct_ipv6_dst);
    }
}

char * flow_to_string(const struct flow *flow, const struct ofputil_port_map *port_map)

{
    struct ds ds = DS_EMPTY_INITIALIZER;
    flow_format(&ds, flow, port_map);
    return ds_cstr(&ds);
}

const char * flow_tun_flag_to_string(uint32_t flags)
{
    switch (flags) {
    case FLOW_TNL_F_DONT_FRAGMENT:
        return "df";
    case FLOW_TNL_F_CSUM:
        return "csum";
    case FLOW_TNL_F_KEY:
        return "key";
    case FLOW_TNL_F_OAM:
        return "oam";
    default:
        return NULL;
    }
}

void format_flags(struct ds *ds, const char *(*bit_to_string)(uint32_t), uint32_t flags, char del)

{
    uint32_t bad = 0;

    if (!flags) {
        ds_put_char(ds, '0');
        return;
    }
    while (flags) {
        uint32_t bit = rightmost_1bit(flags);
        const char *s;

        s = bit_to_string(bit);
        if (s) {
            ds_put_format(ds, "%s%c", s, del);
        } else {
            bad |= bit;
        }

        flags &= ~bit;
    }

    if (bad) {
        ds_put_format(ds, "0x%"PRIx32"%c", bad, del);
    }
    ds_chomp(ds, del);
}

void format_flags_masked(struct ds *ds, const char *name, const char *(*bit_to_string)(uint32_t), uint32_t flags, uint32_t mask, uint32_t max_mask)


{
    if (name) {
        ds_put_format(ds, "%s%s=%s", colors.param, name, colors.end);
    }

    if (mask == max_mask) {
        format_flags(ds, bit_to_string, flags, '|');
        return;
    }

    if (!mask) {
        ds_put_cstr(ds, "0/0");
        return;
    }

    while (mask) {
        uint32_t bit = rightmost_1bit(mask);
        const char *s = bit_to_string(bit);

        ds_put_format(ds, "%s%s", (flags & bit) ? "+" : "-", s ? s : "[Unknown]");
        mask &= ~bit;
    }
}

static void put_u16_masked(struct ds *s, uint16_t value, uint16_t mask)
{
    if (!mask) {
        ds_put_char(s, '*');
    } else {
        if (value > 9) {
            ds_put_format(s, "0x%"PRIx16, value);
        } else {
            ds_put_format(s, "%"PRIu16, value);
        }

        if (mask != UINT16_MAX) {
            ds_put_format(s, "/0x%"PRIx16, mask);
        }
    }
}

void format_packet_type_masked(struct ds *s, ovs_be32 value, ovs_be32 mask)
{
    if (value == htonl(PT_ETH) && mask == OVS_BE32_MAX) {
        ds_put_cstr(s, "eth");
    } else {
        ds_put_cstr(s, "packet_type=(");
        put_u16_masked(s, pt_ns(value), pt_ns(mask));
        ds_put_char(s, ',');
        put_u16_masked(s, pt_ns_type(value), pt_ns_type(mask));
        ds_put_char(s, ')');
    }
}


int parse_flags(const char *s, const char *(*bit_to_string)(uint32_t), char end, const char *field_name, char **res_string, uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask)


{
    uint32_t result = 0;
    int n;

    
    if (res_mask && ovs_scan(s, "%"SCNi32"/%"SCNi32"%n", res_flags, res_mask, &n) && n > 0) {
        if (*res_flags & ~allowed || *res_mask & ~allowed) {
            goto unknown;
        }
        return n;
    }

    n = 0;

    if (res_mask && (*s == '+' || *s == '-')) {
        uint32_t flags = 0, mask = 0;

        
        while (s[0] != end) {
            bool set;
            uint32_t bit;
            size_t len;

            if (s[0] == '+') {
                set = true;
            } else if (s[0] == '-') {
                set = false;
            } else {
                if (res_string) {
                    *res_string = xasprintf("%s: %s must be preceded by '+' " "(for SET) or '-' (NOT SET)", s, field_name);

                }
                return -EINVAL;
            }
            s++;
            n++;

            for (bit = 1; bit; bit <<= 1) {
                const char *fname = bit_to_string(bit);

                if (!fname) {
                    continue;
                }

                len = strlen(fname);
                if (strncmp(s, fname, len) || (s[len] != '+' && s[len] != '-' && s[len] != end)) {
                    continue;
                }

                if (mask & bit) {
                    
                    if (res_string) {
                        *res_string = xasprintf("%s: Each %s flag can be " "specified only once", s, field_name);

                    }
                    return -EINVAL;
                }
                if (!(bit & allowed)) {
                    goto unknown;
                }
                if (set) {
                   flags |= bit;
                }
                mask |= bit;
                break;
            }

            if (!bit) {
                goto unknown;
            }
            s += len;
            n += len;
        }

        *res_flags = flags;
        *res_mask = mask;
        return n;
    }

    
    while (s[n] != end) {
        unsigned long long int flags;
        uint32_t bit;
        int n0;

        if (ovs_scan(&s[n], "%lli%n", &flags, &n0)) {
            if (flags & ~allowed) {
                goto unknown;
            }
            n += n0 + (s[n + n0] == '|');
            result |= flags;
            continue;
        }

        for (bit = 1; bit; bit <<= 1) {
            const char *name = bit_to_string(bit);
            size_t len;

            if (!name) {
                continue;
            }

            len = strlen(name);
            if (!strncmp(s + n, name, len) && (s[n + len] == '|' || s[n + len] == end)) {
                if (!(bit & allowed)) {
                    goto unknown;
                }
                result |= bit;
                n += len + (s[n + len] == '|');
                break;
            }
        }

        if (!bit) {
            goto unknown;
        }
    }

    *res_flags = result;
    if (res_mask) {
        *res_mask = UINT32_MAX;
    }
    if (res_string) {
        *res_string = NULL;
    }
    return n;

unknown:
    if (res_string) {
        *res_string = xasprintf("%s: unknown %s flag(s)", s, field_name);
    }
    return -EINVAL;
}

void flow_format(struct ds *ds, const struct flow *flow, const struct ofputil_port_map *port_map)

{
    struct match match;
    struct flow_wildcards *wc = &match.wc;

    match_wc_init(&match, flow);

    
    if (!flow->in_port.ofp_port) {
        WC_UNMASK_FIELD(wc, in_port);
    }
    if (!flow->skb_priority) {
        WC_UNMASK_FIELD(wc, skb_priority);
    }
    if (!flow->pkt_mark) {
        WC_UNMASK_FIELD(wc, pkt_mark);
    }
    if (!flow->recirc_id) {
        WC_UNMASK_FIELD(wc, recirc_id);
    }
    if (!flow->dp_hash) {
        WC_UNMASK_FIELD(wc, dp_hash);
    }
    if (!flow->ct_state) {
        WC_UNMASK_FIELD(wc, ct_state);
    }
    if (!flow->ct_zone) {
        WC_UNMASK_FIELD(wc, ct_zone);
    }
    if (!flow->ct_mark) {
        WC_UNMASK_FIELD(wc, ct_mark);
    }
    if (ovs_u128_is_zero(flow->ct_label)) {
        WC_UNMASK_FIELD(wc, ct_label);
    }
    if (!is_ct_valid(flow, &match.wc, NULL) || !flow->ct_nw_proto) {
        WC_UNMASK_FIELD(wc, ct_nw_proto);
        WC_UNMASK_FIELD(wc, ct_tp_src);
        WC_UNMASK_FIELD(wc, ct_tp_dst);
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            WC_UNMASK_FIELD(wc, ct_nw_src);
            WC_UNMASK_FIELD(wc, ct_nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            WC_UNMASK_FIELD(wc, ct_ipv6_src);
            WC_UNMASK_FIELD(wc, ct_ipv6_dst);
        }
    }
    for (int i = 0; i < FLOW_N_REGS; i++) {
        if (!flow->regs[i]) {
            WC_UNMASK_FIELD(wc, regs[i]);
        }
    }
    if (!flow->metadata) {
        WC_UNMASK_FIELD(wc, metadata);
    }

    match_format(&match, port_map, ds, OFP_DEFAULT_PRIORITY);
}

void flow_print(FILE *stream, const struct flow *flow, const struct ofputil_port_map *port_map)

{
    char *s = flow_to_string(flow, port_map);
    fputs(s, stream);
    free(s);
}




void flow_wildcards_init_catchall(struct flow_wildcards *wc)
{
    memset(&wc->masks, 0, sizeof wc->masks);
}


void flow_wildcards_init_for_packet(struct flow_wildcards *wc, const struct flow *flow)

{
    ovs_be16 dl_type = OVS_BE16_MAX;

    memset(&wc->masks, 0x0, sizeof wc->masks);

    
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    if (flow_tnl_dst_is_set(&flow->tunnel)) {
        if (flow->tunnel.flags & FLOW_TNL_F_KEY) {
            WC_MASK_FIELD(wc, tunnel.tun_id);
        }
        WC_MASK_FIELD(wc, tunnel.ip_src);
        WC_MASK_FIELD(wc, tunnel.ip_dst);
        WC_MASK_FIELD(wc, tunnel.ipv6_src);
        WC_MASK_FIELD(wc, tunnel.ipv6_dst);
        WC_MASK_FIELD(wc, tunnel.flags);
        WC_MASK_FIELD(wc, tunnel.ip_tos);
        WC_MASK_FIELD(wc, tunnel.ip_ttl);
        WC_MASK_FIELD(wc, tunnel.tp_src);
        WC_MASK_FIELD(wc, tunnel.tp_dst);
        WC_MASK_FIELD(wc, tunnel.gbp_id);
        WC_MASK_FIELD(wc, tunnel.gbp_flags);
        WC_MASK_FIELD(wc, tunnel.erspan_ver);
        WC_MASK_FIELD(wc, tunnel.erspan_idx);
        WC_MASK_FIELD(wc, tunnel.erspan_dir);
        WC_MASK_FIELD(wc, tunnel.erspan_hwid);
        WC_MASK_FIELD(wc, tunnel.gtpu_flags);
        WC_MASK_FIELD(wc, tunnel.gtpu_msgtype);

        if (!(flow->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (flow->tunnel.metadata.present.map) {
                wc->masks.tunnel.metadata.present.map = flow->tunnel.metadata.present.map;
                WC_MASK_FIELD(wc, tunnel.metadata.opts.u8);
                WC_MASK_FIELD(wc, tunnel.metadata.tab);
            }
        } else {
            WC_MASK_FIELD(wc, tunnel.metadata.present.len);
            memset(wc->masks.tunnel.metadata.opts.gnv, 0xff, flow->tunnel.metadata.present.len);
        }
    } else if (flow->tunnel.tun_id) {
        WC_MASK_FIELD(wc, tunnel.tun_id);
    }

    

    WC_MASK_FIELD(wc, skb_priority);
    WC_MASK_FIELD(wc, pkt_mark);
    WC_MASK_FIELD(wc, ct_state);
    WC_MASK_FIELD(wc, ct_zone);
    WC_MASK_FIELD(wc, ct_mark);
    WC_MASK_FIELD(wc, ct_label);
    WC_MASK_FIELD(wc, recirc_id);
    WC_MASK_FIELD(wc, dp_hash);
    WC_MASK_FIELD(wc, in_port);

    

    WC_MASK_FIELD(wc, packet_type);
    if (flow->packet_type == htonl(PT_ETH)) {
        WC_MASK_FIELD(wc, dl_dst);
        WC_MASK_FIELD(wc, dl_src);
        WC_MASK_FIELD(wc, dl_type);
        
        for (int i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
            
            WC_MASK_FIELD(wc, vlans[i]);
            if (flow->vlans[i].tci == htons(0)) {
                break;
            }
        }
        dl_type = flow->dl_type;
    } else {
        dl_type = pt_ns_type_be(flow->packet_type);
    }

    if (dl_type == htons(ETH_TYPE_IP)) {
        WC_MASK_FIELD(wc, nw_src);
        WC_MASK_FIELD(wc, nw_dst);
        WC_MASK_FIELD(wc, ct_nw_src);
        WC_MASK_FIELD(wc, ct_nw_dst);
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        WC_MASK_FIELD(wc, ipv6_src);
        WC_MASK_FIELD(wc, ipv6_dst);
        WC_MASK_FIELD(wc, ipv6_label);
        if (is_nd(flow, wc)) {
            WC_MASK_FIELD(wc, arp_sha);
            WC_MASK_FIELD(wc, arp_tha);
            WC_MASK_FIELD(wc, nd_target);
        } else {
            WC_MASK_FIELD(wc, ct_ipv6_src);
            WC_MASK_FIELD(wc, ct_ipv6_dst);
        }
    } else if (dl_type == htons(ETH_TYPE_ARP) || dl_type == htons(ETH_TYPE_RARP)) {
        WC_MASK_FIELD(wc, nw_src);
        WC_MASK_FIELD(wc, nw_dst);
        WC_MASK_FIELD(wc, nw_proto);
        WC_MASK_FIELD(wc, arp_sha);
        WC_MASK_FIELD(wc, arp_tha);
        return;
    } else if (eth_type_mpls(dl_type)) {
        for (int i = 0; i < FLOW_MAX_MPLS_LABELS; i++) {
            WC_MASK_FIELD(wc, mpls_lse[i]);
            if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                break;
            }
        }
        return;
    } else if (flow->dl_type == htons(ETH_TYPE_NSH)) {
        WC_MASK_FIELD(wc, nsh.flags);
        WC_MASK_FIELD(wc, nsh.ttl);
        WC_MASK_FIELD(wc, nsh.mdtype);
        WC_MASK_FIELD(wc, nsh.np);
        WC_MASK_FIELD(wc, nsh.path_hdr);
        WC_MASK_FIELD(wc, nsh.context);
    } else {
        return; 
    }

    
    WC_MASK_FIELD(wc, nw_frag);
    WC_MASK_FIELD(wc, nw_tos);
    WC_MASK_FIELD(wc, nw_ttl);
    WC_MASK_FIELD(wc, nw_proto);
    WC_MASK_FIELD(wc, ct_nw_proto);
    WC_MASK_FIELD(wc, ct_tp_src);
    WC_MASK_FIELD(wc, ct_tp_dst);

    
    if (!(flow->nw_frag & FLOW_NW_FRAG_LATER) && (flow->nw_proto == IPPROTO_ICMP || flow->nw_proto == IPPROTO_ICMPV6 || flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_UDP || flow->nw_proto == IPPROTO_SCTP || flow->nw_proto == IPPROTO_IGMP)) {





        WC_MASK_FIELD(wc, tp_src);
        WC_MASK_FIELD(wc, tp_dst);

        if (flow->nw_proto == IPPROTO_TCP) {
            WC_MASK_FIELD(wc, tcp_flags);
        } else if (flow->nw_proto == IPPROTO_IGMP) {
            WC_MASK_FIELD(wc, igmp_group_ip4);
        }
    }
}


void flow_wc_map(const struct flow *flow, struct flowmap *map)
{
    
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    flowmap_init(map);

    if (flow_tnl_dst_is_set(&flow->tunnel)) {
        FLOWMAP_SET__(map, tunnel, offsetof(struct flow_tnl, metadata));
        if (!(flow->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (flow->tunnel.metadata.present.map) {
                FLOWMAP_SET(map, tunnel.metadata);
            }
        } else {
            FLOWMAP_SET(map, tunnel.metadata.present.len);
            FLOWMAP_SET__(map, tunnel.metadata.opts.gnv, flow->tunnel.metadata.present.len);
        }
    }

    
    FLOWMAP_SET(map, skb_priority);
    FLOWMAP_SET(map, pkt_mark);
    FLOWMAP_SET(map, recirc_id);
    FLOWMAP_SET(map, dp_hash);
    FLOWMAP_SET(map, in_port);
    FLOWMAP_SET(map, dl_dst);
    FLOWMAP_SET(map, dl_src);
    FLOWMAP_SET(map, dl_type);
    FLOWMAP_SET(map, vlans);
    FLOWMAP_SET(map, ct_state);
    FLOWMAP_SET(map, ct_zone);
    FLOWMAP_SET(map, ct_mark);
    FLOWMAP_SET(map, ct_label);
    FLOWMAP_SET(map, packet_type);

    
    if (OVS_LIKELY(flow->dl_type == htons(ETH_TYPE_IP))) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);
        FLOWMAP_SET(map, tp_src);
        FLOWMAP_SET(map, tp_dst);
        FLOWMAP_SET(map, ct_nw_proto);
        FLOWMAP_SET(map, ct_nw_src);
        FLOWMAP_SET(map, ct_nw_dst);
        FLOWMAP_SET(map, ct_tp_src);
        FLOWMAP_SET(map, ct_tp_dst);

        if (OVS_UNLIKELY(flow->nw_proto == IPPROTO_IGMP)) {
            FLOWMAP_SET(map, igmp_group_ip4);
        } else {
            FLOWMAP_SET(map, tcp_flags);
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        FLOWMAP_SET(map, ipv6_src);
        FLOWMAP_SET(map, ipv6_dst);
        FLOWMAP_SET(map, ipv6_label);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);
        FLOWMAP_SET(map, tp_src);
        FLOWMAP_SET(map, tp_dst);

        if (OVS_UNLIKELY(is_nd(flow, NULL))) {
            FLOWMAP_SET(map, nd_target);
            FLOWMAP_SET(map, arp_sha);
            FLOWMAP_SET(map, arp_tha);
            FLOWMAP_SET(map, tcp_flags);
            FLOWMAP_SET(map, igmp_group_ip4);
        } else {
            FLOWMAP_SET(map, ct_nw_proto);
            FLOWMAP_SET(map, ct_ipv6_src);
            FLOWMAP_SET(map, ct_ipv6_dst);
            FLOWMAP_SET(map, ct_tp_src);
            FLOWMAP_SET(map, ct_tp_dst);
            FLOWMAP_SET(map, tcp_flags);
        }
    } else if (eth_type_mpls(flow->dl_type)) {
        FLOWMAP_SET(map, mpls_lse);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) || flow->dl_type == htons(ETH_TYPE_RARP)) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, arp_sha);
        FLOWMAP_SET(map, arp_tha);
    } else if (flow->dl_type == htons(ETH_TYPE_NSH)) {
        FLOWMAP_SET(map, nsh.flags);
        FLOWMAP_SET(map, nsh.mdtype);
        FLOWMAP_SET(map, nsh.np);
        FLOWMAP_SET(map, nsh.path_hdr);
        FLOWMAP_SET(map, nsh.context);
    }
}


void flow_wildcards_clear_non_packet_fields(struct flow_wildcards *wc)
{
    
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    memset(&wc->masks.metadata, 0, sizeof wc->masks.metadata);
    memset(&wc->masks.regs, 0, sizeof wc->masks.regs);
    wc->masks.actset_output = 0;
    wc->masks.conj_id = 0;
}


bool flow_wildcards_is_catchall(const struct flow_wildcards *wc)
{
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if (wc_u64[i]) {
            return false;
        }
    }
    return true;
}


void flow_wildcards_and(struct flow_wildcards *dst, const struct flow_wildcards *src1, const struct flow_wildcards *src2)


{
    uint64_t *dst_u64 = (uint64_t *) &dst->masks;
    const uint64_t *src1_u64 = (const uint64_t *) &src1->masks;
    const uint64_t *src2_u64 = (const uint64_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        dst_u64[i] = src1_u64[i] & src2_u64[i];
    }
}


void flow_wildcards_or(struct flow_wildcards *dst, const struct flow_wildcards *src1, const struct flow_wildcards *src2)


{
    uint64_t *dst_u64 = (uint64_t *) &dst->masks;
    const uint64_t *src1_u64 = (const uint64_t *) &src1->masks;
    const uint64_t *src2_u64 = (const uint64_t *) &src2->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        dst_u64[i] = src1_u64[i] | src2_u64[i];
    }
}


uint32_t flow_wildcards_hash(const struct flow_wildcards *wc, uint32_t basis)
{
    return flow_hash(&wc->masks, basis);
}


bool flow_wildcards_equal(const struct flow_wildcards *a, const struct flow_wildcards *b)

{
    return flow_equal(&a->masks, &b->masks);
}


bool flow_wildcards_has_extra(const struct flow_wildcards *a, const struct flow_wildcards *b)

{
    const uint64_t *a_u64 = (const uint64_t *) &a->masks;
    const uint64_t *b_u64 = (const uint64_t *) &b->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if ((a_u64[i] & b_u64[i]) != b_u64[i]) {
            return true;
        }
    }
    return false;
}


bool flow_equal_except(const struct flow *a, const struct flow *b, const struct flow_wildcards *wc)

{
    const uint64_t *a_u64 = (const uint64_t *) a;
    const uint64_t *b_u64 = (const uint64_t *) b;
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    size_t i;

    for (i = 0; i < FLOW_U64S; i++) {
        if ((a_u64[i] ^ b_u64[i]) & wc_u64[i]) {
            return false;
        }
    }
    return true;
}


void flow_wildcards_set_reg_mask(struct flow_wildcards *wc, int idx, uint32_t mask)
{
    wc->masks.regs[idx] = mask;
}


void flow_wildcards_set_xreg_mask(struct flow_wildcards *wc, int idx, uint64_t mask)
{
    flow_set_xreg(&wc->masks, idx, mask);
}


void flow_wildcards_set_xxreg_mask(struct flow_wildcards *wc, int idx, ovs_u128 mask)

{
    flow_set_xxreg(&wc->masks, idx, mask);
}


uint32_t miniflow_hash_5tuple(const struct miniflow *flow, uint32_t basis)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);
    uint32_t hash = basis;

    if (flow) {
        ovs_be16 dl_type = MINIFLOW_GET_BE16(flow, dl_type);
        uint8_t nw_proto;

        if (dl_type == htons(ETH_TYPE_IPV6)) {
            struct flowmap map = FLOWMAP_EMPTY_INITIALIZER;
            uint64_t value;

            FLOWMAP_SET(&map, ipv6_src);
            FLOWMAP_SET(&map, ipv6_dst);

            MINIFLOW_FOR_EACH_IN_FLOWMAP(value, flow, map) {
                hash = hash_add64(hash, value);
            }
        } else if (dl_type == htons(ETH_TYPE_IP)
                   || dl_type == htons(ETH_TYPE_ARP)) {
            hash = hash_add(hash, MINIFLOW_GET_U32(flow, nw_src));
            hash = hash_add(hash, MINIFLOW_GET_U32(flow, nw_dst));
        } else {
            goto out;
        }

        nw_proto = MINIFLOW_GET_U8(flow, nw_proto);
        hash = hash_add(hash, nw_proto);
        if (nw_proto != IPPROTO_TCP && nw_proto != IPPROTO_UDP && nw_proto != IPPROTO_SCTP && nw_proto != IPPROTO_ICMP && nw_proto != IPPROTO_ICMPV6) {

            goto out;
        }

        
        hash = hash_add(hash, (OVS_FORCE uint32_t) miniflow_get_ports(flow));
    }
out:
    return hash_finish(hash, 42);
}

ASSERT_SEQUENTIAL_SAME_WORD(tp_src, tp_dst);
ASSERT_SEQUENTIAL(ipv6_src, ipv6_dst);


uint32_t flow_hash_5tuple(const struct flow *flow, uint32_t basis)
{
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);
    uint32_t hash = basis;

    if (flow) {

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            const uint64_t *flow_u64 = (const uint64_t *)flow;
            int ofs = offsetof(struct flow, ipv6_src) / 8;
            int end = ofs + 2 * sizeof flow->ipv6_src / 8;

            for (;ofs < end; ofs++) {
                hash = hash_add64(hash, flow_u64[ofs]);
            }
        } else if (flow->dl_type == htons(ETH_TYPE_IP)
                   || flow->dl_type == htons(ETH_TYPE_ARP)) {
            hash = hash_add(hash, (OVS_FORCE uint32_t) flow->nw_src);
            hash = hash_add(hash, (OVS_FORCE uint32_t) flow->nw_dst);
        } else {
            goto out;
        }

        hash = hash_add(hash, flow->nw_proto);
        if (flow->nw_proto != IPPROTO_TCP && flow->nw_proto != IPPROTO_UDP && flow->nw_proto != IPPROTO_SCTP && flow->nw_proto != IPPROTO_ICMP && flow->nw_proto != IPPROTO_ICMPV6) {

            goto out;
        }

        
        hash = hash_add(hash, ((const uint32_t *)flow)[offsetof(struct flow, tp_src)
                                                 / sizeof(uint32_t)]);
    }
out:
    return hash_finish(hash, 42); 
}


uint32_t flow_hash_symmetric_l4(const struct flow *flow, uint32_t basis)
{
    struct {
        union {
            ovs_be32 ipv4_addr;
            struct in6_addr ipv6_addr;
        };
        ovs_be16 eth_type;
        ovs_be16 vlan_tci;
        ovs_be16 tp_port;
        struct eth_addr eth_addr;
        uint8_t ip_proto;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    for (i = 0; i < ARRAY_SIZE(fields.eth_addr.be16); i++) {
        fields.eth_addr.be16[i] = flow->dl_src.be16[i] ^ flow->dl_dst.be16[i];
    }
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        fields.vlan_tci ^= flow->vlans[i].tci & htons(VLAN_VID_MASK);
    }
    fields.eth_type = flow->dl_type;

    
    if (fields.eth_type == htons(ETH_TYPE_IP)) {
        fields.ipv4_addr = flow->nw_src ^ flow->nw_dst;
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP || fields.ip_proto == IPPROTO_SCTP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    } else if (fields.eth_type == htons(ETH_TYPE_IPV6)) {
        const uint8_t *a = &flow->ipv6_src.s6_addr[0];
        const uint8_t *b = &flow->ipv6_dst.s6_addr[0];
        uint8_t *ipv6_addr = &fields.ipv6_addr.s6_addr[0];

        for (i=0; i<16; i++) {
            ipv6_addr[i] = a[i] ^ b[i];
        }
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IPPROTO_TCP || fields.ip_proto == IPPROTO_SCTP) {
            fields.tp_port = flow->tp_src ^ flow->tp_dst;
        }
    }
    return jhash_bytes(&fields, sizeof fields, basis);
}


uint32_t flow_hash_symmetric_l2(const struct flow *flow, uint32_t basis)
{
    union {
        struct {
            ovs_be16 eth_type;
            ovs_be16 vlan_tci;
            struct eth_addr eth_addr;
            ovs_be16 pad;
        };
        uint32_t word[3];
    } fields;

    uint32_t hash = basis;
    int i;

    if (flow->packet_type != htonl(PT_ETH)) {
        
        return 0;
    }

    for (i = 0; i < ARRAY_SIZE(fields.eth_addr.be16); i++) {
        fields.eth_addr.be16[i] = flow->dl_src.be16[i] ^ flow->dl_dst.be16[i];
    }
    fields.vlan_tci = 0;
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        fields.vlan_tci ^= flow->vlans[i].tci & htons(VLAN_VID_MASK);
    }
    fields.eth_type = flow->dl_type;
    fields.pad = 0;

    hash = hash_add(hash, fields.word[0]);
    hash = hash_add(hash, fields.word[1]);
    hash = hash_add(hash, fields.word[2]);
    return hash_finish(hash, basis);
}


uint32_t flow_hash_symmetric_l3l4(const struct flow *flow, uint32_t basis, bool inc_udp_ports)

{
    uint32_t hash = basis;

    
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        hash = hash_add(hash, (OVS_FORCE uint32_t) (flow->nw_src ^ flow->nw_dst));
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        
        const uint64_t *a = ALIGNED_CAST(uint64_t *, flow->ipv6_src.s6_addr);
        const uint64_t *b = ALIGNED_CAST(uint64_t *, flow->ipv6_dst.s6_addr);

        for (int i = 0; i < sizeof flow->ipv6_src / sizeof *a; i++) {
            hash = hash_add64(hash, a[i] ^ b[i]);
        }
    } else {
        
        return flow_hash_symmetric_l2(flow, basis);
    }
    hash = hash_add(hash, flow->nw_proto);
    if (!(flow->nw_frag & FLOW_NW_FRAG_MASK)
        && (flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_SCTP || (inc_udp_ports && flow->nw_proto == IPPROTO_UDP))) {
        hash = hash_add(hash, (OVS_FORCE uint16_t) (flow->tp_src ^ flow->tp_dst));
    }

    return hash_finish(hash, basis);
}


uint32_t flow_hash_symmetric_l3(const struct flow *flow, uint32_t basis)
{
    struct {
        union {
            ovs_be32 ipv4_addr;
            struct in6_addr ipv6_addr;
        };
        ovs_be16 eth_type;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    fields.eth_type = flow->dl_type;

    if (fields.eth_type == htons(ETH_TYPE_IP)) {
        fields.ipv4_addr = flow->nw_src ^ flow->nw_dst;
    } else if (fields.eth_type == htons(ETH_TYPE_IPV6)) {
        const uint8_t *a = &flow->ipv6_src.s6_addr[0];
        const uint8_t *b = &flow->ipv6_dst.s6_addr[0];
        uint8_t *ipv6_addr = &fields.ipv6_addr.s6_addr[0];

        for (i = 0; i < 16; i++) {
            ipv6_addr[i] = a[i] ^ b[i];
        }
    }
    return jhash_bytes(&fields, sizeof fields, basis);
}


void flow_random_hash_fields(struct flow *flow)
{
    uint16_t rnd = random_uint16();
    int i;

    
    memset(flow, 0, sizeof *flow);

    eth_addr_random(&flow->dl_src);
    eth_addr_random(&flow->dl_dst);

    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        uint16_t vlan = random_uint16() & VLAN_VID_MASK;
        flow->vlans[i].tpid = htons(ETH_TYPE_VLAN_8021Q);
        flow->vlans[i].tci = htons(vlan | VLAN_CFI);
    }

    
    flow->dl_type = rnd < 0x8000 ? htons(ETH_TYPE_IP) :
        rnd < 0xc000 ? htons(ETH_TYPE_IPV6) : (OVS_FORCE ovs_be16)rnd;

    if (dl_type_is_ip_any(flow->dl_type)) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            flow->nw_src = (OVS_FORCE ovs_be32)random_uint32();
            flow->nw_dst = (OVS_FORCE ovs_be32)random_uint32();
        } else {
            random_bytes(&flow->ipv6_src, sizeof flow->ipv6_src);
            random_bytes(&flow->ipv6_dst, sizeof flow->ipv6_dst);
        }
        
        rnd = random_uint16();
        flow->nw_proto = rnd < 0x8000 ? IPPROTO_TCP :
            rnd < 0xc000 ? IPPROTO_UDP :
            rnd < 0xd000 ? IPPROTO_SCTP : (uint8_t)rnd;
        if (flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_UDP || flow->nw_proto == IPPROTO_SCTP) {

            flow->tp_src = (OVS_FORCE ovs_be16)random_uint16();
            flow->tp_dst = (OVS_FORCE ovs_be16)random_uint16();
        }
    }
}


void flow_mask_hash_fields(const struct flow *flow, struct flow_wildcards *wc, enum nx_hash_fields fields)

{
    int i;
    switch (fields) {
    case NX_HASH_FIELDS_ETH_SRC:
        memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
        break;

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        memset(&wc->masks.dl_src, 0xff, sizeof wc->masks.dl_src);
        memset(&wc->masks.dl_dst, 0xff, sizeof wc->masks.dl_dst);
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        }
        if (is_ip_any(flow)) {
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
            
            if (flow->nw_proto != IPPROTO_UDP) {
                flow_unwildcard_tp_ports(flow, wc);
            }
        }
        for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
            wc->masks.vlans[i].tci |= htons(VLAN_VID_MASK | VLAN_CFI);
        }
        break;
    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP:
        if (is_ip_any(flow) && flow->nw_proto == IPPROTO_UDP && !(flow->nw_frag & FLOW_NW_FRAG_MASK)) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        
    case NX_HASH_FIELDS_SYMMETRIC_L3L4:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        } else {
            break; 
        }
        memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
        if ((flow->nw_proto == IPPROTO_TCP || flow->nw_proto == IPPROTO_SCTP)
             && !(flow->nw_frag & FLOW_NW_FRAG_MASK)) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        break;

    case NX_HASH_FIELDS_NW_SRC:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
        }
        break;

    case NX_HASH_FIELDS_NW_DST:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        }
        break;

    case NX_HASH_FIELDS_SYMMETRIC_L3:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
            memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            memset(&wc->masks.ipv6_src, 0xff, sizeof wc->masks.ipv6_src);
            memset(&wc->masks.ipv6_dst, 0xff, sizeof wc->masks.ipv6_dst);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
}


uint32_t flow_hash_fields(const struct flow *flow, enum nx_hash_fields fields, uint16_t basis)

{
    switch (fields) {

    case NX_HASH_FIELDS_ETH_SRC:
        return jhash_bytes(&flow->dl_src, sizeof flow->dl_src, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L4:
        return flow_hash_symmetric_l4(flow, basis);

    case NX_HASH_FIELDS_SYMMETRIC_L3L4:
        return flow_hash_symmetric_l3l4(flow, basis, false);

    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP:
        return flow_hash_symmetric_l3l4(flow, basis, true);

    case NX_HASH_FIELDS_NW_SRC:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            return jhash_bytes(&flow->nw_src, sizeof flow->nw_src, basis);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            return jhash_bytes(&flow->ipv6_src, sizeof flow->ipv6_src, basis);
        } else {
            return basis;
        }

    case NX_HASH_FIELDS_NW_DST:
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            return jhash_bytes(&flow->nw_dst, sizeof flow->nw_dst, basis);
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            return jhash_bytes(&flow->ipv6_dst, sizeof flow->ipv6_dst, basis);
        } else {
            return basis;
        }

    case NX_HASH_FIELDS_SYMMETRIC_L3:
        return flow_hash_symmetric_l3(flow, basis);
    }

    OVS_NOT_REACHED();
}


const char * flow_hash_fields_to_str(enum nx_hash_fields fields)
{
    switch (fields) {
    case NX_HASH_FIELDS_ETH_SRC: return "eth_src";
    case NX_HASH_FIELDS_SYMMETRIC_L4: return "symmetric_l4";
    case NX_HASH_FIELDS_SYMMETRIC_L3L4: return "symmetric_l3l4";
    case NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP: return "symmetric_l3l4+udp";
    case NX_HASH_FIELDS_NW_SRC: return "nw_src";
    case NX_HASH_FIELDS_NW_DST: return "nw_dst";
    case NX_HASH_FIELDS_SYMMETRIC_L3: return "symmetric_l3";
    default: return "<unknown>";
    }
}


bool flow_hash_fields_valid(enum nx_hash_fields fields)
{
    return fields == NX_HASH_FIELDS_ETH_SRC || fields == NX_HASH_FIELDS_SYMMETRIC_L4 || fields == NX_HASH_FIELDS_SYMMETRIC_L3L4 || fields == NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP || fields == NX_HASH_FIELDS_NW_SRC || fields == NX_HASH_FIELDS_NW_DST || fields == NX_HASH_FIELDS_SYMMETRIC_L3;





}


uint32_t flow_hash_in_wildcards(const struct flow *flow, const struct flow_wildcards *wc, uint32_t basis)

{
    const uint64_t *wc_u64 = (const uint64_t *) &wc->masks;
    const uint64_t *flow_u64 = (const uint64_t *) flow;
    uint32_t hash;
    size_t i;

    hash = basis;
    for (i = 0; i < FLOW_U64S; i++) {
        hash = hash_add64(hash, flow_u64[i] & wc_u64[i]);
    }
    return hash_finish(hash, 8 * FLOW_U64S);
}


void flow_set_dl_vlan(struct flow *flow, ovs_be16 vid, int id)
{
    if (vid == htons(OFP10_VLAN_NONE)) {
        flow->vlans[id].tci = htons(0);
    } else {
        vid &= htons(VLAN_VID_MASK);
        flow->vlans[id].tci &= ~htons(VLAN_VID_MASK);
        flow->vlans[id].tci |= htons(VLAN_CFI) | vid;
    }
}


void flow_fix_vlan_tpid(struct flow *flow)
{
    if (flow->vlans[0].tpid == htons(0) && flow->vlans[0].tci != 0) {
        flow->vlans[0].tpid = htons(ETH_TYPE_VLAN_8021Q);
    }
}


void flow_set_vlan_vid(struct flow *flow, ovs_be16 vid)
{
    ovs_be16 mask = htons(VLAN_VID_MASK | VLAN_CFI);
    flow->vlans[0].tci &= ~mask;
    flow->vlans[0].tci |= vid & mask;
}


void flow_set_vlan_pcp(struct flow *flow, uint8_t pcp, int id)
{
    pcp &= 0x07;
    flow->vlans[id].tci &= ~htons(VLAN_PCP_MASK);
    flow->vlans[id].tci |= htons((pcp << VLAN_PCP_SHIFT) | VLAN_CFI);
}


int flow_count_vlan_headers(const struct flow *flow)
{
    int i;

    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        if (!(flow->vlans[i].tci & htons(VLAN_CFI))) {
            break;
        }
    }
    return i;
}


void flow_skip_common_vlan_headers(const struct flow *a, int *p_an, const struct flow *b, int *p_bn)

{
    int an = *p_an, bn = *p_bn;

    for (an--, bn--; an >= 0 && bn >= 0; an--, bn--) {
        if (a->vlans[an].qtag != b->vlans[bn].qtag) {
            break;
        }
    }
    *p_an = an;
    *p_bn = bn;
}

void flow_pop_vlan(struct flow *flow, struct flow_wildcards *wc)
{
    int n = flow_count_vlan_headers(flow);
    if (n > 1) {
        if (wc) {
            memset(&wc->masks.vlans[1], 0xff, sizeof(union flow_vlan_hdr) * (n - 1));
        }
        memmove(&flow->vlans[0], &flow->vlans[1], sizeof(union flow_vlan_hdr) * (n - 1));
    }
    if (n > 0) {
        memset(&flow->vlans[n - 1], 0, sizeof(union flow_vlan_hdr));
    }
}

void flow_push_vlan_uninit(struct flow *flow, struct flow_wildcards *wc)
{
    if (wc) {
        int n = flow_count_vlan_headers(flow);
        if (n) {
            memset(wc->masks.vlans, 0xff, sizeof(union flow_vlan_hdr) * n);
        }
    }
    memmove(&flow->vlans[1], &flow->vlans[0], sizeof(union flow_vlan_hdr) * (FLOW_MAX_VLAN_HEADERS - 1));
    memset(&flow->vlans[0], 0, sizeof(union flow_vlan_hdr));
}


int flow_count_mpls_labels(const struct flow *flow, struct flow_wildcards *wc)
{
    
    if (eth_type_mpls(flow->dl_type)) {
        int i;
        int cnt;

        cnt = 0;
        for (i = 0; i < FLOW_MAX_MPLS_LABELS; i++) {
            if (wc) {
                wc->masks.mpls_lse[i] |= htonl(MPLS_BOS_MASK);
            }
            if (flow->mpls_lse[i] & htonl(MPLS_BOS_MASK)) {
                return i + 1;
            }
            if (flow->mpls_lse[i]) {
                cnt++;
            }
        }
        return cnt;
    } else {
        return 0;
    }
}


int flow_count_common_mpls_labels(const struct flow *a, int an, const struct flow *b, int bn, struct flow_wildcards *wc)


{
    int min_n = MIN(an, bn);
    if (min_n == 0) {
        return 0;
    } else {
        int common_n = 0;
        int a_last = an - 1;
        int b_last = bn - 1;
        int i;

        for (i = 0; i < min_n; i++) {
            if (wc) {
                wc->masks.mpls_lse[a_last - i] = OVS_BE32_MAX;
                wc->masks.mpls_lse[b_last - i] = OVS_BE32_MAX;
            }
            if (a->mpls_lse[a_last - i] != b->mpls_lse[b_last - i]) {
                break;
            } else {
                common_n++;
            }
        }

        return common_n;
    }
}


void flow_push_mpls(struct flow *flow, int n, ovs_be16 mpls_eth_type, struct flow_wildcards *wc, bool clear_flow_L3)

{
    ovs_assert(eth_type_mpls(mpls_eth_type));
    ovs_assert(n < FLOW_MAX_MPLS_LABELS);

    if (n) {
        int i;

        if (wc) {
            memset(&wc->masks.mpls_lse, 0xff, sizeof *wc->masks.mpls_lse * n);
        }
        for (i = n; i >= 1; i--) {
            flow->mpls_lse[i] = flow->mpls_lse[i - 1];
        }
        flow->mpls_lse[0] = (flow->mpls_lse[1] & htonl(~MPLS_BOS_MASK));
    } else {
        int label = 0;          
        int tc = 0;
        int ttl = 64;

        if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            label = 2;
        }

        if (is_ip_any(flow)) {
            tc = (flow->nw_tos & IP_DSCP_MASK) >> 2;
            if (wc) {
                wc->masks.nw_tos |= IP_DSCP_MASK;
                wc->masks.nw_ttl = 0xff;
            }

            if (flow->nw_ttl) {
                ttl = flow->nw_ttl;
            }
        }

        flow->mpls_lse[0] = set_mpls_lse_values(ttl, tc, 1, htonl(label));

        if (clear_flow_L3) {
            
            BUILD_ASSERT(FLOW_WC_SEQ == 42);
            memset((char *) flow + FLOW_SEGMENT_2_ENDS_AT, 0, sizeof(struct flow) - FLOW_SEGMENT_2_ENDS_AT);
            flow->dp_hash = 0;
        }
    }
    flow->dl_type = mpls_eth_type;
}


bool flow_pop_mpls(struct flow *flow, int n, ovs_be16 eth_type, struct flow_wildcards *wc)

{
    int i;

    if (n == 0) {
        
        return false;
    } else if (n == FLOW_MAX_MPLS_LABELS) {
        if (wc) {
            wc->masks.mpls_lse[n - 1] |= htonl(MPLS_BOS_MASK);
        }
        if (!(flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK))) {
            
            return false;
        }
    }

    if (wc) {
        memset(&wc->masks.mpls_lse[1], 0xff, sizeof *wc->masks.mpls_lse * (n - 1));
    }
    for (i = 1; i < n; i++) {
        flow->mpls_lse[i - 1] = flow->mpls_lse[i];
    }
    flow->mpls_lse[n - 1] = 0;
    flow->dl_type = eth_type;
    return true;
}


void flow_set_mpls_label(struct flow *flow, int idx, ovs_be32 label)
{
    set_mpls_lse_label(&flow->mpls_lse[idx], label);
}


void flow_set_mpls_ttl(struct flow *flow, int idx, uint8_t ttl)
{
    set_mpls_lse_ttl(&flow->mpls_lse[idx], ttl);
}


void flow_set_mpls_tc(struct flow *flow, int idx, uint8_t tc)
{
    set_mpls_lse_tc(&flow->mpls_lse[idx], tc);
}


void flow_set_mpls_bos(struct flow *flow, int idx, uint8_t bos)
{
    set_mpls_lse_bos(&flow->mpls_lse[idx], bos);
}


void flow_set_mpls_lse(struct flow *flow, int idx, ovs_be32 lse)
{
    flow->mpls_lse[idx] = lse;
}

static void flow_compose_l7(struct dp_packet *p, const void *l7, size_t l7_len)
{
    if (l7_len) {
        if (l7) {
            dp_packet_put(p, l7, l7_len);
        } else {
            uint8_t *payload = dp_packet_put_uninit(p, l7_len);
            for (size_t i = 0; i < l7_len; i++) {
                payload[i] = i;
            }
        }
    }
}

static size_t flow_compose_l4(struct dp_packet *p, const struct flow *flow, const void *l7, size_t l7_len)

{
    size_t orig_len = dp_packet_size(p);

    if (!(flow->nw_frag & FLOW_NW_FRAG_ANY)
        || !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            struct tcp_header *tcp = dp_packet_put_zeros(p, sizeof *tcp);
            tcp->tcp_src = flow->tp_src;
            tcp->tcp_dst = flow->tp_dst;
            tcp->tcp_ctl = TCP_CTL(ntohs(flow->tcp_flags), 5);
            if (!(flow->tcp_flags & htons(TCP_SYN | TCP_FIN | TCP_RST))) {
                flow_compose_l7(p, l7, l7_len);
            }
        } else if (flow->nw_proto == IPPROTO_UDP) {
            struct udp_header *udp = dp_packet_put_zeros(p, sizeof *udp);
            udp->udp_src = flow->tp_src;
            udp->udp_dst = flow->tp_dst;
            udp->udp_len = htons(sizeof *udp + l7_len);
            flow_compose_l7(p, l7, l7_len);
        } else if (flow->nw_proto == IPPROTO_SCTP) {
            struct sctp_header *sctp = dp_packet_put_zeros(p, sizeof *sctp);
            sctp->sctp_src = flow->tp_src;
            sctp->sctp_dst = flow->tp_dst;
            
        } else if (flow->nw_proto == IPPROTO_ICMP) {
            struct icmp_header *icmp = dp_packet_put_zeros(p, sizeof *icmp);
            icmp->icmp_type = ntohs(flow->tp_src);
            icmp->icmp_code = ntohs(flow->tp_dst);
            if ((icmp->icmp_type == ICMP4_ECHO_REQUEST || icmp->icmp_type == ICMP4_ECHO_REPLY)
                && icmp->icmp_code == 0) {
                flow_compose_l7(p, l7, l7_len);
            } else {
                
            }
        } else if (flow->nw_proto == IPPROTO_IGMP) {
            struct igmp_header *igmp = dp_packet_put_zeros(p, sizeof *igmp);
            igmp->igmp_type = ntohs(flow->tp_src);
            igmp->igmp_code = ntohs(flow->tp_dst);
            put_16aligned_be32(&igmp->group, flow->igmp_group_ip4);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            struct icmp6_data_header *icmp6;

            icmp6 = dp_packet_put_zeros(p, sizeof *icmp6);
            icmp6->icmp6_base.icmp6_type = ntohs(flow->tp_src);
            icmp6->icmp6_base.icmp6_code = ntohs(flow->tp_dst);
            put_16aligned_be32(icmp6->icmp6_data.be32, flow->igmp_group_ip4);

            if (icmp6->icmp6_base.icmp6_code == 0 && (icmp6->icmp6_base.icmp6_type == ND_NEIGHBOR_SOLICIT || icmp6->icmp6_base.icmp6_type == ND_NEIGHBOR_ADVERT)) {

                struct in6_addr *nd_target;
                struct ovs_nd_lla_opt *lla_opt;

                nd_target = dp_packet_put_zeros(p, sizeof *nd_target);
                *nd_target = flow->nd_target;

                if (!eth_addr_is_zero(flow->arp_sha)) {
                    lla_opt = dp_packet_put_zeros(p, 8);
                    lla_opt->len = 1;
                    lla_opt->type = ND_OPT_SOURCE_LINKADDR;
                    lla_opt->mac = flow->arp_sha;
                }
                if (!eth_addr_is_zero(flow->arp_tha)) {
                    lla_opt = dp_packet_put_zeros(p, 8);
                    lla_opt->len = 1;
                    lla_opt->type = ND_OPT_TARGET_LINKADDR;
                    lla_opt->mac = flow->arp_tha;
                }
            } else if (icmp6->icmp6_base.icmp6_code == 0 && (icmp6->icmp6_base.icmp6_type == ICMP6_ECHO_REQUEST || icmp6->icmp6_base.icmp6_type == ICMP6_ECHO_REPLY)) {

                flow_compose_l7(p, l7, l7_len);
            } else {
                
            }
        }
    }

    return dp_packet_size(p) - orig_len;
}

static void flow_compose_l4_csum(struct dp_packet *p, const struct flow *flow, uint32_t pseudo_hdr_csum)

{
    size_t l4_len = (char *) dp_packet_tail(p) - (char *) dp_packet_l4(p);

    if (!(flow->nw_frag & FLOW_NW_FRAG_ANY)
        || !(flow->nw_frag & FLOW_NW_FRAG_LATER)) {
        if (flow->nw_proto == IPPROTO_TCP) {
            struct tcp_header *tcp = dp_packet_l4(p);

            tcp->tcp_csum = 0;
            tcp->tcp_csum = csum_finish(csum_continue(pseudo_hdr_csum, tcp, l4_len));
        } else if (flow->nw_proto == IPPROTO_UDP) {
            struct udp_header *udp = dp_packet_l4(p);

            udp->udp_csum = 0;
            udp->udp_csum = csum_finish(csum_continue(pseudo_hdr_csum, udp, l4_len));
            if (!udp->udp_csum) {
                udp->udp_csum = htons(0xffff);
            }
        } else if (flow->nw_proto == IPPROTO_ICMP) {
            struct icmp_header *icmp = dp_packet_l4(p);

            icmp->icmp_csum = 0;
            icmp->icmp_csum = csum(icmp, l4_len);
        } else if (flow->nw_proto == IPPROTO_IGMP) {
            struct igmp_header *igmp = dp_packet_l4(p);

            igmp->igmp_csum = 0;
            igmp->igmp_csum = csum(igmp, l4_len);
        } else if (flow->nw_proto == IPPROTO_ICMPV6) {
            struct icmp6_data_header *icmp6 = dp_packet_l4(p);

            icmp6->icmp6_base.icmp6_cksum = 0;
            icmp6->icmp6_base.icmp6_cksum = csum_finish(csum_continue(pseudo_hdr_csum, icmp6, l4_len));
        }
    }
}


void packet_expand(struct dp_packet *p, const struct flow *flow, size_t size)
{
    size_t extra_size;

    ovs_assert(size > dp_packet_size(p));

    extra_size = size - dp_packet_size(p);
    dp_packet_put_zeros(p, extra_size);

    if (flow->dl_type == htons(FLOW_DL_TYPE_NONE)) {
        struct eth_header *eth = dp_packet_eth(p);

        eth->eth_type = htons(dp_packet_size(p));
    } else if (dl_type_is_ip_any(flow->dl_type)) {
        uint32_t pseudo_hdr_csum;
        size_t l4_len = (char *) dp_packet_tail(p) - (char *) dp_packet_l4(p);

        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            struct ip_header *ip = dp_packet_l3(p);

            ip->ip_tot_len = htons(p->l4_ofs - p->l3_ofs + l4_len);
            ip->ip_csum = 0;
            ip->ip_csum = csum(ip, sizeof *ip);

            pseudo_hdr_csum = packet_csum_pseudoheader(ip);
        } else { 
            struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(p);

            nh->ip6_plen = htons(l4_len);
            pseudo_hdr_csum = packet_csum_pseudoheader6(nh);
        }

        if ((!(flow->nw_frag & FLOW_NW_FRAG_ANY)
             || !(flow->nw_frag & FLOW_NW_FRAG_LATER))
            && flow->nw_proto == IPPROTO_UDP) {
            struct udp_header *udp = dp_packet_l4(p);

            udp->udp_len = htons(l4_len + extra_size);
        }
        flow_compose_l4_csum(p, flow, pseudo_hdr_csum);
    }
}


void flow_compose(struct dp_packet *p, const struct flow *flow, const void *l7, size_t l7_len)

{
    
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    uint32_t pseudo_hdr_csum;
    size_t l4_len;

    
    eth_compose(p, flow->dl_dst, flow->dl_src, ntohs(flow->dl_type), 0);
    if (flow->dl_type == htons(FLOW_DL_TYPE_NONE)) {
        struct eth_header *eth = dp_packet_eth(p);
        eth->eth_type = htons(dp_packet_size(p));
        return;
    }

    for (int encaps = FLOW_MAX_VLAN_HEADERS - 1; encaps >= 0; encaps--) {
        if (flow->vlans[encaps].tci & htons(VLAN_CFI)) {
            eth_push_vlan(p, flow->vlans[encaps].tpid, flow->vlans[encaps].tci);
        }
    }

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct ip_header *ip;

        ip = dp_packet_put_zeros(p, sizeof *ip);
        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip->ip_tos = flow->nw_tos;
        ip->ip_ttl = flow->nw_ttl;
        ip->ip_proto = flow->nw_proto;
        put_16aligned_be32(&ip->ip_src, flow->nw_src);
        put_16aligned_be32(&ip->ip_dst, flow->nw_dst);

        if (flow->nw_frag & FLOW_NW_FRAG_ANY) {
            ip->ip_frag_off |= htons(IP_MORE_FRAGMENTS);
            if (flow->nw_frag & FLOW_NW_FRAG_LATER) {
                ip->ip_frag_off |= htons(100);
            }
        }

        dp_packet_set_l4(p, dp_packet_tail(p));

        l4_len = flow_compose_l4(p, flow, l7, l7_len);

        ip = dp_packet_l3(p);
        ip->ip_tot_len = htons(p->l4_ofs - p->l3_ofs + l4_len);
        
        ip->ip_csum = csum(ip, sizeof *ip);

        pseudo_hdr_csum = packet_csum_pseudoheader(ip);
        flow_compose_l4_csum(p, flow, pseudo_hdr_csum);
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        struct ovs_16aligned_ip6_hdr *nh;

        nh = dp_packet_put_zeros(p, sizeof *nh);
        put_16aligned_be32(&nh->ip6_flow, htonl(6 << 28) | htonl(flow->nw_tos << 20) | flow->ipv6_label);
        nh->ip6_hlim = flow->nw_ttl;
        nh->ip6_nxt = flow->nw_proto;

        memcpy(&nh->ip6_src, &flow->ipv6_src, sizeof(nh->ip6_src));
        memcpy(&nh->ip6_dst, &flow->ipv6_dst, sizeof(nh->ip6_dst));

        dp_packet_set_l4(p, dp_packet_tail(p));

        l4_len = flow_compose_l4(p, flow, l7, l7_len);

        nh = dp_packet_l3(p);
        nh->ip6_plen = htons(l4_len);

        pseudo_hdr_csum = packet_csum_pseudoheader6(nh);
        flow_compose_l4_csum(p, flow, pseudo_hdr_csum);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) || flow->dl_type == htons(ETH_TYPE_RARP)) {
        struct arp_eth_header *arp;

        arp = dp_packet_put_zeros(p, sizeof *arp);
        dp_packet_set_l3(p, arp);
        arp->ar_hrd = htons(1);
        arp->ar_pro = htons(ETH_TYPE_IP);
        arp->ar_hln = ETH_ADDR_LEN;
        arp->ar_pln = 4;
        arp->ar_op = htons(flow->nw_proto);

        if (flow->nw_proto == ARP_OP_REQUEST || flow->nw_proto == ARP_OP_REPLY) {
            put_16aligned_be32(&arp->ar_spa, flow->nw_src);
            put_16aligned_be32(&arp->ar_tpa, flow->nw_dst);
            arp->ar_sha = flow->arp_sha;
            arp->ar_tha = flow->arp_tha;
        }
    }

    if (eth_type_mpls(flow->dl_type)) {
        int n;

        p->l2_5_ofs = p->l3_ofs;
        for (n = 1; n < FLOW_MAX_MPLS_LABELS; n++) {
            if (flow->mpls_lse[n - 1] & htonl(MPLS_BOS_MASK)) {
                break;
            }
        }
        while (n > 0) {
            push_mpls(p, flow->dl_type, flow->mpls_lse[--n]);
        }
    }
}




void miniflow_init(struct miniflow *dst, const struct flow *src)
{
    uint64_t *dst_u64 = miniflow_values(dst);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, dst->map) {
        *dst_u64++ = flow_u64_value(src, idx);
    }
}


void miniflow_map_init(struct miniflow *flow, const struct flow *src)
{
    
    flowmap_init(&flow->map);
    for (size_t i = 0; i < FLOW_U64S; i++) {
        if (flow_u64_value(src, i)) {
            flowmap_set(&flow->map, i, 1);
        }
    }
}


size_t miniflow_alloc(struct miniflow *dsts[], size_t n, const struct miniflow *src)
{
    size_t n_values = miniflow_n_values(src);
    size_t data_size = MINIFLOW_VALUES_SIZE(n_values);
    struct miniflow *dst = xmalloc(n * (sizeof *src + data_size));
    size_t i;

    COVERAGE_INC(miniflow_malloc);

    for (i = 0; i < n; i++) {
        *dst = *src;   
        dsts[i] = dst;
        dst += 1;      
        dst = (struct miniflow *)((uint64_t *)dst + n_values); 
    }
    return data_size;
}


struct miniflow * miniflow_create(const struct flow *src)
{
    struct miniflow tmp;
    struct miniflow *dst;

    miniflow_map_init(&tmp, src);

    miniflow_alloc(&dst, 1, &tmp);
    miniflow_init(dst, src);
    return dst;
}


void miniflow_clone(struct miniflow *dst, const struct miniflow *src, size_t n_values)

{
    *dst = *src;   
    memcpy(miniflow_values(dst), miniflow_get_values(src), MINIFLOW_VALUES_SIZE(n_values));
}


void miniflow_expand(const struct miniflow *src, struct flow *dst)
{
    memset(dst, 0, sizeof *dst);
    flow_union_with_miniflow(dst, src);
}


bool miniflow_equal(const struct miniflow *a, const struct miniflow *b)
{
    const uint64_t *ap = miniflow_get_values(a);
    const uint64_t *bp = miniflow_get_values(b);

    
    if (OVS_LIKELY(flowmap_equal(a->map, b->map))) {
        return !memcmp(ap, bp, miniflow_n_values(a) * sizeof *ap);
    } else {
        size_t idx;

        FLOWMAP_FOR_EACH_INDEX (idx, flowmap_or(a->map, b->map)) {
            if ((flowmap_is_set(&a->map, idx) ? *ap++ : 0)
                != (flowmap_is_set(&b->map, idx) ? *bp++ : 0)) {
                return false;
            }
        }
    }

    return true;
}


bool miniflow_equal_in_minimask(const struct miniflow *a, const struct miniflow *b, const struct minimask *mask)

{
    const uint64_t *p = miniflow_get_values(&mask->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        if ((miniflow_get(a, idx) ^ miniflow_get(b, idx)) & *p++) {
            return false;
        }
    }

    return true;
}


bool miniflow_equal_flow_in_minimask(const struct miniflow *a, const struct flow *b, const struct minimask *mask)

{
    const uint64_t *p = miniflow_get_values(&mask->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, mask->masks.map) {
        if ((miniflow_get(a, idx) ^ flow_u64_value(b, idx)) & *p++) {
            return false;
        }
    }

    return true;
}


void minimask_init(struct minimask *mask, const struct flow_wildcards *wc)
{
    miniflow_init(&mask->masks, &wc->masks);
}


struct minimask * minimask_create(const struct flow_wildcards *wc)
{
    return (struct minimask *)miniflow_create(&wc->masks);
}


void minimask_combine(struct minimask *dst_, const struct minimask *a_, const struct minimask *b_, uint64_t storage[FLOW_U64S])


{
    struct miniflow *dst = &dst_->masks;
    uint64_t *dst_values = storage;
    const struct miniflow *a = &a_->masks;
    const struct miniflow *b = &b_->masks;
    size_t idx;

    flowmap_init(&dst->map);

    FLOWMAP_FOR_EACH_INDEX(idx, flowmap_and(a->map, b->map)) {
        
        uint64_t mask = *miniflow_get__(a, idx) & *miniflow_get__(b, idx);

        if (mask) {
            flowmap_set(&dst->map, idx, 1);
            *dst_values++ = mask;
        }
    }
}


void minimask_expand(const struct minimask *mask, struct flow_wildcards *wc)
{
    miniflow_expand(&mask->masks, &wc->masks);
}


bool minimask_equal(const struct minimask *a, const struct minimask *b)
{
    
    return (!memcmp(a, b, sizeof *a)
            && !memcmp(a + 1, b + 1, MINIFLOW_VALUES_SIZE(miniflow_n_values(&a->masks))));
}


bool minimask_has_extra(const struct minimask *a, const struct minimask *b)
{
    const uint64_t *bp = miniflow_get_values(&b->masks);
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX(idx, b->masks.map) {
        uint64_t b_u64 = *bp++;

        
        if (!MINIFLOW_IN_MAP(&a->masks, idx)
            || ((*miniflow_get__(&a->masks, idx) & b_u64) != b_u64)) {
            return true; 
        }
    }

    return false;
}

void flow_limit_vlans(int vlan_limit)
{
    if (vlan_limit <= 0) {
        flow_vlan_limit = FLOW_MAX_VLAN_HEADERS;
    } else {
        flow_vlan_limit = MIN(vlan_limit, FLOW_MAX_VLAN_HEADERS);
    }
}

struct netdev * flow_get_tunnel_netdev(struct flow_tnl *tunnel)
{
    char iface[IFNAMSIZ];
    struct in6_addr ip6;
    struct in6_addr gw;

    if (tunnel->ip_src) {
        in6_addr_set_mapped_ipv4(&ip6, tunnel->ip_src);
    } else if (ipv6_addr_is_set(&tunnel->ipv6_src)) {
        ip6 = tunnel->ipv6_src;
    } else {
        return NULL;
    }

    if (!ovs_router_lookup(0, &ip6, iface, NULL, &gw)) {
        return NULL;
    }

    return netdev_from_name(iface);
}
