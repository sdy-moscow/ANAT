/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* axt_NAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 
#ifndef SDY_PKC_F_T_xt_ANAT_pc_donat
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_donat 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_donat
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_donat 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

//forward declaration
static axt_htb_ssi_p   axt_dnt_create_static_session(const uint8_t i_proto, const uint32_t i_useraddr, const uint16_t i_userport, 
											const uint32_t i_naddr, const uint16_t i_nport,  uint8_t i_usgr, uint8_t i_trch);
/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_donat
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_donat 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */



static axt_htb_ssi_p  axt_dnt_create_session(const uint8_t i_proto, const uint32_t i_useraddr, const uint16_t i_userport, 
											const uint32_t i_naddr, const uint16_t i_nport, 
											const uint32_t i_dstaddr, const uint16_t i_dstport,
											uint8_t i_usgr, uint8_t i_trch, uint32_t i_nip_hash, int i_static) {
//spin_lock_bh(&axt_ht_natipspl[i_nip_hash]); MUST be called befor call!!!

	axt_htb_ssi_p 			l_ses; 
	uint64_t 				l_sstart_ms;	

    l_ses = kzalloc(sizeof(typeof(*l_ses)), GFP_ATOMIC);

    if (unlikely(l_ses == NULL)) {
        printk(KERN_WARNING "xt_ANAT ERROR: Cannot allocate memory for axt_ht_innssi session.\n");
        spin_unlock_bh(&axt_ht_natipspl[i_nip_hash]);
		axt_cnt_inc(&cnt_mem_enomempk);					
        return NULL;
    }

	l_sstart_ms			= axt_wtm_get_cur_ms();

	l_ses->h.su.utcms	= l_sstart_ms;
	l_ses->h.su.usr		= NULL; //SDY TODO future
	
	l_ses->o.pf.flags   = (i_proto != IPPROTO_ICMP ? 0 : AXT_FLAG_ITSICMP);  //SDY TODO future (newly - not ready flag)
	l_ses->o.pf.proto	= i_proto;
	l_ses->o.pf.addr	= i_naddr;
	l_ses->o.pf.port	= i_nport;
	
	l_ses->i.tk.tmt		= ( i_static ? AXT_TMT_SSTMT_STA : (3 + AXT_TMT_SSTMT_SHS) ); //AXT_TMT_SSTMT_STA or 30sec
	l_ses->i.tk.kaint 	= axt_nf9_ssk_get_intrv(l_sstart_ms);
	l_ses->i.tk.addr	= i_useraddr;
	l_ses->i.tk.port	= i_userport;

    l_ses->d.ar.trch	= i_trch;
    l_ses->d.ar.usgr	= i_usgr;
	l_ses->d.ar.addr	= i_dstaddr;
    l_ses->d.ar.port	= i_dstport;
	
	//l_ses->nopayload	=0;
	axt_hla_init_rcu(&(l_ses->out_htln));
	axt_hla_init_rcu(&(l_ses->inn_htln));


	axt_htb_add_session(l_ses);
	
    spin_unlock_bh(&axt_ht_natipspl[i_nip_hash]);

    axt_htb_update_user_limits(i_proto, i_useraddr, i_usgr, 1); 
    axt_nf9_new_event_tosend(i_proto, i_useraddr, i_userport, i_dstaddr, i_dstport, i_naddr, i_nport, 1, l_sstart_ms);
    axt_cnt_inc(&cnt_st_sessions_created);
    axt_cnt_inc(&cnt_st_sessions_active);

 	return l_ses;
}
											
static axt_htb_ssi_p   axt_dnt_create_nat_session(const uint8_t i_proto, const uint32_t i_useraddr, const uint16_t i_userport, 
											const uint32_t i_dstaddr, const uint16_t i_dstport,  const uint32_t i_mark) {
    axt_htb_ssi_p 			l_ses; 
	uint32_t 				l_nataddr;	
    uint16_t 				l_natport;
    uint32_t	 			l_nip_hash;
	uint8_t  				l_trch, l_usgr; //trace char , user group
	
    axt_cnt_inc(&cnt_st_sessions_tried);

	l_nataddr = axt_cfg_get_nataddr(i_useraddr, &l_trch, &l_usgr, 0, i_mark, 1);
			
	//check if  l_nataddr ==0 ( Config not loaded or pool not found! ) return NULL 
    if (unlikely(l_nataddr == 0)) {
		axt_msg_message_ip(AXT_MSGC_USRNATANF, i_proto, i_useraddr, 0, 0,0,i_dstaddr,i_userport);
		axt_cnt_inc(&cnt_nat_noaddr);
		return NULL;
    }
	
	if (unlikely(axt_htb_check_user_limits(i_proto, i_useraddr, l_usgr) == 0)) {
		//coun&warning in axt_htb_check_user_limits()
		return NULL;
    }
	l_nip_hash = axt_htb_hash_for_natipspl(l_nataddr);
	
    spin_lock_bh(&axt_ht_natipspl[l_nip_hash]);
	
    rcu_read_lock_bh();
    l_ses = axt_htb_lookup_session_in(i_proto, i_useraddr, i_userport); //test if already created by another thread
    if(unlikely(l_ses)) {
        spin_unlock_bh(&axt_ht_natipspl[l_nip_hash]);
		axt_cnt_inc(&cnt_st_sessions_triedfp);
		return l_ses;
    }
    rcu_read_unlock_bh();

    if (likely(i_proto == IPPROTO_TCP || i_proto == IPPROTO_UDP || i_proto == IPPROTO_ICMP)) {
        rcu_read_lock_bh();
        l_natport =  axt_htb_search_free_l4_port(i_proto, l_nataddr, i_userport);
        rcu_read_unlock_bh();
        if (l_natport == 0) {
            spin_unlock_bh(&axt_ht_natipspl[l_nip_hash]);
 			//count&warning are in axt_htb_search_free_l4_port()
			return NULL; //not need  rcu_read_lock_bh()
        }
    } else {
        l_natport = i_userport;
    }
	l_ses = axt_dnt_create_session(i_proto, i_useraddr, i_userport, l_nataddr, l_natport, i_dstaddr, i_dstport, l_usgr, l_trch, l_nip_hash, 0);
	
	rcu_read_lock_bh(); //it is needed for correct work axt_dnt_nat_tg()	
	return l_ses;
}


static axt_htb_ssi_p   axt_dnt_create_static_session(const uint8_t i_proto, const uint32_t i_useraddr, const uint16_t i_userport, 
											const uint32_t i_naddr, const uint16_t i_nport,  uint8_t i_usgr, uint8_t i_trch) {
    uint32_t	 			l_nip_hash;
    axt_htb_ssi_p 			l_ses, l_ses_in, l_ses_out; 
	
	uint32_t 				l_uip = i_useraddr;
	uint32_t 				l_nip = i_naddr;
 	printk(KERN_INFO "xt_ANAT DBG: axt_dnt_create_static_session: p:%d u: %pI4:%d  => n: %pI4:%d  +%02d ^%c\n", 
				 i_proto, &l_uip, ntohs(i_userport), &l_nip, ntohs(i_nport), i_usgr, (char) (i_trch + 0x40) );
	

    axt_cnt_inc(&cnt_st_sessions_static);
	
	l_nip_hash = axt_htb_hash_for_natipspl(i_naddr);
    spin_lock_bh(&axt_ht_natipspl[l_nip_hash]);
	
    rcu_read_lock_bh();
	//find old
    l_ses_in  = axt_htb_lookup_session_in(i_proto, i_useraddr, i_userport); //test if already created by another thread
    l_ses_out = axt_htb_lookup_session_out(i_proto, i_naddr, i_nport); //test if already nat used by another thread
	//add new
	l_ses = axt_dnt_create_session(i_proto, i_useraddr, i_userport, i_naddr, i_nport, 0, 0, i_usgr, i_trch, l_nip_hash, 1);
	//set old will del
	if (l_ses_in) axt_htb_flag_setb(AXT_FLAG_WILLDEL_BN, l_ses_in);	
	if (l_ses_out) axt_htb_flag_setb(AXT_FLAG_WILLDEL_BN, l_ses_out);	
    rcu_read_unlock_bh();
	
	return l_ses;	
}


static unsigned int   axt_dnt_nat_tg(struct sk_buff *i_skb, const struct xt_action_param *i_par) { 
    struct iphdr 						*l_ip;
    struct tcphdr 						*l_tcp;
    struct udphdr 						*l_udp;
    struct icmphdr 						*l_icmp;
    axt_htb_ssi_p 						l_ses;
    skb_frag_t 							*l_frag;
    uint16_t 							l_fake_port;
    const struct axt_nat_tginfo 		*l_tginfo	 	= i_par->targinfo;
	uint32_t 							l_mark;
	uint8_t								l_proto, l_proto2, l_trch, l_usgr, l_direction, l_tflags; 
	uint32_t 							l_daddr, l_naddr, l_uaddr, l_saddr;
	uint16_t							l_dport, l_nport, l_uport, l_sport, l_pksz;
	int									l_res;
	
	l_res = NF_DROP;
	l_ses = NULL;
	l_proto = 0; l_proto2 = 0; l_trch  = 0; l_usgr  = 0; l_direction = 0; l_tflags = 0;
	l_daddr = 0; l_naddr  = 0; l_uaddr = 0; l_saddr = 0;
	l_dport = 0; l_nport  = 0; l_uport = 0; l_sport = 0;
	l_pksz  = i_skb->len;
	
    if (unlikely(i_skb->protocol != htons(ETH_P_IP))) {
        //printk(KERN_DEBUG "xt_ANAT DEBUG: Drop not IP packet\n");
		axt_cnt_inc(&cnt_pkt_wproto);
		return NF_DROP;
    }
    if (unlikely(ip_hdrlen(i_skb) != sizeof(struct iphdr))) {
        //printk(KERN_DEBUG "xt_ANAT DEBUG: Drop truncated IP packet\n");
		axt_cnt_inc(&cnt_pkt_wtrunc);
        return NF_DROP;
    }

    l_ip = (struct iphdr *)skb_network_header(i_skb);

    if (unlikely(l_ip->frag_off & htons(IP_OFFSET))) {
        //printk(KERN_DEBUG "xt_ANAT DEBUG: Drop fragmented IP packet\n");
		axt_cnt_inc(&cnt_pkt_wfrags);
        return NF_DROP;
    }
    if (unlikely(l_ip->version != 4)) {
        //printk(KERN_DEBUG "xt_ANAT DEBUG: Drop not IPv4 IP packet\n");
		axt_cnt_inc(&cnt_pkt_wproto);
		return NF_DROP;
    }

	l_proto = l_ip->protocol;
    if (l_tginfo->variant == XTNAT_SNAT) { //OUT pkt
 		//SDY can speed up per cpu counts!!!!
 		axt_cnt_inc(&cnt_pkt_allint);
 		axt_cnt_add(&cnt_pkt_bytint, l_pksz);
		
		l_mark = i_skb->mark;
		l_uaddr = l_ip->saddr;
		l_daddr = l_ip->daddr;
		
        if (l_proto == IPPROTO_TCP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct tcphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT SNAT: Drop truncated TCP packet\n");
				axt_cnt_inc(&cnt_pkt_wtrunc);
              return NF_DROP;
            }
            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_tcp = (struct tcphdr *)skb_transport_header(i_skb);
            skb_reset_transport_header(i_skb);
			l_uport = l_tcp->source;
			l_dport = l_tcp->dest;
			
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_in(l_proto, l_uaddr, l_uport);
            if (!(l_ses)) {
                rcu_read_unlock_bh();
				l_ses = axt_dnt_create_nat_session(l_proto, l_uaddr, l_uport, l_daddr, l_dport, l_mark);
                if (l_ses == NULL) {
                   goto do_DROP_OUT;
                }
            }
			l_naddr = l_ses->o.pf.addr;
			l_nport = l_ses->o.pf.port;
			csum_replace4(&l_ip->check, l_uaddr, l_naddr);
			inet_proto_csum_replace4(&l_tcp->check, i_skb, l_uaddr, l_naddr, true);
			inet_proto_csum_replace2(&l_tcp->check, i_skb, l_uport, l_nport, true);
			l_ip->saddr		= l_naddr;
			l_tcp->source	= l_nport;
			if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_ACTIVED) == 0) axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
			if (l_tcp->fin || l_tcp->rst) {
				axt_htb_flag_setb(AXT_FLAG_TCP_FIN_BN, l_ses); //Test before set is not acctual, rarely changed, only DDOSif happen!
			}
			rcu_read_unlock_bh();

        } else if (l_proto == IPPROTO_UDP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct udphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT SNAT: Drop truncated UDP packet\n");
				axt_cnt_inc(&cnt_pkt_wtrunc);
                return NF_DROP;
            }
            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_udp = (struct udphdr *)skb_transport_header(i_skb);
            skb_reset_transport_header(i_skb);
			l_uport = l_udp->source;
			l_dport = l_udp->dest;

            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_in(l_proto, l_uaddr, l_uport);
            if (!(l_ses)) {
                rcu_read_unlock_bh();
                l_ses = axt_dnt_create_nat_session(l_proto, l_uaddr, l_uport, l_daddr, l_dport, l_mark);
                if (l_ses == NULL) {
                    goto do_DROP_OUT;
                }
            }
			l_naddr = l_ses->o.pf.addr;
			l_nport = l_ses->o.pf.port;
			csum_replace4(&l_ip->check, l_uaddr, l_naddr);
			if (l_udp->check) {
				inet_proto_csum_replace4(&l_udp->check, i_skb, l_uaddr, l_naddr, true);
				inet_proto_csum_replace2(&l_udp->check, i_skb, l_uport, l_nport, true);
			}
			l_ip->saddr   = l_naddr;
			l_udp->source = l_nport;
			if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_ACTIVED) == 0) axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
			rcu_read_unlock_bh();

		} else if (l_proto == IPPROTO_ICMP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT SNAT: Drop truncated ICMP packet\n");
 				axt_cnt_inc(&cnt_pkt_wtrunc);
                return NF_DROP;
            }

            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_icmp = (struct icmphdr *)skb_transport_header(i_skb);
            skb_reset_transport_header(i_skb);
			
			//l_uport = 0; already
            if (l_icmp->type == 0 || l_icmp->type == 8) {
                l_uport = l_icmp->un.echo.id;
            }
			l_dport = l_uport;
			
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_in(l_proto, l_uaddr, l_uport);
            if (!(l_ses)) {
                rcu_read_unlock_bh();
                l_ses = axt_dnt_create_nat_session(l_proto, l_uaddr, l_uport, l_daddr, l_dport, l_mark);
                if (l_ses == NULL) {
                    goto do_DROP_OUT;
                }
            }
			l_naddr = l_ses->o.pf.addr;
			l_nport = l_ses->o.pf.port;
			csum_replace4(&l_ip->check, l_uaddr, l_naddr);
			l_ip->saddr = l_naddr;
			if (l_icmp->type == 0 || l_icmp->type == 8) {
				inet_proto_csum_replace2(&l_icmp->checksum, i_skb, l_uport, l_nport, true);
				l_icmp->un.echo.id = l_nport;
			}
			//set event happen flag
			if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_ACTIVED) == 0) axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
			rcu_read_unlock_bh();
	
        } else { //OTHER IP PROTO
			//SDY MULPTIPLE OTHER IP protocols use support for many users . Old NAT ver: l_fake_port = 0; new ANAT ver:
			l_uport = reciprocal_scale(jhash_1word(l_daddr, 0), 65536);
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_in(l_proto, l_uaddr, l_uport);
            if (!(l_ses)) {
                rcu_read_unlock_bh();
                l_ses = axt_dnt_create_nat_session(l_proto, l_uaddr, l_uport, l_daddr, 0, l_mark);
                if (l_ses == NULL) {
                    goto do_DROP_OUT;
                }
            }
			l_naddr = l_ses->o.pf.addr;
			csum_replace4(&l_ip->check, l_uaddr, l_naddr);
			l_ip->saddr = l_naddr;
			if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_ACTIVED) == 0) axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
			rcu_read_unlock_bh();

        }
		goto do_ACCEPT_OUT;
    } else if (l_tginfo->variant == XTNAT_DNAT) {
 		//SDY can speed up per cpu counts!!!!
		axt_cnt_inc(&cnt_pkt_allext);
 		axt_cnt_add(&cnt_pkt_bytext, l_pksz);
		
		l_daddr = l_ip->saddr;
		l_naddr = l_ip->daddr;

		if (l_proto == IPPROTO_TCP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct tcphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT DNAT: Drop truncated TCP packet\n");
				axt_cnt_inc(&cnt_pkt_wtrunc);
                return NF_DROP;
            }
            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_tcp = (struct tcphdr *)skb_transport_header(i_skb);
            skb_reset_transport_header(i_skb);

            if (unlikely( (skb_shinfo(i_skb)->nr_frags > 1) && (skb_headlen(i_skb) == sizeof(struct iphdr)) )) {
                l_frag = &skb_shinfo(i_skb)->frags[0];
                if (unlikely(skb_frag_size(l_frag) < sizeof(struct tcphdr))) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: drop TCP frag_size = %d\n", skb_frag_size(l_frag));
						axt_cnt_inc(&cnt_pkt_wfrags);
						return NF_DROP;
                }
                l_tcp = (struct tcphdr *)skb_frag_address_safe(l_frag);
                if (unlikely(l_tcp == NULL)) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: drop fragmented TCP\n");
 						axt_cnt_inc(&cnt_pkt_wfrags);
						return NF_DROP;
                }
                axt_cnt_inc(&cnt_pkt_frags);
            }
			l_dport = l_tcp->source;
			l_nport = l_tcp->dest;
			
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_out(l_proto, l_naddr, l_nport);
            if ( likely(l_ses) ) {
		        skb_reset_transport_header(i_skb);
				l_uaddr = l_ses->i.tk.addr;
				l_uport = l_ses->i.tk.port;
                csum_replace4(&l_ip->check, l_naddr, l_ses->i.tk.addr);
                inet_proto_csum_replace4(&l_tcp->check, i_skb, l_naddr, l_uaddr, true);
                inet_proto_csum_replace2(&l_tcp->check, i_skb, l_nport, l_uport, true);
                l_ip->daddr = l_uaddr;
                l_tcp->dest = l_uport;

				if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_REPLIED) == 0) {
					axt_htb_flag_setb(AXT_FLAG_REPLIED_BN, l_ses);
					axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
				}	
                if (l_tcp->fin || l_tcp->rst) {  //Test before set is not acctual, rarely changed, only DDOSif happen!
					axt_htb_flag_setb(AXT_FLAG_TCP_FIN_BN, l_ses);
				}
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				goto do_LOCAL_IN;
            }
		} else if (l_proto == IPPROTO_UDP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct udphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT DNAT: Drop truncated UDP packet\n");
				axt_cnt_inc(&cnt_pkt_wtrunc);
                return NF_DROP;
            }

            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_udp = (struct udphdr *)skb_transport_header(i_skb);

            if (unlikely( (skb_shinfo(i_skb)->nr_frags > 1) && (skb_headlen(i_skb) == sizeof(struct iphdr)) )) {
                l_frag = &skb_shinfo(i_skb)->frags[0];
                if (unlikely(skb_frag_size(l_frag) < sizeof(struct udphdr))) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: drop UDP frag_size = %d\n", skb_frag_size(l_frag));
 						axt_cnt_inc(&cnt_pkt_wfrags);
                        return NF_DROP;
                }
                l_udp = (struct udphdr *)skb_frag_address_safe(l_frag);
                if (unlikely(l_udp == NULL)) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: drop fragmented UDP\n");
  						axt_cnt_inc(&cnt_pkt_wfrags);
                        return NF_DROP;
                }
                axt_cnt_inc(&cnt_pkt_frags);
            }
			l_dport = l_udp->source;
			l_nport = l_udp->dest;

            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_out(l_proto, l_naddr, l_nport);
            if (likely(l_ses)) {
		        skb_reset_transport_header(i_skb);
				l_uaddr = l_ses->i.tk.addr;
				l_uport = l_ses->i.tk.port;
                csum_replace4(&l_ip->check, l_naddr, l_uaddr);
                if (l_udp->check) {
                    inet_proto_csum_replace4(&l_udp->check, i_skb, l_naddr, l_uaddr, true);
                    inet_proto_csum_replace2(&l_udp->check, i_skb, l_nport, l_uport, true);
                }
                l_ip->daddr = l_uaddr;
                l_udp->dest = l_uport;
				
				if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_REPLIED) == 0) {
					axt_htb_flag_setb(AXT_FLAG_REPLIED_BN, l_ses);
					axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
				}	
				rcu_read_unlock_bh();
            } else {
				rcu_read_unlock_bh();
				goto do_LOCAL_IN;
            }
		} else if (l_proto == IPPROTO_ICMP) {
            if ( unlikely(i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr))) ) {
                //printk(KERN_DEBUG "xt_ANAT DNAT: Drop truncated ICMP packet\n");
				axt_cnt_inc(&cnt_pkt_wtrunc);
                return NF_DROP;
            }

            skb_set_transport_header(i_skb, l_ip->ihl * 4);
            l_icmp = (struct icmphdr *)skb_transport_header(i_skb);

            //l_nport = 0; already
            if (l_icmp->type == 0 || l_icmp->type == 8) {
                l_nport = l_icmp->un.echo.id;
            } else if (l_icmp->type == 3 || l_icmp->type == 4 || l_icmp->type == 5 || l_icmp->type == 11 || l_icmp->type == 12 || l_icmp->type == 31) {
                axt_cnt_inc(&cnt_pkt_related_icmp);
                if (i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr) + sizeof(struct iphdr))) {
                    //printk(KERN_DEBUG "xt_ANAT DNAT: Drop related ICMP packet witch truncated IP header\n");
					axt_cnt_inc(&cnt_pkt_wtrunc);
                    return NF_DROP;
                }

                skb_set_network_header(i_skb,sizeof(struct icmphdr) + sizeof(struct iphdr));
                l_ip = (struct iphdr *)skb_network_header(i_skb);
                skb_reset_network_header(i_skb);
				l_proto2 = l_ip->protocol;

                if (l_proto2 == IPPROTO_TCP) {
                    if (i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8)) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: Drop related ICMP packet witch truncated TCP header\n");
						axt_cnt_inc(&cnt_pkt_wtrunc);
                        return NF_DROP;
                    }
                    skb_set_transport_header(i_skb, (l_ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    l_tcp = (struct tcphdr *)skb_transport_header(i_skb);
                    skb_reset_transport_header(i_skb);
					
                    rcu_read_lock_bh();
                    l_ses = axt_htb_lookup_session_out(l_proto2, l_ip->saddr, l_tcp->source);
                    if (l_ses) {
						l_uaddr = l_ses->i.tk.addr;
                        csum_replace4(&l_ip->check, l_ip->saddr, l_uaddr);
                        l_ip->saddr   = l_uaddr;
                        l_tcp->source = l_ses->i.tk.port;
                    } else {
                        rcu_read_unlock_bh();
 						goto do_LOCAL_IN;
					}
                    l_ip = (struct iphdr *)skb_network_header(i_skb);
                    csum_replace4(&l_ip->check, l_naddr, l_uaddr);
                    l_ip->daddr = l_uaddr;
                    rcu_read_unlock_bh();
					
                } else if (l_proto2 == IPPROTO_UDP) {
                    if (i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8)) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: Drop related ICMP packet witch truncated UDP header\n");
						axt_cnt_inc(&cnt_pkt_wtrunc);
                        return NF_DROP;
                    }
                    skb_set_transport_header(i_skb, (l_ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    l_udp = (struct udphdr *)skb_transport_header(i_skb);
                    skb_reset_transport_header(i_skb);
					
                    rcu_read_lock_bh();
                    l_ses = axt_htb_lookup_session_out(l_proto2, l_ip->saddr, l_udp->source);
                    if (l_ses) {
						l_uaddr = l_ses->i.tk.addr;
                        csum_replace4(&l_ip->check, l_ip->saddr, l_uaddr);
                        l_ip->saddr   = l_uaddr;
                        l_udp->source = l_ses->i.tk.port;
                    } else {
                        rcu_read_unlock_bh();
 						goto do_LOCAL_IN;
					}
                    l_ip = (struct iphdr *)skb_network_header(i_skb);
                    csum_replace4(&l_ip->check, l_naddr, l_uaddr);
                    l_ip->daddr = l_uaddr;
                    rcu_read_unlock_bh();
					
                } else if (l_proto2 == IPPROTO_ICMP) {
                    if (i_skb->len < (ip_hdrlen(i_skb) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8)) {
                        //printk(KERN_DEBUG "xt_ANAT DNAT: Drop related ICMP packet witch truncated ICMP header\n");
						axt_cnt_inc(&cnt_pkt_wtrunc);
                        return NF_DROP;
                    }

                    skb_set_transport_header(i_skb, (l_ip->ihl * 4) + sizeof(struct icmphdr) + sizeof(struct iphdr));
                    l_icmp = (struct icmphdr *)skb_transport_header(i_skb);
                    skb_reset_transport_header(i_skb);

                    l_fake_port = 0;
                    if (l_icmp->type == 0 || l_icmp->type == 8) {
                        l_fake_port = l_icmp->un.echo.id;
                    }

                    rcu_read_lock_bh();
                    l_ses = axt_htb_lookup_session_out(l_proto2, l_ip->saddr, l_fake_port);
                    if (l_ses) {
						l_uaddr = l_ses->i.tk.addr;
                        csum_replace4(&l_ip->check, l_ip->saddr, l_uaddr);
                        l_ip->saddr = l_uaddr;
                        if (l_icmp->type == 0 || l_icmp->type == 8) {
                            inet_proto_csum_replace2(&l_icmp->checksum, i_skb, l_fake_port, l_ses->i.tk.port, true);
                            l_icmp->un.echo.id = l_ses->i.tk.port;
                        }
                    } else {
                        rcu_read_unlock_bh();
						goto do_LOCAL_IN;
					}
                    l_ip = (struct iphdr *)skb_network_header(i_skb);
                    csum_replace4(&l_ip->check, l_naddr, l_uaddr);
                    l_ip->daddr = l_uaddr;
                    rcu_read_unlock_bh();
                }
                goto do_ACCEPT_IN;
            }
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_out(l_proto, l_naddr, l_nport);
            if (likely(l_ses)) {
				l_uaddr = l_ses->i.tk.addr;
                csum_replace4(&l_ip->check, l_ip->daddr, l_uaddr);
                l_ip->daddr = l_uaddr;
                if (l_icmp->type == 0 || l_icmp->type == 8) {
					l_uport = l_ses->i.tk.port;
                    inet_proto_csum_replace2(&l_icmp->checksum, i_skb, l_nport, l_uport, true);
                    l_icmp->un.echo.id = l_uport;
                }
				if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_REPLIED) == 0) {
					axt_htb_flag_setb(AXT_FLAG_REPLIED_BN, l_ses);
					axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
				}
				rcu_read_unlock_bh();
            } else {
				rcu_read_unlock_bh();
				goto do_LOCAL_IN;
            }
		} else { //OTHER PROTO
			//SDY MULPTIPLE IP protocols for many users support. Old NAT ver: l_nport (l_fake_port) = 0; new ANAT ver:
			l_nport = reciprocal_scale(jhash_1word(l_daddr, 0), 65536);
            rcu_read_lock_bh();
            l_ses = axt_htb_lookup_session_out(l_proto, l_naddr, l_nport);
            if (likely(l_ses)) {
				l_uaddr = l_ses->i.tk.addr;
                csum_replace4(&l_ip->check, l_naddr, l_uaddr);
                l_ip->daddr = l_uaddr;
				if ((READ_ONCE(l_ses->o.pf.flags) & AXT_FLAG_REPLIED) == 0) {
					axt_htb_flag_setb(AXT_FLAG_REPLIED_BN, l_ses);
					axt_htb_flag_setb(AXT_FLAG_ACTIVED_BN, l_ses);
				}						
				rcu_read_unlock_bh();
            } else {
				rcu_read_unlock_bh();
				goto do_LOCAL_IN;
            }
		}
		goto do_ACCEPT_IN;
    }
//-----------------------	
  do_ACCEPT_IN:	
	l_direction = AXT_MSG_TRF_DIRECT; 
	
  do_ACCEPT_OUT:
	l_res = NF_ACCEPT;
	if (unlikely(axt_cfg_x_tr_isenabled())) {
		l_trch = l_ses->d.ar.trch;
		l_usgr = l_ses->d.ar.usgr;
		if ( (axt_cfg_x_tr_ison(l_trch)) || (axt_cfg_x_trus_ison( l_uaddr, l_usgr)) ) {
			l_tflags = l_direction |  AXT_MSG_TRF_SESFND | AXT_MSG_TRF_READY ;
			l_saddr = l_ses->d.ar.addr;
			l_sport = l_ses->d.ar.port;
			goto  do_TRACE;
		}
	}
    return l_res;
//-----------------------	
  do_LOCAL_IN:
    axt_cnt_inc(&cnt_pkt_dnat_nofnd); 
	l_direction = AXT_MSG_TRF_DIRECT; 
	l_res = (axt_aprm_getN32(&axt_aprm_nat_locfrwd_pol) == 0 ? NF_DROP : NF_ACCEPT );
	if (unlikely( axt_cfg_x_tr_isenabled() && axt_cfg_x_tr_locfrwd_ison() )) { 
		l_tflags = l_direction | AXT_MSG_TRF_READY ;
		goto  do_TRACE;	
	}
	return l_res;
	
  do_DROP_OUT:
 	l_res = NF_DROP;
	if (unlikely( axt_cfg_x_tr_isenabled() && axt_cfg_x_tr_outdrop_ison() )) { 
		l_tflags = l_direction | AXT_MSG_TRF_READY ;
		goto  do_TRACE;	
	}
    return l_res; 
//-----------------------	
  do_TRACE:
	l_tflags |= (l_res == NF_DROP ? 0 : AXT_MSG_TRF_RESULT);
	if (unlikely( axt_cfg_x_tr_filter_ison() )) {
		if (likely( !axt_cfg_x_tr_filter_chkhdr_ison(l_proto, l_pksz, l_tflags) )) return l_res;
		if (likely( !axt_cfg_x_tr_filter_chkipf_ison(&axt_xcfg.trfl_u, ntohl(l_uaddr), ntohs(l_uport)) )) return l_res;
		if (likely( !axt_cfg_x_tr_filter_chkipf_ison(&axt_xcfg.trfl_n, ntohl(l_naddr), ntohs(l_nport)) )) return l_res;
		if (likely( !axt_cfg_x_tr_filter_chkipf_ison(&axt_xcfg.trfl_d, ntohl(l_daddr), ntohs(l_dport)) )) return l_res;
		if (unlikely( !axt_cfg_x_tr_filter_chkipf_ison(&axt_xcfg.trfl_s, ntohl(l_saddr), ntohs(l_sport)) )) return l_res;
	}
	axt_msg_trace_add(l_tflags, l_proto, l_usgr, l_trch, l_uaddr, l_naddr, l_daddr, l_saddr, l_uport, l_nport, l_dport, l_sport, l_pksz);
    return l_res; 
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */