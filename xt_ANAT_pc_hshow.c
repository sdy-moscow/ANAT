/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* axt_NAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 

#ifndef SDY_PKC_F_T_xt_ANAT_pc_hshow
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_hshow 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_hshow
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_hshow 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_hshow
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_hshow 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

static int 	axt_hsh_sess_seq_show(struct seq_file *m, void *v) {
    axt_htb_ssi_p 				l_ses;
    axt_htl_node_p 				l_head;
    uint32_t	 				j,k,l_i, l_count,l_proto;
	//uint16_t					l_tmts;
	int							l_tmt, l_stat, l_flags;
	
    l_count=0;
	// ? SDY ERRORS can happen here, if output more then 4kB - seq_printf will return <0 error and uotput will retry again, increase bufsize << seg_read - codeshit!
    seq_printf(m, "Proto SrcIP:SrcPort -> NatIP:NatPort dest \n");

	axt_htb_inout_for_each_from_to(j, k, l_i, 0, axt_iprm_htb_INOUT_HTSZ) {
        rcu_read_lock_bh();
		if (axt_wat_get16(&(axt_ht_outer[j].use[k])) > 0) {
			l_head = &axt_ht_outer[j].ss[k].hd;
			axt_hla_for_each_entry_rcu(l_ses, l_head, out_htln) {
				l_flags = READ_ONCE(l_ses->o.pf.flags);
				if ( (l_flags&AXT_FLAG_DELETED) != 0 ) continue;
				l_tmt 	= READ_ONCE(l_ses->i.tk.tmt);
				l_stat  = (l_tmt == AXT_TMT_SSTMT_STA);
				l_tmt	= (l_tmt - AXT_TMT_SSTMT_SHS)*10; // timeout sec
				l_proto = l_ses->o.pf.proto;
				seq_printf(m, "(^%c) (+%02d) prt:", (char) (l_ses->d.ar.trch + 0x40), l_ses->d.ar.usgr);
				if (l_proto==IPPROTO_TCP) seq_printf(m,"tcp  "); 
				else if (l_proto==IPPROTO_UDP) seq_printf(m,"udp  "); 
				else if (l_proto==IPPROTO_ICMP) seq_printf(m,"icmp "); 
				else seq_printf(m,"%03d  ",l_proto); 
			seq_printf(m, "user:%pI4 :%u |-> nat:%pI4 :%u >-> dest:%pI4 :%u --- ttl:%d", 
				&l_ses->i.tk.addr, ntohs(l_ses->i.tk.port), &l_ses->o.pf.addr, ntohs(l_ses->o.pf.port),  &l_ses->d.ar.addr, ntohs(l_ses->d.ar.port), l_tmt);
				if (l_stat) seq_printf(m, " (STATIC_MAP)");
				if ((l_flags&AXT_FLAG_DEPRICT) != 0) seq_printf(m, " (will be deleted)");
				seq_printf(m, "\n");
				// SDY TODO future if AXT_FLAG_ISNEWLY_BN - no out data!!
				l_count++;
			}
		} 
        rcu_read_unlock_bh();
    }
    seq_printf(m, "Total translations: %d\n", l_count);
    return 0;
}

static int 	axt_hsh_users_seq_show(struct seq_file *m, void *v) {
    axt_htb_htuser_usr_p			l_user;
    struct hlist_head 				*l_head;
    __be32 							l_nataddr;
    uint32_t	 					i, l_count;
	uint8_t							l_trch, l_usgr;
	uint64_t						l_pause_to_jif64, l_now_jif;
    l_count=0;
	l_now_jif = get_jiffies_64();
 	seq_printf(m, "-- !!! NAT IP is correct only for newly unmarked sessions !!! ---)\n");
    for (i = 0; i < axt_iprm_htb_USER_HTSZ; i++) {
        rcu_read_lock_bh();
        if (axt_wat_get16(&(axt_ht_users[i].use)) > 0) {
            l_head = &axt_ht_users[i].user;
            hlist_for_each_entry_rcu(l_user, l_head, list_node) {
                if (l_user->idle < 15) {
					//SDY shown here is actual only for new builded sessions 
					l_usgr = l_user->usgr;
                    l_nataddr = axt_cfg_get_nataddr(l_user->addr, &l_trch, &l_usgr, 1, 0 ,0);
					l_pause_to_jif64 = READ_ONCE(l_user->pause_to_jif64);
					if (l_pause_to_jif64 != 0) { 
						if (l_pause_to_jif64 == ~0)  seq_printf(m, "=BLOCK= ");
						else if (l_pause_to_jif64 <= l_now_jif) WRITE_ONCE(l_user->pause_to_jif64, 0);
						else seq_printf(m, "=PAUSE=%llds= ", (l_pause_to_jif64-l_now_jif)/HZ );
					}			
						
                    seq_printf(m, "(+%02d) ",  l_user->usgr);

					seq_printf(m, "%pI4 -> %pI4 (tcp: %u, udp: %u, icmp: %u, other: %u) idle: %d\n",
                               &l_user->addr, &l_nataddr, l_user->tcp_count, l_user->udp_count, l_user->icmp_count, l_user->other_count, l_user->idle);
                    l_count++;
                }
            }
        }
        rcu_read_unlock_bh();
    }
    seq_printf(m, "Total users: %d\n", l_count);
    return 0;
}

// init|done|work /proc/.. entery
static int 	axt_hsh_sess_seq_open(struct inode *i_inode, struct file *i_file) {
    return single_open(i_file, axt_hsh_sess_seq_show, NULL);
}

static const struct file_operations 	axt_hsh_sess_seq_fops = {
    .open		= axt_hsh_sess_seq_open,
    .read		= seq_read,
    .llseek		= seq_lseek,
    .release	= single_release,
};

static int 	axt_hsh_users_seq_open(struct inode *i_inode, struct file *i_file) {
    return single_open(i_file, axt_hsh_users_seq_show, NULL);
}

static const struct file_operations axt_hsh_users_seq_fops = {
    .open           = axt_hsh_users_seq_open,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static void		axt_hsh_create_proc_fs(struct proc_dir_entry 	*i_dir_node) {
    proc_create("sessions",	0644, i_dir_node, &axt_hsh_sess_seq_fops);
    proc_create("users",	0644, i_dir_node, &axt_hsh_users_seq_fops);
}

static void		axt_hsh_remove_proc_fs(struct proc_dir_entry 	*i_dir_node) {
    remove_proc_entry( "sessions", 	i_dir_node );
    remove_proc_entry( "users",  	i_dir_node );	
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */