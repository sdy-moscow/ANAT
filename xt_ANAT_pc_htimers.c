/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* axt_NAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)  
*/ 

#ifndef SDY_PKC_F_T_xt_ANAT_pc_htimers
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_htimers 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_htimers
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_htimers 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

static 	DEFINE_SPINLOCK(	axt_htm_sessions_timer_lock);
static 	DEFINE_SPINLOCK(	axt_htm_users_timer_lock);
static struct timer_list 	axt_htm_sessions_cleanup_timer = {0};
static struct timer_list 	axt_htm_users_cleanup_timer  = {0};

// htimers lookup
static uint32_t 			axt_htm_inout_htable_vector = 0;
static uint32_t 			axt_htm_users_htable_vector = 0;

//forward declaration
static void 	axt_htm_ses_kill(int i_operation, int i_fip, int i_fproto, int i_fport, int i_fusgr, int i_ftrch,
									uint32_t i_ip, uint16_t i_proto, uint16_t i_port, uint8_t i_usgr, uint8_t i_trch);
static void 	axt_htm_user_blockpause(int i_operation, int i_fip, int i_fusgr, uint32_t i_ip, uint8_t i_usgr, uint32_t i_pauses);

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_htimers
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_htimers 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

//---------- user cleanup
static void 	axt_htm_users_cleanup_timer_callback( struct timer_list *i_timer ) {
    axt_htb_htuser_usr_p			l_user;
    struct 	hlist_head 				*l_head;
    struct 	hlist_node 				*l_next;
    uint32_t						i, l_vector_start, l_vector_end, l_was_lock;
	uint32_t 						l_idle;
	uint64_t						l_jf,l_pause;
		
    spin_lock_bh(&axt_htm_users_timer_lock);

    if (axt_ht_users == NULL) {
        printk(KERN_WARNING "xt_ANAT ERROR: USERS CLEAN  TIMER BUG found null ptr for axt_ht_users.\n");
        spin_unlock_bh(&axt_htm_users_timer_lock);
		axt_cnt_inc(&cnt_mem_bugs);					
        return;
    }

    l_vector_start =  axt_htm_users_htable_vector * (axt_iprm_htb_USER_HTSZ/60);
    if (axt_htm_users_htable_vector == 60) {
        l_vector_end = axt_iprm_htb_USER_HTSZ;
        axt_htm_users_htable_vector = 0;
    } else {
        l_vector_end = l_vector_start + (axt_iprm_htb_USER_HTSZ/60);
        axt_htm_users_htable_vector++;
    }

	l_jf = get_jiffies_64();

    for (i = l_vector_start; i < l_vector_end; i++) {
		l_head = &axt_ht_users[i].user;
		hlist_for_each_entry_safe(l_user, l_next, l_head, list_node) {
			l_idle  = READ_ONCE(l_user->idle);
			if ((l_idle < 15) && ((l_pause = READ_ONCE(l_user->pause_to_jif64)) !=0)) {
				//do not change idle it is blocked!!!!
				if ( (l_pause != ~0) && (l_pause < get_jiffies_64()) ) {
					WRITE_ONCE(l_user->pause_to_jif64, 0); //pause period expired clear pause_to_jif64 to faster work
					WRITE_ONCE(l_user->idle, 0); // after unpause or unblock start idle from 0 
				}	
			} else {
				//it is some bad thing until we read some one can make lock and inc sessions
				l_was_lock = 0;
				if (l_idle >= 14) { spin_lock_bh(&axt_ht_users[i].lock);	l_was_lock = 1; } 			
				if (READ_ONCE(l_user->tcp_count) == 0 && READ_ONCE(l_user->udp_count) == 0 && 
					READ_ONCE(l_user->icmp_count) == 0 && READ_ONCE(l_user->other_count) == 0) {
					WRITE_ONCE(l_user->idle, ++l_idle);
				}
				if (l_idle > 15) {
					hlist_del_rcu(&l_user->list_node);
					axt_wat_dec16(&(axt_ht_users[i].use));
					kfree_rcu(l_user, rcu);
					axt_cnt_dec(&cnt_st_users_active);
				}
				if (l_was_lock != 0) spin_unlock_bh(&axt_ht_users[i].lock);
			}
		}      
    }
    mod_timer( &axt_htm_users_cleanup_timer, jiffies + msecs_to_jiffies(1000) );  //run every 1 sec
    spin_unlock_bh(&axt_htm_users_timer_lock);
}

//---------- sessions cleanup
static void 	axt_htm_sessions_cleanup_timer_callback( struct timer_list *i_timer ) {
    axt_htb_ssi_p				l_ses;
    axt_htl_node_p 				l_head, l_prev, l_next;
    int							l_locked;
	uint32_t					j, k, l_i, l_vector_start, l_vector_end;
	uint64_t					l_cur_ms;
	uint8_t						l_cur_kaint;
	uint8_t 					l_cur_stic;
    uint8_t	 					l_flags;
	int							l_tmt, l_static;
 
    spin_lock_bh(&axt_htm_sessions_timer_lock);

    if (axt_ht_inner == NULL || axt_ht_outer == NULL) {
		spin_unlock_bh(&axt_htm_sessions_timer_lock);
		printk(KERN_WARNING "xt_ANAT ERROR: SESSIONS CLEAN TIMER BUG found null ptr for axt_ht_inner/axt_ht_outer.\n");
		axt_cnt_inc(&cnt_mem_bugs);					
        return;
    }

    l_vector_start = axt_htm_inout_htable_vector * (axt_iprm_htb_INOUT_HTSZ/100);
    if (axt_htm_inout_htable_vector == 100) {
        l_vector_end = axt_iprm_htb_INOUT_HTSZ;
        axt_htm_inout_htable_vector = 0;
    } else {
        l_vector_end = l_vector_start + (axt_iprm_htb_INOUT_HTSZ/100);
        axt_htm_inout_htable_vector++;
    }

	l_cur_ms	  	= axt_wtm_get_cur_ms();
	l_cur_stic  	= axt_nf9_ssk_get_stic(l_cur_ms);
	l_cur_kaint 	= axt_nf9_ssk_get_intrv(l_cur_ms);
	
	axt_htb_inout_for_each_from_to(j, k, l_i, l_vector_start, l_vector_end) {
    //for (i = l_vector_start; i < l_vector_end; i++) {
 
		// clean innssi+ timeout work + keepalive nf9 work
        l_head = &(axt_ht_inner[j].ss[k].hd); 
		if (!(axt_hla_isnxempty_rcu(l_head))) { // not empty one
			spin_lock_bh(&axt_ht_inner[j].lock); 	//lock add until we use head
			l_locked = 1;
			l_prev = l_head;
			axt_hla_for_each_entry_safe_rcu(l_ses, l_next, l_head, inn_htln) {
				l_flags = READ_ONCE(l_ses->o.pf.flags);
				if ( (l_flags & (AXT_FLAG_DELETED|AXT_FLAG_DELFRIN)) !=0 ) { // it can't be, debug control
					//l_prev  = &(l_ses->inn_htln); //we do not cange it on errors
					printk(KERN_WARNING "xt_ANAT ERROR: SESSIONS CLEAN TIMER BUG in inner chain: (l_flags & (AXT_FLAG_DELETED|AXT_FLAG_DELFRIN)) !=0).\n");
					axt_cnt_inc(&cnt_mem_bugs);							
					continue;  
				}				
				if ( (l_flags & (AXT_FLAG_ISNEWLY)) != 0) { // on create stage do not touch
					l_prev  = &(l_ses->inn_htln);
					continue;  
				}
				l_tmt = READ_ONCE(l_ses->i.tk.tmt); 
				l_static = (l_tmt == AXT_TMT_SSTMT_STA);
				l_tmt -= AXT_TMT_SSTMT_SHS;
				if (!l_static) { // STAtic session tmt never changed only STAT_DEL
					l_tmt--; //dec timeout 10 sec
					if ((l_flags & AXT_FLAG_ACTIVED)) { 
						axt_htb_flag_clearb(AXT_FLAG_ACTIVED_BN, l_ses);
						l_tmt = ( ((l_flags & AXT_FLAG_REPLIED) && ((l_flags & AXT_FLAG_ITSICMP)==0)) ? 30 : 3 ); //300 sec : 30 sec
					}
					if ( unlikely(l_flags & AXT_FLAG_TCP_FIN) ) {
						axt_htb_flag_clearb(AXT_FLAG_TCP_FIN_BN, l_ses);
						l_tmt = 1;
					} 
				} else {
					axt_htb_flag_clearb(AXT_FLAG_ACTIVED_BN, l_ses);
					axt_htb_flag_clearb(AXT_FLAG_TCP_FIN_BN, l_ses);
				}
				if ( unlikely((l_flags & AXT_FLAG_WILLDEL) && (l_tmt > 0)) ) { //lets wait litle more! looks we have can activity after die or kill command
					//kill command: axt_htb_flag_setb(AXT_FLAG_WILLDEL_BN, l_ses); WRITE_ONCE(l_ses->i.tk.tmt, 1+ AXT_TMT_SSTMT_SHS);
					if (l_static) { axt_cnt_dec(&cnt_st_sessions_static); }	
					l_tmt = 0;				
				}
				if ( unlikely(((l_flags & AXT_FLAG_WILLDEL)==0) && (l_tmt < 0)) ) { // MUST NEVER HAPPEN
					l_tmt = 0; 				
					printk(KERN_WARNING "xt_ANAT ERROR: SESSIONS CLEAN TIMER BUG in inner chain: (l_flags & AXT_FLAG_WILLDEL)==0) && (l_tmt < 0)).\n");
					axt_cnt_inc(&cnt_mem_bugs);							
				}				
				if (l_tmt >= 0) { 
					if (unlikely( (l_tmt > 0) && ( READ_ONCE(l_ses->i.tk.kaint) != l_cur_kaint) 
							&& (axt_nf9_ssk_chk_stic(l_ses->i.tk.addr, l_cur_stic)) )) { // it is time to send nf9 keepalive	
						axt_nf9_new_event_tosend(l_ses->o.pf.proto, l_ses->i.tk.addr, l_ses->i.tk.port, l_ses->d.ar.addr, l_ses->d.ar.port,
												 l_ses->o.pf.addr,  l_ses->o.pf.port, 3, l_ses->h.su.utcms);
						//update nf9 SSINT keepalive interval
						WRITE_ONCE(l_ses->i.tk.kaint, l_cur_kaint);
					}
					if (l_tmt==0) axt_htb_flag_setb(AXT_FLAG_WILLDEL_BN, l_ses);
					WRITE_ONCE(l_ses->i.tk.tmt, l_tmt+ AXT_TMT_SSTMT_SHS);
					
					l_prev  = &(l_ses->inn_htln); 
				} else {// l_tmt<0;
					if ( unlikely(l_tmt <= -3) )  { // MUST NEVER HAPPEN
						l_tmt = -3;			
						printk(KERN_WARNING "xt_ANAT ERROR: SESSIONS CLEAN TIMER BUG in inner chain:(l_tmt <= -3).\n");
						axt_cnt_inc(&cnt_mem_bugs);							
					}				
					// it will be only once! on AXT_FLAG_DELFRIN == 0.
					WRITE_ONCE(l_ses->i.tk.tmt, l_tmt + AXT_TMT_SSTMT_SHS);
					axt_htb_flag_setb(AXT_FLAG_DELFRIN_BN, l_ses);				
					axt_nf9_new_event_tosend(l_ses->o.pf.proto, l_ses->i.tk.addr, l_ses->i.tk.port, l_ses->d.ar.addr, l_ses->d.ar.port,
											 l_ses->o.pf.addr,  l_ses->o.pf.port, 2, l_ses->h.su.utcms);
		
					axt_hla_del_rcu(&(l_ses->inn_htln), l_prev); 
					axt_wat_dec16(&(axt_ht_inner[j].use[k]));  
					axt_cnt_dec(&cnt_st_sessions_active);
					
					//SDY TODO future over h.su.usr
					axt_htb_update_user_limits(l_ses->o.pf.proto, l_ses->i.tk.addr, l_ses->d.ar.usgr, -1); 
					//if we delete it - it can't stay l_prev!!!
				}
				if (l_locked && (l_prev != l_head)) { //we go over head, so can unlock add
					spin_unlock_bh(&axt_ht_inner[j].lock);
					l_locked = 0;	
				}			
			}
			if (l_locked) spin_unlock_bh(&axt_ht_inner[j].lock);	
		}
		// clean outssi and kfree 
        l_head = &(axt_ht_outer[j].ss[k].hd); 
		if (!(axt_hla_isnxempty_rcu(l_head))) { // not empty one
			spin_lock_bh(&axt_ht_outer[j].lock); //lock add until we use head
			l_locked = 1;
			l_prev = l_head;
			axt_hla_for_each_entry_safe_rcu(l_ses, l_next, l_head, out_htln) {  //axt_ht_outer - hal htlist, so next in chain can be changed only here!!!
				l_flags = READ_ONCE(l_ses->o.pf.flags);
				if ( (l_flags & (AXT_FLAG_DELETED))  != 0 ) { // it can't be, !
					printk(KERN_WARNING "xt_ANAT ERROR: SESSIONS CLEAN TIMER BUG in outer chain: ((l_flags & (AXT_FLAG_DELETED))  != 0).\n");
					axt_cnt_inc(&cnt_mem_bugs);							
					continue;  
				}
				if ( (l_flags & (AXT_FLAG_DELFRIN)) != 0 ) { // it is our work!!!	
					axt_htb_flag_setb(AXT_FLAG_DELETED_BN, l_ses);				

					axt_hla_del_rcu(&(l_ses->out_htln), l_prev); 
					axt_wat_dec16(&(axt_ht_outer[j].use[k]));
					
					//l_ses->h.rc.rcu = {0}; //SDY TODO look need or no
					l_ses->h.su.utcms = 0;
					l_ses->h.su.usr = 0;
					
					kfree_rcu(l_ses, h.rc.rcu);    
				} else {
					l_prev  = &(l_ses->out_htln);
				}
				if (l_locked && (l_prev != l_head)) { //we go over head, so can unlock add
					spin_unlock_bh(&axt_ht_outer[j].lock);
					l_locked = 0;	
				}
			}
			if (l_locked) spin_unlock_bh(&axt_ht_outer[j].lock);	
		}
	}

    mod_timer( &axt_htm_sessions_cleanup_timer, jiffies + msecs_to_jiffies(100) ); //run every 0,1 sec 
    spin_unlock_bh(&axt_htm_sessions_timer_lock);
}

//---------- sessions kill
static void 	axt_htm_ses_kill(int i_operation, int i_fip, int i_fproto, int i_fport, int i_fusgr, int i_ftrch,
									uint32_t i_ip, uint16_t i_proto, uint16_t i_port, uint8_t i_usgr, uint8_t i_trch) {
//i_operation 0 = ip+port filter by local (user) address, 1 = ip+port filter by out (nat) address 0,1 - del NOT statis
//i_operation 2 = del static session (ip+port filter by local (user) address)
// i_ip, i_port - must be hton
    axt_htb_ssi_p			l_ses;
    axt_htl_node_p 			l_head, l_next;
	uint32_t				j, k, l_i, l_kcnt, l_proto;
    uint8_t	 				l_flags, l_tmt;
	axt_htb_inout_p			l_htb;
	int		 				l_delnat = (i_operation == 1);
 
	//SDY TODO DELETE DEBUG
	uint32_t 				l_ip = i_ip;
 	printk(KERN_INFO "xt_ANAT DBG: CMD_KILL_xxx  op: %d, fip: %d, fproto: %d, fport: %d, fusgr: %d, ftrch: %d => %pI4 p%d : %d +%02d ^%c\n", 
				i_operation, i_fip, i_fproto, i_fport, i_fusgr, i_ftrch, &l_ip, i_proto, ntohs(i_port), i_usgr, (char) (i_trch + 0x40) );

    if (axt_ht_inner == NULL || axt_ht_outer == NULL)  {
		printk(KERN_WARNING "xt_ANAT ERROR: CMD_KILL_xxx BUG found null ptr for axt_ht_inner|axt_ht_outer.\n");
		axt_cnt_inc(&cnt_mem_bugs);					
        return;
    }
	l_kcnt = 0;
	l_htb = axt_ht_inner;
	
	axt_htb_inout_for_each_from_to(j, k, l_i, 0, axt_iprm_htb_INOUT_HTSZ) {
		// hash run
        l_head = &(l_htb[j].ss[k].hd); 
		if (!(axt_hla_isnxempty_rcu(l_head))) { // not empty one
			axt_hla_for_each_entry_safe_rcu(l_ses, l_next, l_head, inn_htln) {
				l_flags = READ_ONCE(l_ses->o.pf.flags);
				if ( (l_flags & (AXT_FLAG_DEPRICT|AXT_FLAG_ISNEWLY)) !=0 )  continue;
				l_tmt = READ_ONCE(l_ses->i.tk.tmt);				
				if (i_operation == 2) {
					if (l_tmt != AXT_TMT_SSTMT_STA) continue; // it is not STAtic session can't kill by STATIC_MAP_DEL	
				} else {
					if (l_tmt == AXT_TMT_SSTMT_STA) continue; // it is STAtic session can be kill only by  STATIC_MAP_DEL				
				}
				if (i_fproto!=0) {
					l_proto = l_ses->o.pf.proto;
					if ( (i_proto == 256) && ((l_proto == IPPROTO_TCP) || (l_proto == IPPROTO_UDP) || (l_proto == IPPROTO_ICMP)) ) continue;
					if ( (i_proto < 256) && (i_proto != l_proto) ) continue;
				}
				if ( ((i_fusgr!=0) && (i_usgr != l_ses->d.ar.usgr)) || ((i_ftrch!=0) && (i_trch != l_ses->d.ar.trch)) )  continue;
				if (l_delnat == 0) {
					if ( ((i_fip!=0) && (i_ip != l_ses->i.tk.addr)) || ((i_fport!=0) && (i_port != l_ses->i.tk.port)) )  continue;
				} else {
					if ( ((i_fip!=0) && (i_ip != l_ses->o.pf.addr)) || ((i_fport!=0) && (i_port != l_ses->o.pf.port)) )  continue;
				}
				axt_htb_flag_setb(AXT_FLAG_WILLDEL_BN, l_ses);				
				l_kcnt++;
			}
		}
	}
	printk(KERN_INFO "xt_ANAT INFO: CMD_KILL_xxx - SUCCESSFUL killed sessions: %d.\n", l_kcnt);
}


//---------- users block&pause
static void 	axt_htm_user_blockpause(int i_operation, int i_fip, int i_fusgr, uint32_t i_ip, uint8_t i_usgr, uint32_t i_pauses) {
//i_operation 1 = block on, -1 = block off, 2 = pause on, -2 = pause off
    axt_htb_htuser_usr_p			l_user;
	uint64_t						l_new_jf, l_pause;
	struct 	hlist_head 				*l_head;
    struct 	hlist_node 				*l_next;
	uint32_t 						i, l_kcnt;
	
	//	uint32_t 						l_ip = i_ip;
	//printk(KERN_INFO "xt_ANAT DBG: CMD_NAT_xxx  op: %d, sec: %d fip: %d, fusgr: %d => %pI4 +%02d\n", 
	//			i_operation, i_pauses, i_fip, i_fusgr, &l_ip, i_usgr);
   
    if (axt_ht_users == NULL) {
        printk(KERN_WARNING "xt_ANAT ERROR: CMD_NAT_xxx BUG found null ptr for axt_ht_users.\n");
		axt_cnt_inc(&cnt_mem_bugs);					
        return;
    }
	l_kcnt = 0;
	l_new_jf = get_jiffies_64()+i_pauses*HZ ;
	
    for (i = 0; i < axt_iprm_htb_USER_HTSZ; i++) {
  		l_head = &axt_ht_users[i].user;
		hlist_for_each_entry_safe(l_user, l_next, l_head, list_node) {
			if ( (READ_ONCE(l_user->idle) >= 15) || ((i_fip!=0) && (i_ip != l_user->addr)) || ((i_fusgr!=0) && (i_usgr != l_user->usgr)) )  continue;
			l_pause = READ_ONCE(l_user->pause_to_jif64);
			if (i_operation == -1) {
				if (l_pause == ~0) WRITE_ONCE(l_user->pause_to_jif64, 0);
			} else if (i_operation == -2) {
				if (l_pause != ~0) WRITE_ONCE(l_user->pause_to_jif64, 0);
			} else if (i_operation == 1) {
				WRITE_ONCE(l_user->pause_to_jif64, ~0);
			} else {
				if (l_pause != ~0) WRITE_ONCE(l_user->pause_to_jif64, l_new_jf);
			}
		}
    }
 	printk(KERN_INFO "xt_ANAT INFO: CMD_NAT_xxx - SUCCESSFUL user processed: %d. Operation: %d. Pause sec: %d.\n", l_kcnt, i_operation, i_pauses);
}

// timers for htables init | done
static void 	axt_htm_timers_setup(void) {
    spin_lock_bh(&axt_htm_sessions_timer_lock);
    timer_setup( &axt_htm_sessions_cleanup_timer, axt_htm_sessions_cleanup_timer_callback, 0 );
    mod_timer( &axt_htm_sessions_cleanup_timer, jiffies + msecs_to_jiffies(10 * 1000) ); //first time start after 10 seconds of startup 
    spin_unlock_bh(&axt_htm_sessions_timer_lock);

    spin_lock_bh(&axt_htm_users_timer_lock);
    timer_setup( &axt_htm_users_cleanup_timer, axt_htm_users_cleanup_timer_callback, 0 );
    mod_timer( &axt_htm_users_cleanup_timer, jiffies + msecs_to_jiffies(60 * 1000) ); //first time start after 60 seconds of startup 
    spin_unlock_bh(&axt_htm_users_timer_lock);
}

static void 	axt_htm_timers_del(void) {
    spin_lock_bh(&axt_htm_sessions_timer_lock);
    spin_lock_bh(&axt_htm_users_timer_lock);
    del_timer_sync( &axt_htm_sessions_cleanup_timer );
    del_timer_sync( &axt_htm_users_cleanup_timer );
    spin_unlock_bh(&axt_htm_sessions_timer_lock);
    spin_unlock_bh(&axt_htm_users_timer_lock);
}


/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */