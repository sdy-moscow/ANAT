/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01



*/ 

#ifndef SDY_PKC_F_T_xt_ANAT_pc_cnt
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_cnt 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xt_ANAT_pc_cnt */

#ifndef SDY_PKC_F_V_xt_ANAT_pc_cnt
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_cnt 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

static atomic64_t cnt_st_users_active     = ATOMIC_INIT(0); //ST_UACTV "Active Users: %ld\n"
static atomic64_t cnt_st_sessions_active  = ATOMIC_INIT(0); //ST_SACTV "Active NAT sessions: %ld\n"
static atomic64_t cnt_st_sessions_tried   = ATOMIC_INIT(0);	//ST_STRYD "Tried NAT sessions: %ld\n"
static atomic64_t cnt_st_sessions_triedfp = ATOMIC_INIT(0);	//ST_STRFP "Tried false parallel NAT sessions: %ld\n"
static atomic64_t cnt_st_sessions_blocked = ATOMIC_INIT(0);	//ST_STRBL "Tried on blocked/paused users NAT sessions: %ld\n"
static atomic64_t cnt_st_sessions_created = ATOMIC_INIT(0);	//ST_SCRED "Created NAT sessions: %ld\n"
static atomic64_t cnt_st_sessions_static  = ATOMIC_INIT(0);	//ST_SSTAT "Static map NAT sessions: %ld\n"
	
static atomic64_t cnt_usr_mslimit = ATOMIC_INIT(0); 		//OV_MSLIM "Too much hashes sessions 1 proto for 1 user (>1k) events: %ld\n"
static atomic64_t cnt_usr_exlimit = ATOMIC_INIT(0); 		//OV_EXLIM "User exceed max allowed sessions events: %ld\n"
static atomic64_t cnt_nat_noaddr  = ATOMIC_INIT(0); 		//OV_NFPRT "Not founds nat address for user: %ld\n"

static atomic64_t cnt_ht_mhusers = ATOMIC_INIT(0); 			//HT_MHUSR "Too much hashes (>ANT_CNT_HT_TOOMUCH_LM) in ht_users element: %ld\n"
static atomic64_t cnt_ht_mhinner = ATOMIC_INIT(0); 			//HT_MHINR "Too much hashes (>ANT_CNT_HT_TOOMUCH_LM) in ht_inner element: %ld\n"
static atomic64_t cnt_ht_mhouter = ATOMIC_INIT(0); 			//HT_MHOUR "Too much hashes (>ANT_CNT_HT_TOOMUCH_LM) in ht_outer element: %ld\n"
static atomic64_t cnt_ht_husersm = ATOMIC_INIT(0); 			//HT_USRMX "Max count hashes in ht_users element: %ld\n"
static atomic64_t cnt_ht_hinnerm = ATOMIC_INIT(0); 			//HT_INRMX "Max count hashes in ht_inner element: %ld\n"
static atomic64_t cnt_ht_houterm = ATOMIC_INIT(0); 			//HT_OURMX "Max count hashes in ht_outer element: %ld\n"

static atomic64_t cnt_nf9_sockerr 		 = ATOMIC_INIT(0); 	//N9_SCKER "Net flow socket errors: %ld\n"
static atomic64_t cnt_nf9_senderr 		 = ATOMIC_INIT(0); 	//N9_SCKER "Net flow send errors: %ld\n"
static atomic64_t cnt_nf9_speedup    	 = ATOMIC_INIT(0);  //N9_SPDPK "Net flow speed up send needed pkts: %ld\n"
static atomic64_t cnt_nf9_speedup_act 	 = ATOMIC_INIT(0);  //N9_SPDAC "Net flow speed up send activated: %ld\n"
static atomic64_t cnt_nf9_rb_overload 	 = ATOMIC_INIT(0);  //N9_RBOVR "Net flow ring buffer overflow error: %ld\n"
static atomic64_t cnt_nf9_sended_pk 	 = ATOMIC_INIT(0);  //N9_SNDPK "Net flow sended nf9 udp packets: %ld\n"
//atomic64_read(&axt_nf9_rb_get_actRb()->ihead)				//N9_EVNHD "Net flow ring buffer head count
//atomic64_read(&axt_nf9_rb_get_actRb()->itail)				//N9_EVNTL "Net flow ring buffer tail count

static atomic64_t cnt_mem_bugs    = ATOMIC_INIT(0);   		//MM_ERBAG "Bugs managment errors find (BUGS): %ld\n"
static atomic64_t cnt_mem_enomempk = ATOMIC_INIT(0); 		//MM_NOMPW "Not enough memory during packets work: %ld\n"

static atomic64_t cnt_pkt_allint 	   = ATOMIC_INIT(0); 	//PK_CNINT "Packets count internall (from user): %ld\n"
static atomic64_t cnt_pkt_allext 	   = ATOMIC_INIT(0); 	//PK_CNEXT "Packets count externall (to user): %ld\n" %ld\n"
static atomic64_t cnt_pkt_bytint 	   = ATOMIC_INIT(0); 	//PK_BTINT "Packets bytes internall (from user): %ld\n"
static atomic64_t cnt_pkt_bytext 	   = ATOMIC_INIT(0); 	//PK_BTEXT "Packets bytes externall (to user): %ld\n" %ld\n"
static atomic64_t cnt_pkt_wfrags 	   = ATOMIC_INIT(0); 	//PK_WFRAG "Wrong fragmentation packets: %ld\n"
static atomic64_t cnt_pkt_wproto 	   = ATOMIC_INIT(0); 	//PK_WPROT "Wrong protocol use packets: %ld\n"
static atomic64_t cnt_pkt_wtrunc 	   = ATOMIC_INIT(0); 	//PK_WTRUN "Wrong truncated packets: %ld\n"
static atomic64_t cnt_pkt_dnat_nofnd   = ATOMIC_INIT(0);	//PK_NOFND "DNAT dropped (NAT ses not found) pkts: %ld\n"
static atomic64_t cnt_pkt_frags        = ATOMIC_INIT(0);	//PK_FRERR "Fragmented pkts: %ld\n"
static atomic64_t cnt_pkt_related_icmp = ATOMIC_INIT(0);	//PK_RICMP "Related ICMP pkts: %ld\n" 

static atomic64_t cnt_fps_ft000 = ATOMIC_INIT(0); 			//FP_FT000 "Free port search try: %ld\n"
static atomic64_t cnt_fps_ft001 = ATOMIC_INIT(0); 			//FP_FT001 "Free port 1 search 1 try >1 line : %ld\n"
static atomic64_t cnt_fps_ft002 = ATOMIC_INIT(0); 			//FP_FT002 "Free port 1 search 2 try (1*2 step 8-512): %ld\n"
static atomic64_t cnt_fps_ft003 = ATOMIC_INIT(0); 			//FP_FT003 "Free port 1 search 3 try (1*3 step 8-512): %ld\n"
static atomic64_t cnt_fps_ft009 = ATOMIC_INIT(0); 			//FP_FT009 "Free port 1 search 9 try (2*1 step 8-512): %ld\n"
static atomic64_t cnt_fps_st001 = ATOMIC_INIT(0); 			//FP_ST001 "Free port f search 1 try ( 1k fast): %ld\n"
static atomic64_t cnt_fps_st003 = ATOMIC_INIT(0); 			//FP_ST003 "Free port f search 3 try ( 4k fast): %ld\n" //NOT PRINT NOW
static atomic64_t cnt_fps_stnfd = ATOMIC_INIT(0); 			//FP_NOFND "Free port not found all try : %ld\n"



/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xt_ANAT_pc_cnt */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_cnt
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_cnt 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

// inc counters 
static inline void 	axt_cnt_inc(atomic64_t *i_cnt_var) {
	atomic64_inc(i_cnt_var);
}

static inline void 	axt_cnt_add(atomic64_t *i_cnt_var, int64_t i_add ) {
	atomic64_add(i_add, i_cnt_var);
}

static inline void	axt_cnt_dec(atomic64_t *i_cnt_var) {
	atomic64_dec(i_cnt_var);
}  

static inline void 	axt_cnt_setmax(atomic64_t *i_cnt_var, const int64_t i_val) {
	// SDY WARNING IT CAN MAKE SOME COLLISION IN STATISTIC IN PARALLEL UPDATE! but it does not so needed accuracy here
	if ( i_val > atomic64_read(i_cnt_var) ) atomic64_set(i_cnt_var, i_val);  
}  

// reset counters by /proc/../config << [COMMANDS]

static void 	axt_cnt_reset_pk(void) {
	atomic64_set(&cnt_pkt_allint, 0);
	atomic64_set(&cnt_pkt_allext, 0);
	atomic64_set(&cnt_pkt_bytint, 0);
	atomic64_set(&cnt_pkt_bytext, 0);
	atomic64_set(&cnt_pkt_wfrags, 0);
	atomic64_set(&cnt_pkt_wproto, 0);
	atomic64_set(&cnt_pkt_wtrunc, 0);
	atomic64_set(&cnt_pkt_dnat_nofnd, 0);
	atomic64_set(&cnt_pkt_frags,  0);
	atomic64_set(&cnt_pkt_related_icmp, 0);
}

static void		axt_cnt_reset_fp(void) {
	atomic64_set(&cnt_fps_ft000, 0);
	atomic64_set(&cnt_fps_ft001, 0);
	atomic64_set(&cnt_fps_ft002, 0);
	atomic64_set(&cnt_fps_ft003, 0);
	atomic64_set(&cnt_fps_ft009, 0);
	atomic64_set(&cnt_fps_st001, 0);
	atomic64_set(&cnt_fps_st003, 0);
	atomic64_set(&cnt_fps_stnfd, 0);
}

static void		axt_cnt_reset_ht(void) {
	atomic64_set(&cnt_ht_mhusers, 0);	
	atomic64_set(&cnt_ht_mhinner, 0);	
	atomic64_set(&cnt_ht_mhouter, 0);	
	atomic64_set(&cnt_ht_husersm, 0);	
	atomic64_set(&cnt_ht_hinnerm, 0);	
	atomic64_set(&cnt_ht_houterm, 0);	
}

static void		axt_cnt_reset_ov(void) {
	atomic64_set(&cnt_usr_mslimit, 0);	
	atomic64_set(&cnt_usr_exlimit, 0);	
	atomic64_set(&cnt_nat_noaddr,  0);	
}

static void 	axt_cnt_reset_nf(void) {
	atomic64_set(&cnt_nf9_sockerr, 0);	
	atomic64_set(&cnt_nf9_senderr, 0);	
	atomic64_set(&cnt_nf9_speedup, 0);	
	atomic64_set(&cnt_nf9_speedup_act, 0);	
	atomic64_set(&cnt_nf9_rb_overload, 0);	
	atomic64_set(&cnt_nf9_sended_pk, 0);	
}

static void		axt_cnt_reset_er(void) {
	atomic64_set(&cnt_mem_bugs, 0);
	atomic64_set(&cnt_mem_enomempk, 0);
}

// counters print by /proc/.../statistics >>
static int		axt_cnt_stat_seq_show(struct seq_file *m, void *v) {
	seq_printf(m, "ST_UACTV: %ld -- Active Users\n", atomic64_read(&cnt_st_users_active));
	seq_printf(m, "ST_SACTV: %ld -- Active NAT sessions\n", atomic64_read(&cnt_st_sessions_active));
	seq_printf(m, "ST_STRYD: %ld -- Tried NAT sessions\n", atomic64_read(&cnt_st_sessions_tried));
	seq_printf(m, "ST_STRFP: %ld -- Tried false parallel NAT sessions\n", atomic64_read(&cnt_st_sessions_triedfp));
	seq_printf(m, "ST_STRBL: %ld -- Tried on blocked/paused users NAT sessions\n", atomic64_read(&cnt_st_sessions_blocked));
	seq_printf(m, "ST_SCRED: %ld -- Created NAT sessions\n", atomic64_read(&cnt_st_sessions_created));
	seq_printf(m, "ST_SSTAT: %ld -- Static map NAT sessions\n", atomic64_read(&cnt_st_sessions_static));
	seq_printf(m, "\n");
	seq_printf(m, "OV_MSLIM: %ld -- Too much hashes sessions 1 proto for 1 user (>wrn) events\n", atomic64_read(&cnt_usr_mslimit)); 
	seq_printf(m, "OV_EXLIM: %ld -- User exceed max allowed sessions events\n", atomic64_read(&cnt_usr_exlimit));
	seq_printf(m, "OV_NFPRT: %ld -- Not founds nat address for user\n", atomic64_read(&cnt_nat_noaddr));
	seq_printf(m, "\n");
	seq_printf(m, "MS_EVCNT: %lld -- Meassges generated after freeze or start\n", axt_msg_message_count());
	seq_printf(m, "HT_MHUSR: %ld -- Too much hashes (>%d) in ht_users element\n", atomic64_read(&cnt_ht_mhusers),axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm));
	seq_printf(m, "HT_MHINR: %ld -- Too much hashes (>%d) in ht_inner element\n", atomic64_read(&cnt_ht_mhinner),axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm));
	seq_printf(m, "HT_MHOUR: %ld -- Too much hashes (>%d) in ht_outer element\n", atomic64_read(&cnt_ht_mhouter),axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm));
	seq_printf(m, "HT_USRMX: %ld -- Max count hashes in ht_users element\n", atomic64_read(&cnt_ht_husersm));
	seq_printf(m, "HT_INRMX: %ld -- Max count hashes in ht_inner element\n", atomic64_read(&cnt_ht_hinnerm));
	seq_printf(m, "HT_OURMX: %ld -- Max count hashes in ht_outer element\n", atomic64_read(&cnt_ht_houterm));
	seq_printf(m, "\n");
	seq_printf(m, "N9_SCKER: %ld -- Net flow socket errors\n", atomic64_read(&cnt_nf9_sockerr));
	seq_printf(m, "N9_SNDER: %ld -- Net flow send errors\n", atomic64_read(&cnt_nf9_senderr));
	seq_printf(m, "N9_SPDPK: %ld -- Net flow speed up send needed pkts\n", atomic64_read(&cnt_nf9_speedup));
	seq_printf(m, "N9_SPDAC: %ld -- Net flow speed up send activated\n", atomic64_read(&cnt_nf9_speedup_act));
	seq_printf(m, "N9_RBOVR: %ld -- Net flow ring buffer overflow error\n", atomic64_read(&cnt_nf9_rb_overload));
	seq_printf(m, "N9_SNDPK: %ld -- Net flow sended nf9 udp packets\n", atomic64_read(&cnt_nf9_sended_pk));
	seq_printf(m, "N9_EVNHD: %ld -- Net flow ring buffer head position\n", atomic64_read(&axt_nf9_rb_get_actRb()->ihead));
	seq_printf(m, "N9_EVNTL: %ld -- Net flow ring buffer tail position\n", atomic64_read(&axt_nf9_rb_get_actRb()->itail));
	seq_printf(m, "\n");
	seq_printf(m, "MM_ERBUG: %ld -- Bugs managment errors find (BUGS)\n", atomic64_read(&cnt_mem_bugs)); 
	seq_printf(m, "MM_NOMEM: %ld -- Not enough memory during packets work\n", atomic64_read(&cnt_mem_enomempk));
	seq_printf(m, "\n");
	seq_printf(m, "PK_CNINT: %ld -- Packets count internall (from users)\n", atomic64_read(&cnt_pkt_allint));
	seq_printf(m, "PK_CNEXT: %ld -- Packets count externall (to user)\n", atomic64_read(&cnt_pkt_allext));
	seq_printf(m, "PK_BTINT: %ld -- Packets bytes internall (from users)\n", atomic64_read(&cnt_pkt_bytint));
	seq_printf(m, "PK_BTEXT: %ld -- Packets bytes externall (to user)\n", atomic64_read(&cnt_pkt_bytext));
	seq_printf(m, "PK_WFRAG: %ld -- Wrong fragmentation packets\n", atomic64_read(&cnt_pkt_wfrags));
	seq_printf(m, "PK_WPROT: %ld -- Wrong protocol use packets\n", atomic64_read(&cnt_pkt_wproto));
	seq_printf(m, "PK_WTRUN: %ld -- Wrong truncated packets\n", atomic64_read(&cnt_pkt_wtrunc));
	seq_printf(m, "PK_NOFND: %ld -- DNAT Local forwarded (NAT ses not found) pkts\n", atomic64_read(&cnt_pkt_dnat_nofnd));
	seq_printf(m, "PK_FRERR: %ld -- Fragmented pkts\n", atomic64_read(&cnt_pkt_frags));
	seq_printf(m, "PK_RICMP: %ld -- Related (trafic control ext reply) ICMP pkts\n", atomic64_read(&cnt_pkt_related_icmp));
	seq_printf(m, "\n");
	seq_printf(m, "FP_FT000: %ld -- Free port search try\n", atomic64_read(&cnt_fps_ft000));
	seq_printf(m, "FP_FT001: %ld -- Free port 1 search 1 try >1 line\n", atomic64_read(&cnt_fps_ft001));
	seq_printf(m, "FP_FT002: %ld -- Free port 1 search 2 try (1*2 step 8-512)\n", atomic64_read(&cnt_fps_ft002));
	seq_printf(m, "FP_FT003: %ld -- Free port 1 search 3 try (1*3 step 8-512)\n", atomic64_read(&cnt_fps_ft003));
	seq_printf(m, "FP_FT009: %ld -- Free port 1 search 9 try (2*1 step 8-512)\n", atomic64_read(&cnt_fps_ft009));
	seq_printf(m, "FP_ST001: %ld -- Free port f search 1 try ( 1k fast)\n", atomic64_read(&cnt_fps_st001));
//	seq_printf(m, "FP_ST003: %ld -- Free port f search 3 try ( 4k fast)\n", atomic64_read(&cnt_fps_st003));
	seq_printf(m, "FP_NOFND: %ld -- Free port not found all try\n", atomic64_read(&cnt_fps_stnfd));
	return 0;
}

//  init|done|work /proc/.... entry  
 static int		axt_cnt_stat_seq_open(struct inode *inode, struct file *file) {
    return single_open(file, axt_cnt_stat_seq_show, NULL);
}

static const struct file_operations  axt_cnt_stat_seq_fops = {
    .open           = axt_cnt_stat_seq_open,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static void  axt_cnt_create_proc_fs(struct proc_dir_entry *i_dir_node) {
    proc_create("statistics", 0644, i_dir_node, &axt_cnt_stat_seq_fops);
}

static void  axt_cnt_remove_proc_fs(struct proc_dir_entry *i_dir_node) {
	remove_proc_entry( "statistics", i_dir_node );
}
/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_ANAT_pc_cnt */