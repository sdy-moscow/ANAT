/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
*/ 

/* we have 3 configuration sets - active and not active (reserve) wich used in work, and tmp used for loading only
   we can change not active config in RCU paradigm only it is unused (free) more than some time (AXT_CFG_MIN_FREETIME)
   to set config we loading new config in tmp config (it never used and safety for load)
   after that we copy tmp to inactive and unused config by [CMD_CONFIG_TMPTOINA] and after it we must do [CMD_CONFIG_SWAP] to activate config
*/

/* config file format v.2.0. (for more information look desription at the END of this file  
# if [CFG_NATPOLL_V2_0] or [CFG_NF9DEST_V2_0] not present it will be copy from ACTIVE config
# if [LOAD_TMP_CONFIG_V2_0] not present TMP config will not be changed
# [CMD_CONFIG_TMPTOINA] [CMD_CONFIG_SWAP] - can be sent in another >> 
# [CMD_xxx] can be not present, for commands description see help

[CMD_xxx]
...
[LOAD_TMP_CONFIG_V2_0]
[CFG_NATPOLL_V2_0]
# usr_ip_start - usr_ip_end : nat_ip_start - nat_ip_end
<xx.xx.xx.xx> - <xx.xx.xx.xx> : <xx.xx.xx.xx> - <xx.xx.xx.xx>
... 
[CFG_NATPOLL_END]
[CFG_NF9DEST_V2_0]
# dest_ip : dest_port 
<xx.xx.xx.xx> : <xxx>
... 
[CFG_NF9DEST_END]
[LOAD_TMP_CONFIG_END]
[CMD_CONFIG_TMPTOINA]
[CMD_CONFIG_SWAP]
[CMD_SET_PRM_<T>: <PARAM_NAME> = <VALUE> ]
[CMD_xxx]
*/

/*
use: https://www.kernel.org/doc/html/latest/core-api/kernel-api.html
event buffers with /proc/..
setup murgins for htaibles
setup nf9 temlaite id, packet size, max time to send
*/

#ifndef SDY_PKC_F_T_xt_ANAT_pc_config
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_config 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

#define AXT_CFG_NATPOOL_REC_MAX 100
#define AXT_CFG_NF9DEST_REC_MAX 10
#define AXT_CFG_MIN_FREETIME 3

#define isdigit(c) ('0' <= (c) && (c) <= '9')

struct axt_cfg_natpool_rec_s {
	uint32_t 				usrip_start;
	uint32_t 				usrip_end;
	uint32_t				natip_start;
	uint32_t 				natip_end;
	uint32_t 				mark;      	//mark value (if rule use mark !0 - the rule is ONLY for non marked trafic, if no !mark - rule is for all trafic)
	uint32_t 				marked;		//bool is !mark use in this line
	uint32_t 				hashtype;	//0 - linear (reciprocal_scale only) 1-hash (jhash+reciprocal_scale)
	uint32_t 				exclude;	//0 - use all nat ir, 1- exclude x.x.x.0 (move to x.1), '2'- exclude x.x.x.255 (move to x.254), '3'- both (1) and (2)),
	uint8_t  				trch;	  	//trace_code for trace packets to msg: <C>-one char from 'A' to 'Z', default = '@' (store as charcode(C) - 40, 0=='@')
    uint8_t  				usgr;  		//user group number 0 - default  
	
}; 
typedef struct axt_cfg_natpool_rec_s 	axt_cfg_natpool_rec_t; 

struct axt_cfg_nf9dest_rec_s {
	uint32_t 				d_ip;
	uint16_t 				d_port;
};
typedef struct axt_cfg_nf9dest_rec_s	axt_cfg_nf9dest_rec_t;

struct axt_cfg_lconfig_s {
	int 					natpool_cnt;
	axt_cfg_natpool_rec_t 	natpool_arr[AXT_CFG_NATPOOL_REC_MAX];
	int		 				nf9dest_cnt;
	axt_cfg_nf9dest_rec_t 	nf9dest_arr[AXT_CFG_NF9DEST_REC_MAX];
	uint64_t				cfg_freetime;		// jiffies form start in seconds
}; 
typedef struct axt_cfg_lconfig_s		axt_cfg_lconfig_t;

//----------------------
struct axt_cfg_x_trfl_ip_s {
	int32_t					addr_f;			//filter ON on addr
	int32_t					port_f;			//filter ON on port
	uint32_t 				addr_s;			//addr (ip) start 
	uint32_t 				addr_e;			//addr (ip) end 
	uint32_t 				port_s;			//port start 	
	uint32_t 				port_e;			//port end 
};
typedef struct axt_cfg_x_trfl_ip_s		axt_cfg_x_trfl_ip_t;
typedef struct axt_cfg_x_trfl_ip_s*		axt_cfg_x_trfl_ip_p;
	
struct axt_cfg_xconfig_s {
	uint32_t				nattest_ip_u;	//htonl test nat ip user addr (= 0- off)
	uint32_t				nattest_ip_n;	//htonl test nat ip nat addr
	uint8_t					nattest_ip_ug;	//test nat ip user group
	uint8_t					nattest_ip_tc;  //test nat ip user trace char
	uint32_t				tr_enable;		//trace enable (used as mask FF..)
	uint32_t				tr_bset;		//trace on bit set 0-'@' 26-'Z'
	int32_t					trus_enable;	//bool user trace enable
	int32_t					trus_fip;		//bool user trace filter on by ip (trus_ip) 
	int32_t					trus_fug;		//bool user trace filter on by u(ser) g(roup) (trus_ug) 
	uint32_t 				trus_ip;		//is htonl
	uint8_t 				trus_ug;		//ug for trace filter
	uint32_t 				tr_outdrop;		//enable trace on out dropped trafic (usr limit or block)
	uint32_t 				tr_locfrwd;		//enable trace on local forward trafic (DNAT session not found)
	
	uint32_t 				trfl_on;		//extended trace filter status (work slowly!) not hton!
	
	int32_t					trfl_proto_f;	//ON on PROTO
	uint32_t				trfl_proto_s;	//proto start 
	uint32_t				trfl_proto_e;	//proto end 
	int32_t					trfl_pksz_f;	//ON on PKSZ
	uint32_t				trfl_pksz_s;	//proto start 
	uint32_t				trfl_pksz_e;	//proto end 
	int32_t					trfl_dir_f;		//direction 0 - both, 1-IN (DNAT) 2-OUT (SNAT)
	int32_t					trfl_res_f;		//direction 0 - both, 1-DROP 2-ACCEPT
	
	axt_cfg_x_trfl_ip_t		trfl_u;			//USER
	axt_cfg_x_trfl_ip_t		trfl_n;			//NAT
	axt_cfg_x_trfl_ip_t		trfl_d;			//DEST
	axt_cfg_x_trfl_ip_t		trfl_s;			//SESSION DEST
};
typedef struct axt_cfg_xconfig_s				axt_cfg_xconfig_t;

//----------------------
struct axt_cfg_uconfig_cnt_s {
	int32_t					c_tcp;			// if =-1 use default from axt_aprm_htb_usr_maxss or axt_aprm_htb_usr_wrnss
	int32_t					c_udp;
	int32_t					c_icm;
	int32_t					c_oth;	
};
typedef struct axt_cfg_uconfig_cnt_s			axt_cfg_uconfig_cnt_t;
typedef struct axt_cfg_uconfig_cnt_s*			axt_cfg_uconfig_cnt_p;

struct axt_cfg_uconfig_s {
	axt_cfg_uconfig_cnt_t	max[64];
	axt_cfg_uconfig_cnt_t	wrn[64];
	uint64_t				mfl_max;		//bit flag message 1=on max limit 0-messages off
	uint64_t				mfl_wrn;		//bit flag message 1=on wrn limit 0-messages off
};
typedef struct axt_cfg_uconfig_s				axt_cfg_uconfig_t;

/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_config
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_config 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

/* 
	config RCU crated like 3 points entry in array ( [1..2] - ACTIVE/INACTIVE [0] - tmp config for load controle 
	we can change it only if anused interval (cfg_freetime) > AXT_CFG_MIN_FREETIME
*/

static axt_cfg_lconfig_t		axt_config[3];
static atomic_t 				axt_config_actn  = ATOMIC_INIT(0); //1..2 if config loaded
static int						axt_config_tmp_load_er = 1; // 0- TMP config loaded sucsesfull and can be used, <0 - TMP loaded with error Exxx, 1- TMP not loaded 
static int						axt_config_tmp_load_erln;   // line num in config file with error 
static DEFINE_SPINLOCK(			axt_config_load_lock);

static axt_cfg_xconfig_t 		axt_xcfg = {0};
static axt_cfg_uconfig_t 		axt_ucfg = {0}; 
//forawrd declaration
static axt_cfg_lconfig_t 		*axt_cfg_get_actConfig(void);

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_config
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_config 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */
//----------------- functions axt_ucfg user group work
static  void 	axt_cfg_u_init(void) {
	int i;
	for (i = 0; i < 64; i++) {
		axt_ucfg.max[i].c_tcp = -1;  axt_ucfg.wrn[i].c_tcp = -1;
		axt_ucfg.max[i].c_udp = -1;  axt_ucfg.wrn[i].c_udp = -1;
		axt_ucfg.max[i].c_icm = -1;  axt_ucfg.wrn[i].c_icm = -1;
		axt_ucfg.max[i].c_oth = -1;  axt_ucfg.wrn[i].c_oth = -1;
	}
	axt_ucfg.mfl_max = ~0;	axt_ucfg.mfl_wrn = ~0;
}

static inline void 	axt_cfg_u_m_set(int i_type, uint8_t i_ug, int i_val) { //i_type = 0 - wrn 1 - max
	uint64_t* l_pv  = (i_type == 0 ? &axt_ucfg.mfl_wrn : &axt_ucfg.mfl_max);
	uint64_t  l_bit = (1 << i_ug);
	WRITE_ONCE( *l_pv, (READ_ONCE(*l_pv) | (l_bit)) ^ ((i_val) ? 0 : l_bit) );
}

static inline int 	axt_cfg_u_m_ison(const int i_type, uint8_t i_ug) { //i_type = 0 - wrn 1 - max
//return bool is message bit on for i_ug
	uint64_t* l_pv = (i_type == 0 ? &axt_ucfg.mfl_wrn : &axt_ucfg.mfl_max);
	return ( (READ_ONCE(*l_pv) & (1 << i_ug)) != 0);
}


//----------------- functions axt_xcfg trace packets work
// trace char working 
static inline void 	axt_cfg_x_tr_onn(uint8_t i_trch) {
	WRITE_ONCE(axt_xcfg.tr_bset, READ_ONCE(axt_xcfg.tr_bset) |  (1 << i_trch));
}

static inline void 	axt_cfg_x_tr_off(uint8_t i_trch) {
	WRITE_ONCE(axt_xcfg.tr_bset, READ_ONCE(axt_xcfg.tr_bset) & ~(1 << i_trch));
}

static inline void 	axt_cfg_x_tr_on_all(void) {
	WRITE_ONCE(axt_xcfg.tr_bset, ~0);
}
static inline void 	axt_cfg_x_tr_off_all(void) {
	WRITE_ONCE(axt_xcfg.tr_bset,  0);
}

static inline int 	axt_cfg_x_tr_state(uint8_t i_trch) {
//return bool is trace bit on for i_trch
	return ( (READ_ONCE(axt_xcfg.tr_bset) & (1 << i_trch)) != 0);
}

static inline void 	axt_cfg_x_tr_enable(void) {
	WRITE_ONCE(axt_xcfg.tr_enable, ~0);
}

static inline void 	axt_cfg_x_tr_disable(void) {
	WRITE_ONCE(axt_xcfg.tr_enable, 0);
}

static inline int 	axt_cfg_x_tr_isenabled(void) {
	return ( READ_ONCE(axt_xcfg.tr_enable) != 0 );
}

static inline int 	axt_cfg_x_tr_ison(uint8_t i_trch) {
//return true if trace bit on for i_trch and trace enabled
	return ( (READ_ONCE(axt_xcfg.tr_bset) & READ_ONCE(axt_xcfg.tr_enable) & (1 << i_trch)) != 0);
}	

//---- out droped & local forwarded trafic trace

static inline void 	axt_cfg_x_tr_outdrop_set(int i_state) {
	WRITE_ONCE(axt_xcfg.tr_outdrop, i_state);
}

static inline int 	axt_cfg_x_tr_outdrop_ison(void) {
	return READ_ONCE(axt_xcfg.tr_outdrop);
}

static inline void 	axt_cfg_x_tr_locfrwd_set(int i_state) {
	WRITE_ONCE(axt_xcfg.tr_locfrwd, i_state);
}

static inline int 	axt_cfg_x_tr_locfrwd_ison(void) {
	return READ_ONCE(axt_xcfg.tr_locfrwd) ;
}

//---- trace advanced filter

static inline void 	axt_cfg_x_tr_filter_set(int i_state) {
	WRITE_ONCE(axt_xcfg.trfl_on, i_state);
}

static inline int 	axt_cfg_x_tr_filter_ison(void) {
	return READ_ONCE(axt_xcfg.trfl_on) ;
}		
	
static inline int 	axt_cfg_x_tr_filter_chkhdr_ison(uint32_t i_proto, uint32_t i_pksz, uint8_t i_tflags) {
	int32_t		l_var;
	if (unlikely( (READ_ONCE(axt_xcfg.trfl_proto_f) != 0) 
				&& ((i_proto < READ_ONCE(axt_xcfg.trfl_proto_s)) || (i_proto > READ_ONCE(axt_xcfg.trfl_proto_e))) )) return 0;
	if (unlikely( (READ_ONCE(axt_xcfg.trfl_pksz_f) != 0)  
				&& ((i_pksz  < READ_ONCE(axt_xcfg.trfl_pksz_s))  || (i_pksz  > READ_ONCE(axt_xcfg.trfl_pksz_e)))  )) return 0;
	if (unlikely( ((l_var = READ_ONCE(axt_xcfg.trfl_dir_f)) != 0)  && (l_var != ((i_tflags & AXT_MSG_TRF_DIRECT) == 0 ? 1 : 2)) )) return 0;
	if (unlikely( ((l_var = READ_ONCE(axt_xcfg.trfl_res_f)) != 0)  && (l_var != ((i_tflags & AXT_MSG_TRF_RESULT) == 0 ? 1 : 2)) )) return 0;
	return 1;
}

static int 	axt_cfg_x_tr_filter_chkipf_ison(axt_cfg_x_trfl_ip_p i_ipf, uint32_t i_addr, uint32_t i_port) {
	if (unlikely( (READ_ONCE(i_ipf->addr_f) != 0) && ((i_addr < READ_ONCE(i_ipf->addr_s)) || (i_addr > READ_ONCE(i_ipf->addr_e))) )) return 0;
	if (unlikely( (READ_ONCE(i_ipf->port_f) != 0) && ((i_port < READ_ONCE(i_ipf->port_s)) || (i_port > READ_ONCE(i_ipf->port_e))) )) return 0;
	return 1;
}	

static inline int  	axt_cfg_x_tr_changechar(char i_ctrch, int i_oper, int i_line) {
	if ((i_ctrch<'@') || (i_ctrch>'Z')) { 
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong trace char in [CMD_TRACE_xx_<X>] in line [%d]. Use <X> = '@'-'Z'.\n", i_line);
		return -EINVAL;
	}
	if (i_oper) axt_cfg_x_tr_onn( ((uint8_t) i_ctrch) - 0x40 ); else  axt_cfg_x_tr_off( ((uint8_t) i_ctrch) - 0x40 );
	return 0;
} 

//---- user trace

static inline int 	axt_cfg_x_trus_state(int *v_fip, int *v_fug, uint32_t *v_ip, uint8_t *v_ug ) {
//return true if enabled, and if enabled filter states 
	if (READ_ONCE(axt_xcfg.trus_enable) == 0) return 0;
	*v_fip 	= READ_ONCE(axt_xcfg.trus_fip);
	*v_fug 	= READ_ONCE(axt_xcfg.trus_fug);	
	*v_ip	= READ_ONCE(axt_xcfg.trus_ip);	
	*v_ug 	= READ_ONCE(axt_xcfg.trus_ug);
	return 1;
}		

static inline int 	axt_cfg_x_trus_ison( uint32_t i_ip, uint8_t i_ug) {
//check is trace for user is on
	return ( (READ_ONCE(axt_xcfg.trus_enable) == 1) && 
			(READ_ONCE(axt_xcfg.trus_fip) == 0 || i_ip == READ_ONCE(axt_xcfg.trus_ip)) && 
			(READ_ONCE(axt_xcfg.trus_fug) == 0 || i_ug == READ_ONCE(axt_xcfg.trus_ug)) );
}

static inline void 	axt_cfg_x_trus_clear(void) {
	WRITE_ONCE(axt_xcfg.trus_enable, 0);
}		

static inline void 	axt_cfg_x_trus_set(int i_fip, int i_fug, uint32_t i_ip, uint8_t i_ug) {
	WRITE_ONCE(axt_xcfg.trus_enable, 0);
	wmb();
	WRITE_ONCE(axt_xcfg.trus_fip, i_fip);
	WRITE_ONCE(axt_xcfg.trus_fug, i_fug);	
	WRITE_ONCE(axt_xcfg.trus_ip,  i_ip);	
	WRITE_ONCE(axt_xcfg.trus_ug,  i_ug);
	wmb();
	WRITE_ONCE(axt_xcfg.trus_enable, (i_fip || i_fug));
}
		
static  int  axt_cfg_docmd_TraceUser(char* i_trbuf, int i_line) {
//implemet '[CMD_TRACE_USER_ON <IP> [+<UG>] | +<UG> ]' &  [CMD_TRACE_USER_OFF]	
// return 0 on ok or error code 
	char			*s, *s_to;
	int 			l_fip, l_fug;
	uint32_t 		l_ip;
	uint8_t 		l_ug;
	
	if (strcmp( i_trbuf, "[CMD_TRACE_USER_OFF]")  == 0)  { axt_cfg_x_trus_clear(); return 0; }
	if (strncmp( i_trbuf, "[CMD_TRACE_USER_ON ",19 )  != 0)  {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd begin [CMD_TRACE_USER_ON <IP [+UG] | +UG >] in line [%d].\n", i_line);
		return -EINVAL;
	}
	s = &i_trbuf[19];
	s_to = &i_trbuf[strnlen(i_trbuf,AXT_MAX_LINELEN)];
	
	l_fip = axt_wst_take_ip4h(s, s_to, &s, &l_ip); 
	l_fug = axt_wst_take_usgr(s, s_to, &s, &l_ug);
	if ((l_fip != 1) && (l_fug!=1)) {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_USER_ON <IP [+UG] | +UG >] both IP and UG not given or incorrect in line [%d].\n", i_line);
		return -EINVAL;
	}		
	s = axt_wst_posltrim(s, s_to);	
	if (strcmp (s,"]") !=0)  {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_USER_ON <IP [+UG] | +UG >] some garbage or wrong params order in line [%d].\n", i_line);
		return -EINVAL;
	}
	axt_cfg_x_trus_set((l_fip==1), (l_fug==1), htonl(l_ip), l_ug);
	return 0;
}					

static  int  axt_cfg_docmd_TraceFilter(char* i_trbuf, int i_line) {
//implemet '[CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]]'
//implemet '[CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]] ]'
// if no data in CMD SET - filter clear	
// return 0 on ok or error code 
	char					*s, *s_to;
	int 					l_fvl, l_fvs, l_dir_f, l_res_f, l_len;
	uint32_t 				l_vl1, l_vl2, l_val1 ;
	uint16_t				l_vs1, l_vs2; 
	axt_cfg_x_trfl_ip_p		l_pipf;
	
	l_len = strnlen(i_trbuf,AXT_MAX_LINELEN);
	if ( (l_len <  24) || (strncmp( i_trbuf, "[CMD_TRACE_FILTER_SET_",22 )  != 0) ) { 
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd format [CMD_TRACE_FILTER_SET_{P|U|N|D|S}] in line [%d].\n", i_line);
		return -EINVAL;
	}

	l_fvl = 0; l_fvs = 0; l_vl1 =0; l_vl2 = 0; l_vs1 = 0; l_vs2 = 0; l_dir_f = 0;  l_res_f = 0;
	s_to = &i_trbuf[l_len];
	s = axt_wst_posltrim(&i_trbuf[23], s_to);	
	if (i_trbuf[22]=='P') {
		//implemet '[CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]]'
		if (strcmp (s,"]") != 0)  { //not empty 
			if ((l_fvs = axt_wst_take_proto(s, s_to, &s, &l_vs1)) < 0) {  //proto 
					printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [pT|pU|pI|pO|p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in pX|p<pr> in line [%d].\n", i_line);
					return -EINVAL;
			} else if (l_fvs == 1) {
				s = axt_wst_posltrim(s, s_to);	
				if (s[0] == '-') {
					if ( l_vs1 == 256 ) { //pO other can't be used with '-'
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P  pO [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] use <pr_e> with pO in line [%d].\n", i_line);
						return -EINVAL;
					}
					if ( ((axt_wst_take_uint32(++s, s_to, &s, &l_val1)) != 1) || ((l_vs2 = (uint8_t) (l_val1)) != l_val1) ) {
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in <pr_e> in line [%d].\n", i_line);
						return -EINVAL;
					}
				} else l_vs2 = l_vs1;
			}
			
			s = axt_wst_posltrim(s, s_to);	
			if (s[0] == 's') { //pksz 
				if ( ((l_fvl = axt_wst_take_uint32(++s, s_to, &s, &l_val1)) != 1) || ((l_vl1 = (uint16_t) (l_val1)) != l_val1) ) {
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [pT|pU|pI|pO|p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in <pksz> in line [%d].\n", i_line);
						return -EINVAL;
				}
				s = axt_wst_posltrim(s, s_to);	
				if (s[0] == '-') {
					if ( ((axt_wst_take_uint32(++s, s_to, &s, &l_val1)) != 1) || ((l_vl2 = (uint16_t) (l_val1)) != l_val1) ) {
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in <pksz_e> in line [%d].\n", i_line);
						return -EINVAL;
					}
				} else l_vl2 = l_vl1;
			}
			s = axt_wst_posltrim(s, s_to);	
			if (s[0] == 'd') { //direction 
				s++;
				if (s[0] == 'I') l_dir_f = 1;
				else if (s[0] == 'O') l_dir_f = 2;
				else if (s[0] == 'B') l_dir_f = 0;
				else {
					printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in d<X> (use X=I|O|B) in line [%d].\n", i_line);
					return -EINVAL;
				}
				s++;
			}
			s = axt_wst_posltrim(s, s_to);	
			if (s[0] == 'r') { //pksz 
				s++;
				if (s[0] == 'D') l_res_f = 1;
				else if (s[0] == 'A') l_res_f = 2;
				else if (s[0] == 'B') l_res_f = 0;
				else {
					printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] in r<X> (use X=D|A|B) in line [%d].\n", i_line);
					return -EINVAL;
				}
				s++;			
			}			
			s = axt_wst_posltrim(s, s_to);
			if (strcmp (s,"]") !=0)  {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_P [p<pr> [- <pr_e>]] [s<pksz> [- <pksz_e>]] [dI|O|B] [rD|A|B]] some garbage or wrong params order in line [%d].\n", i_line);
				return -EINVAL;
			}	
			WRITE_ONCE(axt_xcfg.trfl_dir_f,   l_dir_f);	WRITE_ONCE(axt_xcfg.trfl_res_f,   l_res_f);
			WRITE_ONCE(axt_xcfg.trfl_proto_f, 0);		WRITE_ONCE(axt_xcfg.trfl_pksz_f,  0); 
			wmb();	
			WRITE_ONCE(axt_xcfg.trfl_proto_s, l_vs1);	WRITE_ONCE(axt_xcfg.trfl_proto_e, l_vs2);
			WRITE_ONCE(axt_xcfg.trfl_pksz_s,  l_vl1);	WRITE_ONCE(axt_xcfg.trfl_pksz_e , l_vl2);
			wmb();
			WRITE_ONCE(axt_xcfg.trfl_proto_f, l_fvs);	WRITE_ONCE(axt_xcfg.trfl_pksz_f,  l_fvl); 			
		} else {
			WRITE_ONCE(axt_xcfg.trfl_proto_f, 0);	WRITE_ONCE(axt_xcfg.trfl_pksz_f, 0); //clear
			WRITE_ONCE(axt_xcfg.trfl_dir_f, 0);		WRITE_ONCE(axt_xcfg.trfl_res_f, 0);
		}
	} else {
		//implemet '[CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]] ]'
		if (i_trbuf[22] == 'U') {
			l_pipf = &axt_xcfg.trfl_u;
		} else if (i_trbuf[22] == 'N') {
			l_pipf = &axt_xcfg.trfl_n;
		} else if (i_trbuf[22] == 'D') {
			l_pipf = &axt_xcfg.trfl_d;
		} else if (i_trbuf[22] == 'S') {
			l_pipf = &axt_xcfg.trfl_s;
		} else {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd {P|U|N|D|S} in [CMD_TRACE_FILTER_SET_{P|U|N|D|S}] in line [%d].\n", i_line);
			return -EINVAL;
		}
		if (strcmp (s,"]") !=0)  { //not empty 
			if ((l_fvl = axt_wst_take_ip4h(s, s_to, &s, &l_vl1)) < 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]]] in <ip> in line [%d].\n", i_line);
				return -EINVAL;
			} else if (l_fvl == 1) {			
				s = axt_wst_posltrim(s, s_to);	
				if (s[0] == '-') {
					if ((axt_wst_take_ip4h(++s, s_to, &s, &l_vl2)) != 1) {
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]]] in <ip_e> in line [%d].\n", i_line);
						return -EINVAL;
					}
				} else l_vl2 = l_vl1;
			}
			if ((l_fvs = axt_wst_take_porth(s, s_to, &s, &l_vs1)) < 0) {
					printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]]] in <port> in line [%d].\n", i_line);
					return -EINVAL;
			} else if (l_fvs == 1) {
				s = axt_wst_posltrim(s, s_to);	
				if (s[0] == '-') {
					if ( ((axt_wst_take_uint32(++s, s_to, &s, &l_val1)) != 1) || ((l_vs2 = (uint16_t) (l_val1)) != l_val1) ) {
						printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]]] in <port_e> in line [%d].\n", i_line);
						return -EINVAL;
					}
				} else l_vs2 = l_vs1;
			} 
			s = axt_wst_posltrim(s, s_to);
			if (strcmp (s,"]") !=0)  {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TRACE_FILTER_SET_{U|N|D|S} [<ip> [- <ip_e>]] [: <port> [- <port_e>]]] some garbage or wrong params order in line [%d].\n", i_line);
				return -EINVAL;
			}	
			WRITE_ONCE(l_pipf->addr_f, 0);	WRITE_ONCE(l_pipf->port_f, 0); 
			wmb();			
			WRITE_ONCE(l_pipf->addr_s, l_vl1);	WRITE_ONCE(l_pipf->addr_e, l_vl2);
			WRITE_ONCE(l_pipf->port_s, l_vs1);	WRITE_ONCE(l_pipf->port_e, l_vs2);
			wmb();
			WRITE_ONCE(l_pipf->addr_f, l_fvl);	WRITE_ONCE(l_pipf->port_f, l_fvs);
		} else {
			WRITE_ONCE(l_pipf->addr_f, 0);	WRITE_ONCE(l_pipf->port_f, 0); //clear
		}
	}
	return 0;
}					

// --------------- session Kill command do 

static  int  axt_cfg_docmd_Kill(char* i_trbuf, int i_line) {
//implemet 	'CMD_KILL_USER <IP>[p<PROTO>][:PORT][+<UG>][^<T>]' & 'CMD_KILL_NAT <IP>[:port][+<UG>][^<T>]' & 'CMD_KILL_ALL [+<UG>][^<T>]'
// return 0 on ok or error code 
	char			*s, *s_to;
	int 			l_fport, l_fusgr, l_ftrch, l_opperation, l_ip_need, l_fproto, l_res;
	uint32_t 		l_ip;
	uint16_t 		l_port, l_proto;	
	uint8_t 		l_usgr, l_trch; 
	
	l_opperation = 0; l_ip_need = 0; l_fport = 0; l_fproto = 0;
	l_ip = 0; l_port = 0; l_proto = 0; l_usgr =0; l_trch=0;
	if (strncmp( i_trbuf,		"[CMD_KILL_USER ",15 ) == 0)  	{ l_opperation = 0; l_ip_need = 1; s = &i_trbuf[15];}
	else if (strncmp( i_trbuf,	"[CMD_KILL_NAT ",14 )  == 0)  	{ l_opperation = 1; l_ip_need = 1; s = &i_trbuf[14];}
	else if (strncmp( i_trbuf,	"[CMD_KILL_ALL ",14 )  == 0)  	{ l_opperation = 0; l_ip_need = 0; s = &i_trbuf[14];}
	else if (strcmp( i_trbuf,	"[CMD_KILL_ALL]") 	   == 0) 	{ axt_htm_ses_kill(0,0,0,0,0,0,0,0,0,0,0);	return 0;}
	else {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd begin '[CMD_KILL_XXX xxx]' in line [%d].\n", i_line);
		return -EINVAL;
	}
	s_to = &i_trbuf[strnlen(i_trbuf,AXT_MAX_LINELEN)];
	if (l_ip_need) {
		if ((l_res=axt_wst_take_ip4h(s, s_to, &s, &l_ip)) !=1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXXX <IP>[p<PROTO>][:PORT][+<UG>][^<T>]] IP not given or incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_res), i_line);
			return -EINVAL;
		}
		if ((l_fproto = axt_wst_take_proto(s, s_to, &s, &l_proto)) < 0) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXXX <IP>[p<PROTO>][:PORT][+<UG>][^<T>]] PORT format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_fproto), i_line);
			return -EINVAL;
		}	
		
		if ((l_fport = axt_wst_take_porth(s, s_to, &s, &l_port)) < 0) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXXX <IP>[p<PROTO>][:PORT][+<UG>][^<T>]] PORT format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_fport), i_line);
			return -EINVAL;
		}	
	}	 
	if ((l_fusgr = axt_wst_take_usgr(s, s_to, &s, &l_usgr)) < 0) {
		if (l_ip_need) 
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXXX <IP>[p<PROTO>][:PORT][+<UG>][^<T>]] U(ser)G(roup) format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_fusgr), i_line);
		else
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_ALL [+<UG>][^<T>]] U(ser)G(roup) format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_fusgr), i_line);
		return -EINVAL;
	}	
	if ((l_ftrch = axt_wst_take_trch(s, s_to, &s, &l_trch)) < 0) {
		if (l_ip_need) 
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXXX <IP>[p<PROTO>][:PORT][+<UG>][^<T>]] T(race char) format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_ftrch), i_line);
		else 
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_ALL [+<UG>][^<T>]] T(race char) format or value incorrect (%s) in line [%d].\n",
						axt_wst_ierror(l_ftrch), i_line);
		return -EINVAL;
	}		
	s = axt_wst_posltrim(s, s_to);	
	if (strcmp (s,"]") != 0)  {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_KILL_XXX xxx] some garbage or wrong params order in line [%d].\n", i_line);
		return -EINVAL;
	}
	axt_htm_ses_kill(l_opperation, l_ip_need, l_fproto, l_fport, l_fusgr, l_ftrch, htonl(l_ip), l_proto, htons(l_port), l_usgr, l_trch);
	return 0;
}				
// --------------- user groups limits and warning sets 	
static  int  axt_cfg_docmd_UsgrSet(char* i_trbuf, int i_line) {
//		USGR_SET_MAX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]   (<nnn> - num or 'D' - def) if not set - not changed - deafult 'D'
//		USGR_SET_WRN <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]  m-messages (- off, + on, def +) t-tcp, u-udp, i-icmp, o-other
// 		<UG> - user group or 'ALL'
	
	char					*s, *s_to;
	int 					l_fvl, l_fmax, l_len;
	int32_t					l_ms, l_tcp, l_udp, l_icm, l_oth;
	uint8_t 				l_usgr, l_ufrom, l_uto, i; 
	axt_cfg_uconfig_cnt_p	l_plim;
	
	l_len = strnlen(i_trbuf,AXT_MAX_LINELEN);
	if (l_len <  22) { 
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd format [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in line [%d].\n", i_line);
		return -EINVAL;
	}
	if ( (strncmp( i_trbuf, "[CMD_USGR_SET_MAX", 17)  == 0) ) l_fmax = 1;
	else if ( (strncmp( i_trbuf, "[CMD_USGR_SET_WRN",17)  == 0) ) l_fmax = 0;
	else {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] XXX not WRN or MAX  in line [%d].\n", i_line);
		return -EINVAL;
	}
	l_ms = -2; l_tcp = -2; l_udp = -2; l_icm = -2; l_oth = -2;
	s_to = &i_trbuf[l_len];
	s = axt_wst_posltrim(&i_trbuf[17], s_to);
	
	if ((l_fvl = axt_wst_take_usgr(s, s_to, &s, &l_usgr)) < 0) {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] U(ser)G(roup) format or value incorrect in line [%d].\n", i_line);
		return -EINVAL;
	} else if ( (l_fvl == 0) && (strncmp( s, "ALL", 3)  == 0) ) {
		s++; s++; s++;
		l_usgr = 255;
	} else if (l_fvl != 1){
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] <UG> or 'ALL' incorrect in line [%d].\n", i_line);
		return -EINVAL;
	}
	
	s = axt_wst_posltrim(s, s_to);	
	if (s[0] == 'm') { //direction 
		s++;
		if (s[0] == '-') l_ms = 0;
		else if (s[0] == '+') l_ms = 1;
		else {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in m<X> (use X=-|+) in line [%d].\n", i_line);
			return -EINVAL;
		}
		s++;
	}	
	s = axt_wst_posltrim(s, s_to);	
	if (s[0] == 't') { //pksz 
		if (s[1] == 'D') {
			s++; s++;
			l_tcp = -1;
		} else if ( ((l_fvl = axt_wst_take_uint32(++s, s_to, &s, &l_tcp)) != 1) ) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in t<nnn> not num or 'D' in line [%d].\n", i_line);
				return -EINVAL;
		}
	}
	s = axt_wst_posltrim(s, s_to);	
	if (s[0] == 'u') { //pksz 
		if (s[1] == 'D') {
			s++; s++;
			l_udp = -1;
		} else if ( ((l_fvl = axt_wst_take_uint32(++s, s_to, &s, &l_udp)) != 1) ) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in u<nnn> not num or 'D' in line [%d].\n", i_line);
				return -EINVAL;
		}
	}
	s = axt_wst_posltrim(s, s_to);	
	if (s[0] == 'i') { //pksz		
		if (s[1] == 'D') {
			s++; s++;
			l_icm = -1;
		} else if ( ((l_fvl = axt_wst_take_uint32(++s, s_to, &s, &l_icm)) != 1) ) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in i<nnn> not num or 'D' in line [%d].\n", i_line);
				return -EINVAL;
		}
	}
	s = axt_wst_posltrim(s, s_to);	
	if (s[0] == 'o') { //pksz 
		if (s[1] == 'D') {
			s++; s++;
			l_oth = -1;
		} else if ( ((l_fvl = axt_wst_take_uint32(++s, s_to, &s, &l_oth)) != 1) ) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] in o<nnn> not num or 'D' in line [%d].\n", i_line);
				return -EINVAL;
		}
	}
	s = axt_wst_posltrim(s, s_to);
	if (strcmp (s,"]") !=0)  {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_USGR_SET_XXX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]] some garbage or wrong params order in line [%d].\n", i_line);
		return -EINVAL;
	}	

	if (l_usgr==255) {
		l_ufrom = 0;  l_uto = 63;
	} else {
		l_ufrom = l_usgr; l_uto = l_usgr;
	}

	l_plim = ( l_fmax == 0 ? axt_ucfg.wrn : axt_ucfg.max );	

	for (i = l_ufrom; i <=l_uto ; i++) {
		if (l_ms >= 0) axt_cfg_u_m_set(l_fmax, i, l_ms);
		if (l_tcp > -2) WRITE_ONCE(l_plim[i].c_tcp, l_tcp);	
		if (l_udp > -2) WRITE_ONCE(l_plim[i].c_udp, l_udp);	
		if (l_icm > -2) WRITE_ONCE(l_plim[i].c_icm, l_icm);	
		if (l_oth > -2) WRITE_ONCE(l_plim[i].c_oth, l_oth);	
	}
	return 0;	
}
// --------------- user NAT block & pause 
static  int  axt_cfg_docmd_Nat(char* i_trbuf, int i_line) {
//implemet 	'CMD_NAT_BLOCK_ON  [<IP>][+<UG>]' & 'CMD_NAT_BLOCK_OFF [<IP>][+<UG>]' & 'CMD_NAT_PAUSE_ON   <TIME_S> [<IP>][+<UG>]' & 'CMD_NAT_PAUSE_OFF [<IP>][+<UG>]'
// return 0 on ok or error code 
	char			*s, *s_to;
	int 			l_fip, l_fusgr, l_opperation, l_timeneed; //l_operation 1 = block on, -1 = block off, 2 = pause on, -2 = pause off
	uint32_t 		l_ip, l_pauses;
	uint8_t 		l_usgr; 
	
	l_opperation = 0; l_timeneed = 0; 
	if (strncmp( i_trbuf,		"[CMD_NAT_BLOCK_ON ",18 )	== 0)  	{ l_opperation = 1;  s = &i_trbuf[18];}
	else if (strncmp( i_trbuf,	"[CMD_NAT_BLOCK_OFF ",19 )	== 0)  	{ l_opperation = -1; s = &i_trbuf[19];}
	else if (strncmp( i_trbuf,	"[CMD_NAT_PAUSE_ON ",18 )	== 0)  	{ l_opperation = 2;  s = &i_trbuf[18]; l_timeneed = 1;}
	else if (strncmp( i_trbuf,	"[CMD_NAT_PAUSE_OFF ",19 )	== 0)  	{ l_opperation = -2; s = &i_trbuf[19];}
	else if (strcmp( i_trbuf,	"[CMD_NAT_BLOCK_ON]")		== 0) 	{ axt_htm_user_blockpause( 1,0,0,0,0,0);	return 0;}
	else if (strcmp( i_trbuf,	"[CMD_NAT_BLOCK_OFF]")		== 0) 	{ axt_htm_user_blockpause(-1,0,0,0,0,0);	return 0;}
	else if (strcmp( i_trbuf,	"[CMD_NAT_PAUSE_OFF]")		== 0) 	{ axt_htm_user_blockpause(-2,0,0,0,0,0);	return 0;}
	else {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd begin [CMD_NAT_XXX xxx] in line [%d].\n", i_line);
		return -EINVAL;
	}
	s_to = &i_trbuf[strnlen(i_trbuf,AXT_MAX_LINELEN)];
	if (l_timeneed) {
		if (axt_wst_take_uint32(s, s_to, &s, &l_pauses) !=1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_NAT_XXX TIME_S [<IP>][+<UG>]] TIME_S not given or incorrect in line [%d].\n", i_line);
			return -EINVAL;
		}
	}	
	if ((l_fip = axt_wst_take_ip4h(s, s_to, &s, &l_ip)) < 0) {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_NAT_XXX [TIME_S][<IP>][+<UG>]] IP not given or incorrect in line [%d].\n", i_line);
		return -EINVAL;
	}
	if ((l_fusgr = axt_wst_take_usgr(s, s_to, &s, &l_usgr)) < 0) {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_NAT_XXX [TIME_S][<IP>][+<UG>]] U(ser)G(roup) format or value incorrect in line [%d].\n", i_line);
		return -EINVAL;
	}	
	s = axt_wst_posltrim(s, s_to);	
	if (strcmp (s,"]"))  {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_NAT_XXX xxx] some garbage or TIME_S not given in line [%d].\n", i_line);
		return -EINVAL;
	}
	axt_htm_user_blockpause(l_opperation, l_fip, l_fusgr, htonl(l_ip), l_usgr, l_pauses);
	return 0;
}
	
// --------------- test NAT ip set 	
static  int  axt_cfg_docmd_TestIP(char* i_trbuf, int i_line) {
//implemet '[CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>] ]'
// if no data in CMD SET - off test nat ip	
// return 0 on ok or error code 
	char					*s, *s_to;
	int 					l_fvl, l_len;
	uint32_t 				l_vl1, l_vl2;
	uint8_t 				l_ug,  l_trch;
	
	l_len = strnlen(i_trbuf,AXT_MAX_LINELEN);
	if ( (l_len <  16) || (strncmp( i_trbuf, "[CMD_TEST_IP_SET",16 )  != 0) ) { 
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd format [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] in line [%d].\n", i_line);
		return -EINVAL;
	}

	l_fvl = 0; l_vl1 =0; l_vl2 = 0;
	
	s_to = &i_trbuf[l_len];
	s = axt_wst_posltrim(&i_trbuf[16], s_to);	

	if (strcmp (s,"]") !=0)  { //not empty 
		if ((axt_wst_take_ip4h(s, s_to, &s, &l_vl1)) != 1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] in <user_ip> in line [%d].\n", i_line);
			return -EINVAL;
		}
		if ((axt_wst_take_ip4h(s, s_to, &s, &l_vl2)) != 1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] in <nat_ip> in line [%d].\n", i_line);
			return -EINVAL;
		}
		if ((axt_wst_take_usgr(s, s_to, &s, &l_ug)) != 1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] in <UG> in line [%d].\n", i_line);
			return -EINVAL;
		}
		if ((axt_wst_take_trch(s, s_to, &s, &l_trch)) != 1) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] in <T> in line [%d].\n", i_line);
			return -EINVAL;
		}
		s = axt_wst_posltrim(s, s_to);
		if (strcmp (s,"]") !=0)  {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_TEST_IP_SET [<user_ip> <nat_ip> +<UG> ^<T>]] some garbage or wrong params order in line [%d].\n", i_line);
			return -EINVAL;
		}	
		WRITE_ONCE(axt_xcfg.nattest_ip_u, 0);
		wmb();
		WRITE_ONCE(axt_xcfg.nattest_ip_n, htonl(l_vl2));
		WRITE_ONCE(axt_xcfg.nattest_ip_ug, l_ug);
		WRITE_ONCE(axt_xcfg.nattest_ip_tc, l_trch);
		wmb();
		WRITE_ONCE(axt_xcfg.nattest_ip_u, htonl(l_vl1));
	} else {
		WRITE_ONCE(axt_xcfg.nattest_ip_u, 0); //clear	
		wmb();
		WRITE_ONCE(axt_xcfg.nattest_ip_n, 0); 
	}
	return 0;
}		

// --------------- STATIC SESSION (PORT MAPPING) 	
static  int  axt_cfg_docmd_StaticMap(char* i_trbuf, int i_line) {
//implemet '[CMD_STATIC_MAP_ADD p<proto> <user_ip> : <user_port> <nat_ip> : <nat_port> [+<UG>] [^<T>] ]'
//implemet '[CMD_STATIC_MAP_DEL p<proto> <user_ip> : <user_port> ]'
//implemet '[CMD_STATIC_MAP_DEL_ALL [p<proto>] [<user_ip>] [+<UG>] [^<T>] ]'
// return 0 on ok or error code 
	char					*s, *s_to;
	int 					l_len, l_from;
	int						l_fres, l_fproto, l_fuip, l_fusgr, l_ftrch;
	int						l_need_proto, l_need_uip, l_need_uport, l_need_nat, l_need_ug_tc;
	uint32_t 				l_uip, l_nip;
	uint8_t 				l_usgr, l_trch;
	uint16_t 				l_uport, l_nport, l_proto;
	int 					l_oper;  // 0 - add, 1 - del, 2 - del_all
	
	l_need_proto = 1; l_need_uip = 1; l_need_uport = 1; l_need_nat = 1; l_need_ug_tc = 1;
	l_oper = -1;
	if (strncmp( i_trbuf, "[CMD_STATIC_MAP_ADD",19 ) == 0) {
		l_oper = 0; l_from = 19;
	} else if (strncmp( i_trbuf, "[CMD_STATIC_MAP_DEL_ALL",23 ) == 0) {
		l_oper = 2; l_from = 23; l_need_nat = 0; l_need_uip = 0; l_need_uport = 0; l_need_proto=0; 
	} else if (strncmp( i_trbuf, "[CMD_STATIC_MAP_DEL",19 ) == 0) {
		l_oper = 1; l_from = 19; l_need_nat = 0; l_need_ug_tc = 0;
	}
	
	l_len = strnlen(i_trbuf,AXT_MAX_LINELEN); 	
	if ( (l_oper < 0) || (l_from > l_len) ) {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong cmd format [CMD_STATIC_MAP_{ADD|DEL|DEL_ALL}  p<proto> <user_ip>{:<user_port>} {<nat_ip>:<nat_port>} [+<UG>] [^<T>]] in line [%d].\n", i_line);
		return -EINVAL;
	}

	l_fres = 0; l_fproto=0; l_fuip = 0; l_fusgr=0; l_ftrch=0;
	
	l_proto = 0;
	l_uip  = 0;   l_uport = 0;
	l_nip  = 0;	  l_nport = 0;
	l_usgr = 0;   l_trch  = 0;

	s_to = &i_trbuf[l_len];
	s = axt_wst_posltrim(&i_trbuf[l_from], s_to);

	if (strcmp (s,"]") !=0)  { //not empty 
		if ((l_fproto = axt_wst_take_proto(s, s_to, &s, &l_proto)) < l_need_proto) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_xxx p<proto> ... ] in <proto> %s in line [%d].\n",
						axt_wst_ierror(l_fproto), i_line);
			return -EINVAL;
		}	

		if ((l_fuip = axt_wst_take_ip4h(s, s_to, &s, &l_uip)) < l_need_uip) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_xxx .. <user_ip> ... ] in <user_ip> %s in line [%d].\n",
						axt_wst_ierror(l_fuip), i_line);
			return -EINVAL;
		} 
		
		if (l_need_uport) {
			if ((l_fres = axt_wst_take_porth(s, s_to, &s, &l_uport)) != 1) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_{ADD|DEL} <user_ip>: <user_port> ... ]] in <user_port> %s in line [%d].\n",
							axt_wst_ierror(l_fres), i_line);
				return -EINVAL;
			}
		}
		if (l_need_nat) {
			if ((l_fres = axt_wst_take_ip4h(s, s_to, &s, &l_nip)) != 1) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_ADD ... <nat_ip>:<nat_port> ... ]] in <nat_ip> %s in line [%d].\n",
							axt_wst_ierror(l_fres), i_line);
				return -EINVAL;
			
			}
			if ((l_fres =  axt_wst_take_porth(s, s_to, &s, &l_nport)) != 1) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_ADD ... <nat_ip>:<nat_port> ... ]] in <nat_port> %s in line [%d].\n",
							axt_wst_ierror(l_fres), i_line);
				return -EINVAL;
			}		
		}
		
		if (l_need_ug_tc) {		
			if ((l_fusgr = axt_wst_take_usgr(s, s_to, &s, &l_usgr)) < 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_{ADD|DEL_ALL} ... [+<UG>] [^<T>] ] in <UG> %s in line [%d].\n",
							axt_wst_ierror(l_fusgr), i_line);
				return -EINVAL;
			}
			if ((l_ftrch = axt_wst_take_trch(s, s_to, &s, &l_trch)) < 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_{ADD|DEL_ALL} ... [+<UG>] [^<T>] ] in <T> %s in line [%d].\n",
							axt_wst_ierror(l_ftrch), i_line);
				return -EINVAL;
			}
		}
		
		s = axt_wst_posltrim(s, s_to);
		if (strcmp (s,"]") !=0)  {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong [CMD_STATIC_MAP_{ADD|DEL|DEL_ALL} ... ] some garbage or wrong params order in line [%d].\n", i_line);
			return -EINVAL;
		}	
	
		if (l_oper > 0) { //if DEL or DEL_ALL
			axt_htm_ses_kill(2, l_fuip, l_fproto, l_need_uport, l_fusgr, l_ftrch, htonl(l_uip), l_proto, htons(l_uport), l_usgr, l_trch);
		}	else if (l_oper == 0) { 
			axt_dnt_create_static_session(l_proto, htonl(l_uip), htons(l_uport), htonl(l_nip), htons(l_nport), l_usgr, l_trch);		
		}
	} else {
		//if DEL_ALL
		if (l_oper == 2) axt_htm_ses_kill(2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);	
	}
	return 0;
}		

// --------------- functions working with >> proc/.../config 
static inline void 	axt_cfg_copyConfig(const axt_cfg_lconfig_t *i_from, axt_cfg_lconfig_t *i_to) {
	memcpy(i_to, i_from, sizeof(axt_cfg_lconfig_t) );
}


static inline uint64_t 	axt_cfg_checkConfigIsFree(const axt_cfg_lconfig_t *i_chkConfig) {
	// return 1 (true) if i_chkConfig already free by time (unused) now
	return  axt_wtm_get_cur_jif_s() - i_chkConfig->cfg_freetime - AXT_CFG_MIN_FREETIME;
}

static inline int 	axt_cfg_get_actinaConfigN(int *v_act, int *v_ina) { 
	//return 0 if ACTIVE config never loaded, else cur ACTIVE config num
	int l_actc = atomic_read(&axt_config_actn);
	if (l_actc == 2) { *v_act = 2; *v_ina =1; } else { *v_act = 1; *v_ina =2;}; //By default [1] is active [2] is inactive
	return l_actc;
}
	
static int 	axt_cfg_docmd_TmpToInaConfig(void) {
	//must be called only in axt_config_load_lock locked state for saffety!!!  return 0 or error code (<0)
	axt_cfg_lconfig_t 		*l_inaConfig = NULL;
	int 					l_actc, l_actn, l_inan;
	int64_t					l_wsec;
	
	if (axt_config_tmp_load_er > 0) {
		printk( KERN_WARNING "xt_ANAT ERROR: CFG - CAN'T LOAD TMP TO INA! TMP config set was never loaded.\n" );
		return -EINVAL;
	} else if (axt_config_tmp_load_er < 0) {
		printk( KERN_WARNING "xt_ANAT ERROR: CFG - CAN'T LOAD TMP TO INA! TMP config set was loaded with error [%d] in line [%d].\n", 
			axt_config_tmp_load_er, axt_config_tmp_load_erln );
		return axt_config_tmp_load_er;
	}
	// TMP config was loaded sucsesfull
	l_actc = axt_cfg_get_actinaConfigN(&l_actn, &l_inan);
	l_inaConfig = &axt_config[l_inan];
	if (  (l_actc > 0) && ( (l_wsec=axt_cfg_checkConfigIsFree(l_inaConfig)) <=0 ) ) {
		printk( KERN_WARNING "xt_ANAT ERROR: CFG - CMD_CONFIG_TMPTOINA error. Inactive config [%d] free time less then %d seconds. Wait %lld sec.\n", 
								l_inan, AXT_CFG_MIN_FREETIME, -l_wsec );
		return -EINPROGRESS;
	} else {
		axt_cfg_copyConfig(&axt_config[0], l_inaConfig); //copy TMP to INACTIVE config
		printk(KERN_INFO "xt_ANAT INFO: CFG - CMD_CONFIG_TMPTOINA - SUCCESSFUL.\n");
		return 0;	
	}
}

static int 	axt_cfg_docmd_SwapConfig(void) { 
	//must be called only in axt_config_load_lock locked state for saffety!!!  return 0 or error code
	int 	l_actc, l_actn, l_inan;

	l_actc = axt_cfg_get_actinaConfigN(&l_actn, &l_inan);
	if (l_actc > 0) axt_config[l_actn].cfg_freetime = axt_wtm_get_cur_jif_s(); // save free time for RCU protect
	wmb();
	atomic_set(&axt_config_actn, l_inan );
	printk(KERN_INFO "xt_ANAT INFO: CFG - CMD_CONFIG_SWAP - SUCCESSFUL.\n");
	return 0; 
}	

// load config file records
static int 	axt_cfg_loadrec_natpool(char *i_buf, axt_cfg_lconfig_t *i_tmpConfig, const int i_line) {
	// return 0 or error code (<0)
	uint32_t 		l_uips, l_uipe, l_nips, l_nipe;
	uint32_t		l_mark, l_marked, l_hashtype, l_exclude;
	uint8_t  		l_trch, l_usgr; //trace char , user group
	size_t			l_slen;
	int 			l_res, l_cnt;

	if ((l_slen = strnlen(i_buf, AXT_MAX_LINELEN)) >= AXT_MAX_LINELEN) {
			printk(KERN_WARNING "xt_ANAT ERROR: ERROR in alghoritm in call axt_cfg_loadrec_natpool (not 0 ended string)! Line [%d]!\n",  i_line);
			return -EINVAL;
	}
	if ((l_res = axt_wst_loadrec_natpool(i_buf, &i_buf[l_slen], &l_uips, &l_uipe, &l_nips, &l_nipe, &l_mark, &l_marked, &l_hashtype, &l_exclude, &l_trch, &l_usgr)) ) {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong IP nat pool record (%s) in config line [%d].\n", axt_wst_ierror(l_res), i_line);
		return -EINVAL;
	}
 	l_cnt = i_tmpConfig->natpool_cnt;
	if (l_cnt < AXT_CFG_NATPOOL_REC_MAX) {
		i_tmpConfig->natpool_arr[l_cnt].usrip_start	= l_uips;
		i_tmpConfig->natpool_arr[l_cnt].usrip_end	= l_uipe;
		i_tmpConfig->natpool_arr[l_cnt].natip_start	= l_nips;
		i_tmpConfig->natpool_arr[l_cnt].natip_end	= l_nipe;
		i_tmpConfig->natpool_arr[l_cnt].mark		= l_mark;
		i_tmpConfig->natpool_arr[l_cnt].marked		= l_marked;
		i_tmpConfig->natpool_arr[l_cnt].hashtype	= l_hashtype;
		i_tmpConfig->natpool_arr[l_cnt].exclude		= l_exclude;
		i_tmpConfig->natpool_arr[l_cnt].trch		= l_trch;
		i_tmpConfig->natpool_arr[l_cnt].usgr		= l_usgr;
		i_tmpConfig->natpool_cnt++;
	} else {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Too much nat poll records AXT_CFG_NATPOOL_REC_MAX=%d.\n",AXT_CFG_NATPOOL_REC_MAX);
		return -EINVAL;
	}
	return 0; 
}

static int	axt_cfg_loadrec_nf9dest(char *i_buf, axt_cfg_lconfig_t *i_tmpConfig, const int i_line) {
	// return 0 or error code (<0)
	uint32_t 		l_addrn;
	uint16_t		l_port;
	size_t			l_slen;
	int				l_res, l_cnt;
	
	//we already done strim()! !!! SDY be carefull with (u8 *)&s_ip_end !!!
	if ((l_slen = strnlen(i_buf, AXT_MAX_LINELEN)) >= AXT_MAX_LINELEN) {
			printk(KERN_WARNING "xt_ANAT ERROR: ERROR in alghoritm in call axt_cfg_loadrec_nf9dest (not 0 ended string)! Line [%d]!\n",  i_line);
			return -EINVAL;
	}
	if ((l_res = axt_wst_loadrec_nf9dest(i_buf, &i_buf[l_slen], &l_addrn, &l_port)) ) {
	 	printk(KERN_WARNING "xt_ANAT ERROR: CFG - Wrong  nf9 dest IP record (%s) in config line [%d].\n", axt_wst_ierror(l_res), i_line);
		return -EINVAL;
	}
	l_cnt = i_tmpConfig->nf9dest_cnt;
	if (l_cnt < AXT_CFG_NF9DEST_REC_MAX) {
		i_tmpConfig->nf9dest_arr[l_cnt].d_ip	= l_addrn;
		i_tmpConfig->nf9dest_arr[l_cnt].d_port	= l_port;
		i_tmpConfig->nf9dest_cnt++;
	} else {
		printk(KERN_WARNING "xt_ANAT ERROR: CFG - Too much nf9 dest records AXT_CFG_NF9DEST_REC_MAX=%d.\n",AXT_CFG_NF9DEST_REC_MAX);
		return -EINVAL;
	}
	return 0; 
}

static int	axt_cfg_loadend( axt_cfg_lconfig_t *i_tmpConfig) {
	//now nothing use for future process on ending load config!
	return 0; 
}

// load config file processc
static ssize_t axt_cfg_loadconfig_frombuf(char *i_buffer, size_t i_count) { //i_count = sizeof(i_buffer)-1 !!!
	int					l_errc, l_line, l_res;
 	int 				i, j;
	
	axt_cfg_lconfig_t 	*l_tmpConfig = NULL;
	axt_cfg_lconfig_t 	*l_actConfig = NULL;
	int					l_actc, l_actn, l_inan;

	bool 				l_started_cfg   = false;
	bool 				l_started_npool = false;
	bool 				l_started_nf9   = false;
	
	char 				l_buff_str[AXT_MAX_LINELEN]; //SDY use kzalloc if it will grow!!!
	char				*l_trbuf;
	
	//printk(KERN_INFO "%s",i_buffer); 
	//printk(KERN_INFO "xt_ANAT DEBUG: CFG - Started process config file [size=%ld].\n", i_count);

	spin_lock_bh(&axt_config_load_lock);
	
	l_actc = axt_cfg_get_actinaConfigN(&l_actn, &l_inan);
	l_actConfig = &axt_config[l_actn];
	l_tmpConfig = &axt_config[0];
	
	l_line=0;
	i = 0; 	
    while (i < i_count) {
		//process line in config file
		l_line++;		
		memset( l_buff_str, 0, AXT_MAX_LINELEN );
		for(j=0; ( j < (AXT_MAX_LINELEN-1) ) && ( i_buffer[i] != 0x0A ) && ( i_buffer[i] != '\0' ); i++, j++) {
			l_buff_str[j] = i_buffer[i];	 
			//printk(KERN_INFO "i=%d, j=%d, str[i]=%X, i_count=%d", i, j, str[j], i_count);
		}
		i++;
		if ( j >= (AXT_MAX_LINELEN-1) ) {
			printk(KERN_WARNING "xt_ANAT ERROR: CFG - Too long line [%d]. Max config line size is %d chars.\n", l_line, AXT_MAX_LINELEN-1);
			l_errc = -EINVAL;
			goto err_exit;
		}
		
		strreplace(l_buff_str,'\t',' '); //clear tabs
		l_trbuf=strim(l_buff_str);
		//printk(KERN_INFO "LN: %s",l_trbuf);

		if ((l_trbuf[0] == '\0') || (l_trbuf[0] == '#')) continue; //empty line or comments line 
			
		//check for commands at first
		if (!(l_started_cfg)) {
			if (strcmp( l_trbuf, "[CMD_RESET_CNT_PK]") == 0) axt_cnt_reset_pk();
			else if (strcmp(  l_trbuf, "[CMD_DEBUG]") == 0) { if ((l_errc = axt_debug()))  	goto err_exit; }
			else if (strcmp(  l_trbuf, "[CMD_RESET_CNT_FP]") == 0) axt_cnt_reset_fp();
			else if (strcmp(  l_trbuf, "[CMD_RESET_CNT_HT]") == 0) axt_cnt_reset_ht();
			else if (strcmp(  l_trbuf, "[CMD_RESET_CNT_OV]") == 0) axt_cnt_reset_ov();
			else if (strcmp(  l_trbuf, "[CMD_RESET_CNT_NF]") == 0) axt_cnt_reset_nf();
			else if (strcmp(  l_trbuf, "[CMD_RESET_CNT_ER]") == 0) axt_cnt_reset_er();
			else if (strcmp(  l_trbuf, "[CMD_RESET_NF9_SEQ]") == 0) axt_nf9_reset_seq();
			else if (strcmp(  l_trbuf, "[CMD_CONFIG_TMPTOINA]") == 0) { if ((l_errc = axt_cfg_docmd_TmpToInaConfig()))  goto err_exit; }
			else if (strcmp(  l_trbuf, "[CMD_CONFIG_SWAP]")     == 0) { if ((l_errc = axt_cfg_docmd_SwapConfig()))  	goto err_exit; }
			else if (strcmp(  l_trbuf, "[CMD_MESSAGE_FREEZE]")  == 0) { if ((l_errc = axt_msg_message_freeze()))  	goto err_exit; }
			else if (strcmp(  l_trbuf, "[CMD_TRACE_FREEZE]")  == 0) { if ((l_errc = axt_msg_trace_freeze()))  	goto err_exit; }
			else if (strncmp( l_trbuf, "[CMD_SET_PRM_", 13)   == 0)   { if ((l_errc = axt_prm_docmd_SetParam(l_trbuf,l_line)) )  goto err_exit; }
			else if (strncmp( l_trbuf, "[CMD_TEST_IP_SET", 16)   == 0)   { if ((l_errc = axt_cfg_docmd_TestIP(l_trbuf,l_line)) )  goto err_exit; }
			else if (strncmp( l_trbuf, "[CMD_USGR_SET_", 14)   == 0)   { if ((l_errc = axt_cfg_docmd_UsgrSet(l_trbuf,l_line)) )  goto err_exit; }
			else if (strcmp(  l_trbuf, "[CMD_TRACE_START]")   == 0) axt_cfg_x_tr_enable(); 
			else if (strcmp(  l_trbuf, "[CMD_TRACE_STOP]")    == 0) axt_cfg_x_tr_disable();
			else if (strcmp(  l_trbuf, "[CMD_TRACE_ON_ALL]")    == 0) axt_cfg_x_tr_on_all(); 
			else if (strcmp(  l_trbuf, "[CMD_TRACE_OFF_ALL]")   == 0) axt_cfg_x_tr_off_all(); 			
			else if (strcmp(  l_trbuf, "[CMD_TRACE_OUTDROP_ON]")  == 0) axt_cfg_x_tr_outdrop_set(1); 
			else if (strcmp(  l_trbuf, "[CMD_TRACE_OUTDROP_OFF]") == 0) axt_cfg_x_tr_outdrop_set(0); 			
			else if (strcmp(  l_trbuf, "[CMD_TRACE_LOCFRWD_ON]")  == 0) axt_cfg_x_tr_locfrwd_set(1); 
			else if (strcmp(  l_trbuf, "[CMD_TRACE_LOCFRWD_OFF]") == 0) axt_cfg_x_tr_locfrwd_set(0);
			else if (strcmp(  l_trbuf, "[CMD_TRACE_FILTER_ON]")  == 0) axt_cfg_x_tr_filter_set(1); 
			else if (strcmp(  l_trbuf, "[CMD_TRACE_FILTER_OFF]") == 0) axt_cfg_x_tr_filter_set(0);
			else if (strncmp( l_trbuf, "[CMD_TRACE_FILTER_SET_", 22)   == 0)   { if ((l_errc = axt_cfg_docmd_TraceFilter(l_trbuf,l_line)) )  goto err_exit; }
 			else if ( (strncmp(l_trbuf,"[CMD_TRACE_ON_",  14) == 0) && ( strcmp(&l_trbuf[15], "]") == 0) ) 
											{ if ((l_errc = axt_cfg_x_tr_changechar(l_trbuf[14], 1, l_line) ))  goto err_exit; } 
			else if ( (strncmp(l_trbuf,"[CMD_TRACE_OFF_", 15) == 0) && ( strcmp(&l_trbuf[16], "]") == 0) ) 
											{ if ((l_errc = axt_cfg_x_tr_changechar(l_trbuf[15], 0, l_line) ))  goto err_exit; } 
			else if (strncmp( l_trbuf, "[CMD_TRACE_USER_", 16)   == 0)   { if ((l_errc = axt_cfg_docmd_TraceUser(l_trbuf,l_line)) )  goto err_exit; }	
			else if (strncmp( l_trbuf, "[CMD_KILL_", 10)   == 0)   { if ((l_errc = axt_cfg_docmd_Kill(l_trbuf,l_line)) )  goto err_exit; }	
			else if (strncmp( l_trbuf, "[CMD_NAT_", 9)   == 0)   { if ((l_errc = axt_cfg_docmd_Nat(l_trbuf,l_line)) )  goto err_exit; }	
			
			else if (strncmp( l_trbuf, "[CMD_STATIC_MAP_", 16)   == 0)   { if ((l_errc = axt_cfg_docmd_StaticMap(l_trbuf,l_line)) )  goto err_exit; }

			//  find "[LOAD_TMP_CONFIG_V2_0]" to start config load process 
			else if (strcmp( l_trbuf, "[LOAD_TMP_CONFIG_V2_0]") == 0) {
				printk( KERN_INFO "xt_ANAT INFO: CFG - Started LOAD_TMP_CONFIG");
				l_started_cfg = true; 
				axt_config_tmp_load_er = -EINVAL; //clean only in the end of loading
				axt_config_tmp_load_erln = 0;		
				// copy active config setting to l_tmpConfig for correct partial load
				axt_cfg_copyConfig(l_actConfig, l_tmpConfig);
			}
			else { //error command or garbage in config line
				printk(KERN_INFO "xt_ANAT ERROR: CFG  - Unknown simbols or command in line [%d] : %s\n", l_line, l_buff_str);
				l_errc = -EINVAL;		
				goto err_exit;				
			}
			
		} else { // we are processing LOAD_TMP_CONFIG section 
			// find "[LOAD_TMP_CONFIG_END]"
			if (l_started_npool) { // we are processing nat pool section CFG_NATPOLL
				if (strcmp( l_trbuf, "[CFG_NATPOLL_END]") == 0) {
						l_started_npool = false;  
						//printk(KERN_INFO "xt_ANAT: DEBUGCFG ended CFG_NATPOLL - SUCCESSFUL\n");
						continue; 
				} else { //load natpool record config from line
					if ( (l_res = axt_cfg_loadrec_natpool(l_trbuf, l_tmpConfig, l_line) ) ) {
						l_errc = l_res;
						goto err_exit;
					}
				}
			} else if (l_started_nf9) {
				if (strcmp( l_trbuf, "[CFG_NF9DEST_END]") == 0) {
						l_started_nf9 = false;  
						//printk(KERN_INFO "xt_ANAT: DEBUGCFG ended CFG_NF9DEST - SUCCESSFUL\n");
						continue; 
				} else { //load nf9dist record config from line
					if ( (l_res = axt_cfg_loadrec_nf9dest(l_trbuf, l_tmpConfig, l_line) ) ) {
						l_errc = l_res;
						goto err_exit;
					}
				}
			} // (l_started_npool == false)  && (l_started_nf9 == false) - all settings in advanced sections done or empty
	 		else if (strcmp( l_trbuf, "[CFG_NATPOLL_V2_0]") == 0) {  //find "[CFG_NATPOLL_V2_0]"
				printk(KERN_INFO "xt_ANAT INFO: CFG - Started CFG_NATPOLL_V2_0\n");
				l_started_npool = true; 
				l_tmpConfig->natpool_cnt = 0;
			} else if (strcmp( l_trbuf, "[CFG_NF9DEST_V2_0]") == 0) {  //find "[CFG_NF9DEST_V2_0]"
				printk(KERN_INFO "xt_ANAT INFO: CFG - Started CFG_NF9DEST_V2_0\n");
				l_started_nf9 = true; 
				l_tmpConfig->nf9dest_cnt = 0;
			} else if (strcmp( l_trbuf, "[LOAD_TMP_CONFIG_END]") == 0) {
				//SDY if it will be some more procedures to update data at the end it is need to do it call in axt_prm_init!!!
				if ((l_errc =axt_cfg_loadend(l_tmpConfig))) goto err_exit; 
				l_started_cfg = false;  
				axt_config_tmp_load_er = 0;
				axt_config_tmp_load_erln = 0;
				printk(KERN_INFO "xt_ANAT INFO: CFG - Ended LOAD_TMP_CONFIG - SUCCESSFUL\n");
				continue; 
			} else {
				printk(KERN_INFO "xt_ANAT ERROR: CFG  - Unknown simbols in line [%d] : %s\n", l_line, l_buff_str);
				l_errc = -EINVAL;		
				goto err_exit;
			}
		}
	}
	
  //wrk_exit:
	l_errc = 0;	
	goto cont_exit;
	
  err_exit:
 	printk(KERN_INFO "xt_ANAT ERROR: CFG  - Found error [%d] in line [%d] : %s\n", l_errc, l_line, l_buff_str);
	if (l_started_cfg) axt_config_tmp_load_erln = l_line;
 
  cont_exit:
	spin_unlock_bh(&axt_config_load_lock);
 	return l_errc;		
}

// functions working with  proc/.../config >> 
// === >> to config
static ssize_t	axt_cfg_proc_write(struct file* i_file,const char __user *buffer, size_t count, loff_t *f_pos) {	//interface standart call
	int				l_errc;
	char 			*l_buffer;

	//printk( KERN_INFO "xt_ANAT DEBUG: CFG - Start config file analize length=%lu bytes\n", count );
	l_errc = 0;	
	
	l_buffer = kzalloc((count+1),GFP_KERNEL);
	if (!l_buffer) { l_errc = -ENOMEM; goto err_exit; }
	if ( copy_from_user(l_buffer, buffer, count) ) { l_errc = -ENOMEM;  goto err_exit; }

	l_errc = axt_cfg_loadconfig_frombuf(l_buffer, count);

	//printk(KERN_INFO "xt_ANAT DEBUG: CFG - End config file analize\n");
	if (!l_errc) goto cont_exit;
	
  err_exit:	
 	printk(KERN_INFO "xt_ANAT ERROR: CFG  - Proceed error [%d]\n", l_errc);

  cont_exit:

    if (!l_buffer) kfree(l_buffer);
	return ( l_errc < 0 ? l_errc : count);	
}


// === from config >>
static void axt_cfg_show_confNPool( struct seq_file *m, axt_cfg_lconfig_t *i_curConfig) {
    int 					i, l_cnt;
	uint32_t 				l_us_start, l_us_end, l_nt_start, l_nt_end;
	axt_cfg_natpool_rec_t	*l_cur_r;

	seq_printf( m, "    -- NAT pools -- (lines: %d ) \n", i_curConfig->natpool_cnt);
	seq_printf( m, "      #[ [^<T>] [+<UG>] [&<E>] [*L(inear)|*H(ash)] [!<mark>] : ] [ <usr_ip_start> - <usr_ip_end> :] <nat_ip_start> - <nat_ip_end>\n");
	l_cnt = i_curConfig->natpool_cnt;
	for ( i=0; i < l_cnt; i++ ) {
		l_cur_r = &i_curConfig->natpool_arr[i];
		l_us_start = htonl( l_cur_r->usrip_start );
		l_us_end   = htonl( l_cur_r->usrip_end );
		l_nt_start = htonl( l_cur_r->natip_start );
		l_nt_end   = htonl( l_cur_r->natip_end );

		seq_printf( m, "      ^%c +%02d &%d *%s ", (char) (l_cur_r->trch + 0x40), l_cur_r->usgr, l_cur_r->exclude, (l_cur_r->hashtype ? "H" : "L"));
		if (l_cur_r->marked)
			seq_printf( m, "!0x%08X ", l_cur_r->mark);
		else
			seq_printf( m, "!---------- ");
		seq_printf( m, ": %pI4 - %pI4 : %pI4 - %pI4\n", &l_us_start, &l_us_end, &l_nt_start, &l_nt_end);
	}	
}

static void axt_cfg_show_confNF9Dest( struct seq_file *m, axt_cfg_lconfig_t *i_curConfig) {
    int 					i, l_cnt;
	uint32_t 				l_d_ip;
	uint16_t 				l_d_port;
	axt_cfg_nf9dest_rec_t 	*l_cur_r;

	seq_printf( m, "    -- NF9 destinations -- (lines: %d )\n", i_curConfig->nf9dest_cnt);
	seq_printf( m, "      # <dest_ip> : <dest_port>\n");
	l_cnt = i_curConfig->nf9dest_cnt;
	for ( i=0; i < l_cnt; i++ ) {
		l_cur_r = &i_curConfig->nf9dest_arr[i];
		l_d_ip 	 = htonl( l_cur_r->d_ip );
		l_d_port = l_cur_r->d_port;
		seq_printf( m, "      %pI4 : %d\n", &l_d_ip, l_d_port);
	}	
}

static void axt_cfg_show_confAll( struct seq_file *m, axt_cfg_lconfig_t *i_curConfig, const char* i_status, const int i_num) {
	seq_printf( m, "  == %s == CONFIG - [%d] \n", i_status, i_num);	
	seq_printf( m, "    Last used (jiffies) sec: %lld\n", i_curConfig->cfg_freetime);
	axt_cfg_show_confNPool( m, i_curConfig);
	axt_cfg_show_confNF9Dest( m, i_curConfig);
	//seq_printf( m, " ======= CONFIG INFO END ========\n");	
	//seq_printf( m, "\n");
}
	
static void axt_cfg_proc_show_trfl_ipf( struct seq_file *m,  axt_cfg_x_trfl_ip_p i_pipf) {
	int32_t		l_fip, l_fport;
	uint32_t 	l_vl1, l_vl2;
	l_fip = READ_ONCE(i_pipf->addr_f);	l_fport = READ_ONCE(i_pipf->port_f); 
	if ((l_fip == 0) && (l_fport == 0) ) seq_printf( m, "[OFF]");
	else {
		seq_printf( m, "[");
		if (l_fip != 0) {
			l_vl1 = htonl(READ_ONCE(i_pipf->addr_s)); l_vl2 = htonl(READ_ONCE(i_pipf->addr_e));
			if (l_vl1 != l_vl2) seq_printf( m, "%pI4 - %pI4", &l_vl1, &l_vl2);
			else  seq_printf( m, "%pI4", &l_vl1);
		}
		if (l_fport != 0) {
			l_vl1 = htonl(READ_ONCE(i_pipf->port_s)); l_vl2 = htonl(READ_ONCE(i_pipf->port_e));
			if (l_vl1 != l_vl2) seq_printf( m, " :%d - %d", l_vl1, l_vl2);
			else  seq_printf( m, ": %d", l_vl1);
		}
		seq_printf( m, "]");
	}												
}
	
static int axt_cfg_proc_show( struct seq_file *m, void *v){  //config show
	int			l_actc, l_actn, l_inan, l_was_ch;
	uint8_t		l_ch;
	int 		l_fip, l_fug;
	uint32_t 	l_ip, l_ip1, l_val, l_val2;
	uint8_t 	l_ug;

	l_actc = axt_cfg_get_actinaConfigN(&l_actn, &l_inan);	
	seq_printf( m, "\n");
	seq_printf( m, "===============================================================================================\n");	
	seq_printf( m, "=============================== Config LOAD pool and NF9 status ===============================\n");	
	seq_printf( m, "  Curent (jiffies) sec: %lld\n", axt_wtm_get_cur_jif_s());
	seq_printf( m, "  ACTIVE config number = [%d]\n", l_actc);
	seq_printf( m, "  TMP config status: ");	
	if (axt_config_tmp_load_er <= 0) {
		if (axt_config_tmp_load_er < 0) {
			seq_printf( m, "Loaded with ERROR [%d] in line [%d] !!!\n", axt_config_tmp_load_er, axt_config_tmp_load_erln);
		} else	{
			seq_printf( m,"OK\n");
		}
		seq_printf( m, "\n");
		axt_cfg_show_confAll(m, &axt_config[0], "TMP", 0); 
		seq_printf( m, "\n");
	} else {
		seq_printf( m, "WAS NEVER LOADED \n");
		seq_printf( m, "\n");
	}
	// show INACTIVE config set
	axt_cfg_show_confAll(m, &axt_config[l_inan], "INACTIVE", l_inan); 
	// show TMP config set
	// show ACTIVE config set
	seq_printf( m, "\n");
	if (l_actc > 0) {
		axt_cfg_show_confAll(m, &axt_config[l_actn], "ACTIVE", l_actn); 
	} else  {
		seq_printf( m, "  == ACTIVE|INACTIVE == config swap command was not send !!!\n"); 
	}
	seq_printf( m, "\n");
	seq_printf( m, "======================= Trace CHAR and trace USER status [CMD_TRACE_XXX] ======================\n");	
	seq_printf( m, "  TRACE pkts status: %s\n", (axt_cfg_x_tr_isenabled() ? "STARTED (work)" : "STOPED (paused)" ));
	seq_printf( m, "    ON for ^chars: ");
	for (l_ch = 0, l_was_ch = 0; l_ch < 27; l_ch++) {
		if (l_ch != 0) seq_printf( m, ",");
		if (axt_cfg_x_tr_state(l_ch)) { seq_printf( m, "%c", (char)(l_ch+0x40) );}
	}
	seq_printf( m, "\n");
	seq_printf( m, "    OFF for ^chars: ");
	for (l_ch = 0; l_ch < 27; l_ch++) {
		if (l_ch != 0) seq_printf( m, ",");
		if (!axt_cfg_x_tr_state(l_ch)) { seq_printf( m, "%c", (char)(l_ch+0x40) );}
	}
	seq_printf( m, "\n");
	seq_printf( m, "    USER trace: ");
	if ( axt_cfg_x_trus_state(&l_fip, &l_fug, &l_ip, &l_ug ) ) {
		if (l_fip) seq_printf( m, "%pI4 ", &l_ip);
		if (l_fug) seq_printf( m, "+%02d", l_ug);
	} else seq_printf( m, "[OFF]");
	seq_printf( m, "\n");
	seq_printf( m, "    Trace out dropped trafic (usr limit or block):         [%s]\n", ( axt_cfg_x_tr_outdrop_ison()==0 ? "OFF" : "ON"));
	seq_printf( m, "    Trace local forwarded trafic (DNAT session not found): [%s]\n", ( axt_cfg_x_tr_locfrwd_ison()==0 ? "OFF" : "ON"));	
	seq_printf( m, "    Trace advanced filter: [%s]\n", ( axt_cfg_x_tr_filter_ison()==0 ? "OFF" : "ON"));	
	seq_printf( m, "      Proto: ");
			if (READ_ONCE(axt_xcfg.trfl_proto_f) == 0) seq_printf( m, "[OFF]");
			else if (READ_ONCE(axt_xcfg.trfl_proto_s) == 256) seq_printf( m, "[OTHER]");	
			else seq_printf( m, "[%3d - %3d]", READ_ONCE(axt_xcfg.trfl_proto_s), READ_ONCE(axt_xcfg.trfl_proto_e));	
		seq_printf( m, "    Packet size: ");
			if (READ_ONCE(axt_xcfg.trfl_pksz_f) == 0) seq_printf( m, "[OFF]");
			else seq_printf( m, "[%5d - %5d]", READ_ONCE(axt_xcfg.trfl_pksz_s), READ_ONCE(axt_xcfg.trfl_pksz_e));
		seq_printf( m, "    Direction: [%s]    Result: [%s]\n", ((l_val = READ_ONCE(axt_xcfg.trfl_dir_f)) == 0 ? "BOTH": (l_val ==1 ? "IN": "OUT")) ,
																((l_val2 = READ_ONCE(axt_xcfg.trfl_res_f)) == 0 ? "BOTH": (l_val2 ==1 ? "DROP": "ACCEPT")) );
	seq_printf( m, "      User: "); axt_cfg_proc_show_trfl_ipf(m, &axt_xcfg.trfl_u); 											
		seq_printf( m, "     Nat: "); axt_cfg_proc_show_trfl_ipf(m, &axt_xcfg.trfl_n);
		seq_printf( m, "\n");
	seq_printf( m, "      Dest: "); axt_cfg_proc_show_trfl_ipf(m, &axt_xcfg.trfl_d); 											
		seq_printf( m, "     Session init dest: "); axt_cfg_proc_show_trfl_ipf(m, &axt_xcfg.trfl_s);
		seq_printf( m, "\n");
	seq_printf( m, "\n");
	seq_printf( m, "============================== Test Nat IP [CMD_TEST_IP_SET XXX] ==============================\n");	
	seq_printf( m, "  Test nat IP: ");
		l_ip = READ_ONCE(axt_xcfg.nattest_ip_u); l_ip1 = READ_ONCE(axt_xcfg.nattest_ip_n); 
		if (l_ip == 0) seq_printf( m, "[OFF]\n");
		else seq_printf( m, "[ %pI4 |-> %pI4 ] +%02d ^%c\n", &l_ip, &l_ip1,  READ_ONCE(axt_xcfg.nattest_ip_ug), READ_ONCE(axt_xcfg.nattest_ip_tc)+0x40 );
	seq_printf( m, "\n");
	seq_printf( m, "* cat /proc/net/ANAT/ugroups - user groups config info\n");
	seq_printf( m, "  cat /proc/net/ANAT/params  - parametrs config info\n");	
	seq_printf( m, "===============================================================================================\n");	
	seq_printf( m, "\n");
	return 0;
}

static void axt_cfg_ugroups_seq_ugcnt( struct seq_file *m,  int32_t i_cnt) {
	if (i_cnt < 0) seq_printf( m, "  D   "); else seq_printf( m, "%6d", i_cnt);									
}
	
static int axt_cfg_ugroups_seq_show( struct seq_file *m, void *v){  //user groups info show
	int			i;
	
	seq_printf( m, "\n");
	seq_printf( m,     "=================================================================================================\n");	
	seq_printf( m,     "=================================== User groups config status ===================================\n");	
		seq_printf( m, " UGROUP |          MAXIMUM SESSIONS             ||         WARNING SESSIONS              | UGROUP\n");
		seq_printf( m, "        |  MSG |  TCP  |  UDP  | ICMP  | OTHER  ||  MSG |  TCP  |  UDP  | ICMP  | OTHER  |\n");
	for ( i = 0; i < 64; i++) {
		seq_printf( m, "   +%02d  |  m%c  |",i, (axt_cfg_u_m_ison(1, i) ? '+' : '-'));
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.max[i].c_tcp));  seq_printf( m, " |");	
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.max[i].c_udp));  seq_printf( m, " |");	
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.max[i].c_icm));  seq_printf( m, " |");
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.max[i].c_oth));  seq_printf( m, "  ||  m%c  |", (axt_cfg_u_m_ison(0, i) ? '+' : '-'));
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.wrn[i].c_tcp));  seq_printf( m, " |");	
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.wrn[i].c_udp));  seq_printf( m, " |");	
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.wrn[i].c_icm));  seq_printf( m, " |");
		axt_cfg_ugroups_seq_ugcnt( m, READ_ONCE(axt_ucfg.wrn[i].c_oth));  seq_printf( m, "  |  +%02d\n", i);
											
	}
		seq_printf( m, "        |  MSG |  TCP  |  UDP  | ICMP  | OTHER  ||  MSG |  TCP  |  UDP  | ICMP  | OTHER  |\n");
		seq_printf( m, " UGROUP |          MAXIMUM SESSIONS             ||         WARNING SESSIONS              | UGROUP\n");
	    seq_printf( m, "=================================================================================================\n");	
	
	return 0;
}
// =================================== WORK with config data =================================

static axt_cfg_lconfig_t   *axt_cfg_get_actConfig(void) {
	//retun ptr for active Config or NULL if was not loaded
	int l_poolcgf_actn;
	l_poolcgf_actn = atomic_read(&axt_config_actn);
	if ((l_poolcgf_actn > 0) && (l_poolcgf_actn <=2 )) { //ACTIVE CONFIG WAS LOADED 
		return &axt_config[ l_poolcgf_actn ];
	} else return NULL; //ACTIVE CONFIG WAS not LOADED 
}

static axt_cfg_lconfig_t   *axt_cfg_init_actConfig(void) {
	//retun ptr for active Config or NULL if was not loaded
	int l_poolcgf_actn;
	l_poolcgf_actn = atomic_read(&axt_config_actn);
	if ((l_poolcgf_actn <= 0) || (l_poolcgf_actn > 2))  atomic_set(&axt_config_actn, 1);
	return axt_cfg_get_actConfig();
}

static uint32_t axt_cfg_get_nataddr(const uint32_t i_uaddr, uint8_t* v_trch,  uint8_t* v_usgr, int i_chk_usgr, uint32_t l_mark, int i_chk_mark) {
	axt_cfg_lconfig_t 			*l_curConfig;
	axt_cfg_natpool_rec_t 		*l_pool_arr;
	int 						i, l_pool_cnt;
	uint32_t 					l_nat_ip, l_addrh, l_us_start, l_us_end, l_nt_start;
	uint64_t 					l_base;
	
	//nat test ip work
	l_addrh = READ_ONCE(axt_xcfg.nattest_ip_u);
	if (unlikely( (l_addrh != 0) && (i_uaddr == l_addrh) )) {
		*v_usgr = READ_ONCE(axt_xcfg.nattest_ip_ug);
		*v_trch = READ_ONCE(axt_xcfg.nattest_ip_tc);
		return READ_ONCE(axt_xcfg.nattest_ip_n);
	}
	
	//normal work
	l_addrh=ntohl(i_uaddr);
	if ((l_curConfig = axt_cfg_get_actConfig()) != NULL) {
		l_pool_arr = l_curConfig->natpool_arr;
		l_pool_cnt = l_curConfig->natpool_cnt;
		for (i=0; i < l_pool_cnt; i++) {
			
			if ( (l_addrh >= (l_us_start = l_pool_arr[i].usrip_start)) && (l_addrh <= (l_us_end = l_pool_arr[i].usrip_end)) 
					&& (i_chk_usgr==0 || l_pool_arr[i].usgr==*v_usgr) 
					&& (i_chk_mark==0 || ( l_pool_arr[i].marked==0 || l_pool_arr[i].mark == l_mark) ) ) {
				l_nt_start = l_pool_arr[i].natip_start;
				if (l_pool_arr[i].hashtype == 0) {  //0 - linear (reciprocal_scale only)
					l_base = ((l_addrh - l_us_start)*(l_pool_arr[i].natip_end + 1 - l_nt_start  ))/(l_us_end  + 1 - l_us_start);
					l_nat_ip = l_nt_start + (uint32_t) l_base;
				} else { 							// 1-hash (jhash+reciprocal_scale)
					l_nat_ip = l_nt_start + reciprocal_scale( jhash_1word(l_addrh, 0), l_pool_arr[i].natip_end - l_nt_start + 1);
				}
				
				if ((l_nat_ip % 256==0)  && ((l_pool_arr[i].exclude&1) != 0)) l_nat_ip++; 
				else if ((l_nat_ip % 256==255) && ((l_pool_arr[i].exclude&2) != 0)) l_nat_ip--; 

				*v_trch = l_pool_arr[i].trch;
				*v_usgr = l_pool_arr[i].usgr;
				
				return htonl(l_nat_ip);
			}
		}
	}

	//pool not found 
	return 0;
}

// ============================ config load from init params
static int axt_cfg_init(void) {
	int 					l_res;
	size_t					l_sz;
	axt_cfg_lconfig_t 		*l_actCnf;
	char					l_buf[AXT_MAX_LINELEN];
	
	//safety protecion set \0 at the string end
	axt_cfg_u_init();
	
	l_actCnf = NULL;
	if ((l_sz=strscpy(l_buf, nat_pool, AXT_MAX_LINELEN)) < 0 ){
		printk(KERN_INFO "xt_ANAT ERROR: CFG  - Proceed error nat_pool parametr too long!\n");
		return -EINVAL;
	} else if(l_sz > 0) { //have nat_pool var
		if (!l_actCnf) {
			if (!(l_actCnf = axt_cfg_init_actConfig())) {
				printk(KERN_INFO "xt_ANAT ERROR: CFG  - Proceed error can't init active config at nat_pool!\n");
				return -EINVAL;
			}
		}
		if ( (l_res=axt_cfg_loadrec_natpool(l_buf, l_actCnf, 0)) )  return l_res;
	}
	if ((l_sz=strscpy(l_buf, nf_dest, AXT_MAX_LINELEN)) < 0 ){
		printk(KERN_INFO "xt_ANAT ERROR: CFG  - Proceed error nf_dest parametr too long!\n");
		return -EINVAL;
	} else if(l_sz > 0) { //have nat_pool var
		if (!l_actCnf) {
			if (!(l_actCnf = axt_cfg_init_actConfig())) {
				printk(KERN_INFO "xt_ANAT ERROR: CFG  - Proceed error can't init active config at nf_dest!\n");
				return -EINVAL;
			}
		}
		if ( (l_res=axt_cfg_loadrec_nf9dest(l_buf, l_actCnf, 0)) )  return l_res;
	}
	if (l_actCnf) {
		axt_cfg_loadend(l_actCnf);
	}	
	return 0;
}
	
static void axt_cfg_done(void) {
}
	
// ============================ config /proc/.... entry

//  init|done|work /proc/.... entry  
static int   axt_cfg_proc_open( struct inode  *i_inode, struct file  *i_file){  //interface standart call
	return single_open( i_file, axt_cfg_proc_show, NULL);
}

static const struct file_operations	  axt_cfg_config_fops={
	.owner = THIS_MODULE,
	.open = axt_cfg_proc_open,
	.release = single_release,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = axt_cfg_proc_write
};	

static int 	axt_cfg_ugroups_seq_open(struct inode *i_inode, struct file *i_file) {
    return single_open(i_file, axt_cfg_ugroups_seq_show, NULL);
}

static const struct file_operations axt_cfg_ugroups_seq_fops = {
    .open           = axt_cfg_ugroups_seq_open,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static void   axt_cfg_create_proc_fs(struct proc_dir_entry  *i_dir_node) {
	proc_create("config",0777,  i_dir_node, &axt_cfg_config_fops);
	proc_create("ugroups",	0644, i_dir_node, &axt_cfg_ugroups_seq_fops);
}

static void   axt_cfg_remove_proc_fs(struct proc_dir_entry  *i_dir_node) {
	remove_proc_entry( "config", i_dir_node );
	remove_proc_entry( "ugroups", i_dir_node );
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */