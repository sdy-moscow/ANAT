/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 
/*
It is 3 parametr's types we will use:
iprm - init parametrs, 
			They sets on module starting and do not changing on module work. 
			So, thread can only read them without any limitation.
			User can change it only on module startup by setting module params in command line.
			Usualy, it's used for tables and buffers size settings.
			
aprm - atomic parametrs, 
			They are atomic_t, so it can be set and read only by atomic opration. 
			It's can be chaging by user or by threads during module work, without limitation of use.
			User can change it by '[CMD_SET_EPAR_<T>: <PARAM_NAME> = <VALUE>]' config line send to /proc/../config . 

vprm - versioned parametrs.
			They are can be any type, but they read, change and set are needing spinlock by call axt_prm_vprm_lock_xxxx() functions.
			On finishing change any of these parametrs you must unlock  spilock by call axt_prm_vprm_unlock_change().
			Func axt_prm_vprm_unlock_change() do inc(axt_prm_vprm_version),  unlock spinlock and reurn new value of axt_prm_vprm_version.
			Variable atomic64_t axt_prm_vprm_version show treads current wersion of vprm's. 
			It is initialized  = 1, and inc at least once on init or change vprm value.
			
			Standart algoritm to use vprm in treads based is on use they local (thread) copy with no locking check local and global versions number.
			Usualy it use local int64_t l_vprm_version var inited to 0, to comare it whith atomic64_read(axt_prm_vprm_version) value. 
			On starting thread work check l_vprm_version == atomic64_read(axt_prm_vprm_version). 
			If versions changed thread do spinlock by call axt_prm_vprm_lock_soft() or axt_prm_vprm_lock_hard().
			Copy needed vprm's to they local values copy, and do l_vprm_version = atomic64_read(axt_prm_vprm_version).
			On finish unlock spinlock by call axt_prm_vprm_unlock_read().
			Difference between axt_prm_vprmlock_soft() and axt_prm_vprmlock_hard() 
				axt_prm_vprm_lock_soft() - it try to do spinlock, on success return 1 else 0.
				axt_prm_vprm_lock_hard() - it do spinlock any case by waiting until it stay free. 
				
https://devarea.com/linux-kernel-development-kernel-module-parameters/

*/

#ifndef SDY_PKC_F_T_xt_ANAT_pc_param
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_param 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

//forward declaration
static inline int64_t 	axt_aprm_getN64( int64_t* v_param);
static inline int32_t	axt_aprm_getN32( int32_t* v_param);

/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_param
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_param 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

//#define NATIP_CREATE_SESSION_LOCK_SZ 1000  
// iprm default value (can be changed only at module start)
#define AXT_DEF_HTB_INOUT_HTSZ 			256 * 1024		// in|out sessions hash tables size
#define AXT_DEF_HTB_USER_HTSZ 			64 * 1024		// users hash table size
#define AXT_DEF_HTB_NATIPSPL_HTSZ		1024			// nat ip searh port lock hash table size
#define AXT_DEF_NF9_NFRB_DATA_SZ2		14				// rb_data table size pow 2 : 1<<N  by deafult N=14 BufSz=16384 

// vprm default value								
#define AXT_DEF_NF9_MTU_UDPLOAD	 		1300   	// size of UDP load (pk size exclude ip & udp headers) use MTU & speedup
#define AXT_DEF_NF9_TEMPLATE_ID			300		// template ID in NetFlow 9 packets
#define AXT_DEF_NF9_SOURCE_ID			1		// source ID in NetFlow 9 packets
#define AXT_DEF_NF9_TMPL_SEMPTY			1		// send template flag if no event on NF9_DELAY_SEC:  =1 - send , =0 - do not; !! set =1 for udp keepalive work
#define AXT_DEF_NF9_TMPL_SQUANT			1		// send template in nf9 pk: 0 - don't send with dataflow; 1 - always send tmpl; =(n) - send tmpl every (n) packet

// aprm default value
#define AXT_DEF_NF9_DELAY_SEC			10		// *HZ approximately maximum delay between event and it send nf9 in seconds (it is udp keepalive interval too)
#define AXT_DEF_NF9_SSK_INTRV_S			3*3600	// session keepalive send nf9 interval (event = 3)  min 360 - max 1000000 (if eq 1m or more = send off)
#define AXT_DEF_NF9_EVENTS_ON			1		// generate session events for nf9  =1 - on; = 0 - off (stop NF9 data flow generation? use if nf9 not needed)

#define AXT_DEF_HTB_USR_MAX_SS_TCP		4096	// maximum number of TCP seesions per user
#define AXT_DEF_HTB_USR_MAX_SS_UDP		4096	// maximum number of UDP seesions per user
#define AXT_DEF_HTB_USR_MAX_SS_ICM		256		// maximum number of ICMP seesions per user
#define AXT_DEF_HTB_USR_MAX_SS_OTH		64		// maximum number of OTHER PROTO seesions per user

#define AXT_DEF_HTB_USR_WRN_SS_TCP		2048	// warning over number TCP seesions per user
#define AXT_DEF_HTB_USR_WRN_SS_UDP		2048	// warning over number UDP seesions per user
#define AXT_DEF_HTB_USR_WRN_SS_ICM		128		// warning over number ICMP PROTO seesions per user
#define AXT_DEF_HTB_USR_WRN_SS_OTH		32		// warning over number OTHER PROTO seesions per user

#define AXT_DEF_HTB_HTB_WRN_RNUM		32		// warning too much records in htables cell 1..USHRT_MAX

#define AXT_DEF_MSG_MSRB_SZ2			10		// rb_msg table size pow 2 : 1<<N  by deafult N=10 BufSz=1024 
#define AXT_DEF_MSG_MSRB_PARTN			50		// rb_msg table part show line number /proc/.../msgp

#define AXT_DEF_MSG_TRCB_SZ2			10		// rb_msg table size pow 2 : 1<<N  by deafult N=10 BufSz=1024 
#define AXT_DEF_MSG_TRCB_PARTN			50		// rb_msg table part show line number /proc/.../msgp

#define AXT_DEF_NAT_LOCFRWD_POLICY		0 		// default local forward policy (DNAT no session found) 0-DROP 1-ACCEPT

#define AXT_DEF_WTM_TMZN_MNT			3*60	// default timezone offset minute +3h GMT MSK 

//================  vprm, aprm, iprm params hold vars	
// vprm params vars
static uint32_t		axt_vprm_nf9_pdu_loadsz		= AXT_DEF_NF9_MTU_UDPLOAD; 		// size of UDP load (pk size exclude ip & udp headers) use MTU & speedup
static uint32_t		axt_vprm_nf9_templateID		= AXT_DEF_NF9_TEMPLATE_ID;      // template ID in NetFlow 9 packets
static uint32_t		axt_vprm_nf9_srcID			= AXT_DEF_NF9_SOURCE_ID;		// source ID in NetFlow 9 packets
static uint32_t		axt_vprm_nf9_tmpl_sempty	= AXT_DEF_NF9_TMPL_SEMPTY;		// send template at NF9_THR_MAX_PAUSE_JF lease flag; use =1 for udp keepalive 
static uint32_t		axt_vprm_nf9_tmpl_squant	= AXT_DEF_NF9_TMPL_SQUANT;		// quant for send template with dataflow in NetFlow 9 packets; use for speedup

// aprm params vars
static int64_t		axt_aprm_nf9_max_delay_sec	= (AXT_DEF_NF9_DELAY_SEC);		// approximately maximum delay between session event and it send nf9 

static int32_t		axt_aprm_htb_usr_maxss_tcp	= (AXT_DEF_HTB_USR_MAX_SS_TCP);	// max TCP seesions per user
static int32_t		axt_aprm_htb_usr_maxss_udp	= (AXT_DEF_HTB_USR_MAX_SS_UDP);	// max UDP seesions per user
static int32_t		axt_aprm_htb_usr_maxss_icm	= (AXT_DEF_HTB_USR_MAX_SS_ICM);	// max ICMP seesions per user
static int32_t		axt_aprm_htb_usr_maxss_oth	= (AXT_DEF_HTB_USR_MAX_SS_OTH);	// max OTHER PROTO seesions per user

static int32_t		axt_aprm_htb_usr_wrnss_tcp	= (AXT_DEF_HTB_USR_WRN_SS_TCP);	// warning TCP seesions per user
static int32_t		axt_aprm_htb_usr_wrnss_udp	= (AXT_DEF_HTB_USR_WRN_SS_UDP);	// warning UDP seesions per user
static int32_t		axt_aprm_htb_usr_wrnss_icm	= (AXT_DEF_HTB_USR_WRN_SS_ICM);	// warning ICMP seesions per user
static int32_t		axt_aprm_htb_usr_wrnss_oth	= (AXT_DEF_HTB_USR_WRN_SS_OTH);	// warning OTHER PROTO seesions per user

static int32_t		axt_aprm_htb_htb_wrn_rnm	= (AXT_DEF_HTB_HTB_WRN_RNUM);	// warning too much records in htables cell

static int32_t		axt_aprm_nf9_ssk_intrv_ms	= (AXT_DEF_NF9_SSK_INTRV_S*1000);	// session keepalive send nf9 interval (event = 3) 
static int32_t		axt_aprm_nf9_events_on		= (AXT_DEF_NF9_EVENTS_ON);		// generate session events for nf9  =1 - on; = 0 - off 

static int32_t 		axt_aprm_msg_msrb_sz2		= (AXT_DEF_MSG_MSRB_SZ2); 		// message rb_msg table size pow 2,by deafult N=10 BufSz=1024 
static int32_t 		axt_aprm_msg_msrb_partn		= (AXT_DEF_MSG_MSRB_PARTN); 	// message rb_msg table part show line number

static int32_t 		axt_aprm_msg_trcb_sz2		= (AXT_DEF_MSG_TRCB_SZ2); 		// trace rb_msg table size pow 2,by deafult N=10 BufSz=1024 
static int32_t 		axt_aprm_msg_trcb_partn		= (AXT_DEF_MSG_TRCB_PARTN); 	// trace rb_msg table part show line number

static int32_t 		axt_aprm_nat_locfrwd_pol	= (AXT_DEF_NAT_LOCFRWD_POLICY);	// default local forward policy (DNAT no sess) 0-DROP 1-ACCEPT

static int32_t 		axt_aprm_wtm_tmzn_mnt		= (AXT_DEF_WTM_TMZN_MNT); 		// default timezone offset minute +3h GMT MSK 

// iprm params vars
static int			axt_iprm_htb_INOUT_HTSZ 	= AXT_DEF_HTB_INOUT_HTSZ; 		// in|out sessions hash size		
static int			axt_iprm_htb_USER_HTSZ 		= AXT_DEF_HTB_USER_HTSZ; 		// users hash size
static int 			axt_iprm_htb_NATIPSPL_HTSZ	= AXT_DEF_HTB_NATIPSPL_HTSZ;	// nat ip searh port lock hash size
static int     		axt_iprm_nf9_NFRB_DATA_SZ2	= AXT_DEF_NF9_NFRB_DATA_SZ2; 	// rec num in rb_data pow2, def 14 : 1<<14 = 16384 event record

//================  vprm work vars	
static	atomic64_t 				axt_prm_vprm_version = ATOMIC_INIT(1);  	// vprm current version
static 	DEFINE_SPINLOCK(		axt_prm_vprm_lock );						// spinlock for read & write for vprm vars
		
//================  module paprametrs declaration and varset		
static int inout_htsz = AXT_DEF_HTB_INOUT_HTSZ; //copied to axt_iprm_htb_INOUT_HTSZ 
module_param(inout_htsz, int, 0444);
MODULE_PARM_DESC(inout_htsz, "in|out sessions hash size, default = 256k record (range: 1k - maxint)");

static int user_htsz = AXT_DEF_HTB_USER_HTSZ;  	//copied to axt_iprm_USER_HT_SZ
module_param(user_htsz, int, 0444);
MODULE_PARM_DESC(user_htsz, "users hash size, default = 64k record (range: 1k - maxint)");

static int nat_htsz = AXT_DEF_HTB_NATIPSPL_HTSZ;  	//copied to axt_iprm_htb_NATIPSPL_HTSZ
module_param(nat_htsz, int, 0444);
MODULE_PARM_DESC(nat_htsz, "nat ip serach port lock hash size, default = 1k record (range: 256 - maxint)");

static int nfrb_sz2 = AXT_DEF_NF9_NFRB_DATA_SZ2;  	//copied to axt_iprm_nf9_NFRB_DATA_SZ2
module_param(nfrb_sz2, int, 0444);
MODULE_PARM_DESC(nfrb_sz2, "rec num in nf9 event ring buffer (pow 2), deafult = 14 (16384) (range: 10 - 20)");

static char nat_pool_buf[AXT_MAX_LINELEN] = "";
static char *nat_pool = nat_pool_buf;
module_param(nat_pool, charp, 0444);
MODULE_PARM_DESC(nat_pool, "nat ip pool range ips-ipe, best to set over /proc/net/ANAT/config");

static char nf_dest_buf[AXT_MAX_LINELEN] = "";
static char *nf_dest = nf_dest_buf;
module_param(nf_dest, charp, 0444);
MODULE_PARM_DESC(nf_dest, "Netflow v9 collector (addr1:port1), best to set over /proc/net/ANAT/config");


/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_param
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_param 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */


//======================================================================== params setup 
// ================================  params checking
// check parametr is in rang
static int inline   axt_prm_chkrng_N( const int64_t i_val, const int64_t i_min,  const int64_t i_max) {
	return ( (i_val >= i_min) && (i_val <=i_max) ? 0 : -1);
}

static int  axt_prm_chk_N_err( const int64_t i_val,  const int64_t i_min,  const int64_t i_max, const char* i_name ) {
	if (!(axt_prm_chkrng_N (i_val, i_min, i_max))) return 0;
	printk(KERN_WARNING "xt_ANAT ERROR: PRM Parameter %s = %lld is not in range: %lld - %lld !\n", i_name, i_val, i_min, i_max);
	return -EINVAL;
}	

// ================================ iprm params setting
static int inline   axt_prm_chk_INOUT_HTSZ(const int64_t i_val)		{ return axt_prm_chk_N_err(i_val, 1024, INT_MAX, "inout_htsz (INOUT_HTSZ)"); }
static int inline   axt_prm_chk_USER_HTSZ(const int64_t i_val)		{ return axt_prm_chk_N_err(i_val, 1024, INT_MAX, "user_htsz (USER_HTSZ)"); }
static int inline   axt_prm_chk_NATIPSPL_HTSZ(const int64_t i_val)	{ return axt_prm_chk_N_err(i_val, 256,  INT_MAX, "nat_htsz (NATIPSPL_HTSZ)"); }
static int inline   axt_prm_chk_NFRB_DATA_SZ2(const int64_t i_val)	{ return axt_prm_chk_N_err(i_val,  10,   	 20, "nfrb_sz2 (NFRB_DATA_SZ2)"); }

static int   axt_prm_copy_iprm_to_vars( void ) {
	if ( (axt_prm_chk_INOUT_HTSZ(inout_htsz)) || (axt_prm_chk_USER_HTSZ(user_htsz)) 
		 || (axt_prm_chk_NATIPSPL_HTSZ(nat_htsz)) || (axt_prm_chk_NFRB_DATA_SZ2(nfrb_sz2)) ) return -EINVAL;
		axt_iprm_htb_INOUT_HTSZ 		= inout_htsz;
		axt_iprm_htb_USER_HTSZ 			= user_htsz;
		axt_iprm_htb_NATIPSPL_HTSZ		= nat_htsz;
		axt_iprm_nf9_NFRB_DATA_SZ2		= nfrb_sz2;
	return 0;
}
// ================================ vprm params setting
static inline int     	axt_prm_vprm_lock_soft(void)		{ return spin_trylock_bh(&axt_prm_vprm_lock); }
static inline void    	axt_prm_vprm_lock_hard(void) 		{ spin_lock_bh(&axt_prm_vprm_lock); }
static inline void   	axt_prm_vprm_unlock_read(void) 		{ spin_unlock_bh(&axt_prm_vprm_lock); }

static inline int64_t   axt_prm_vprm_unlock_change(void)	{ 
	int l_vprm_version = atomic64_inc_return(&axt_prm_vprm_version);  
	spin_unlock_bh(&axt_prm_vprm_lock);
	return l_vprm_version;
}

static inline int    	axt_vprm_set_u32( uint32_t* v_var, const int64_t i_val, const int64_t i_min, const int64_t i_max, const char* i_name) {
	int 	l_res;
	if ( !(l_res = axt_prm_chk_N_err(i_val, i_min, i_max, i_name)) ) {
		axt_prm_vprm_lock_hard();
		*v_var = i_val;
		axt_prm_vprm_unlock_change();
	}
	return l_res;
}
// ================================ aprm params getting setting
static inline int64_t 	axt_aprm_getN64( int64_t* v_param) {
	int64_t l_res = READ_ONCE(*v_param);
	return l_res;
}

static inline int32_t	axt_aprm_getN32( int32_t* v_param) {
	int32_t l_res = READ_ONCE(*v_param);
	return l_res;
}

static inline void   	axt_aprm_setN64( int64_t* v_param, const int64_t i_val) {
	WRITE_ONCE( *v_param, i_val); 
}

static inline void   	axt_aprm_setN32( int32_t* v_param, const int32_t i_val) {
	WRITE_ONCE( *v_param, i_val); 
}

static inline int   axt_aprm_setN64err( int64_t* v_param, const int64_t i_val, const int64_t i_min, const int64_t i_max, const char* i_name) {
	int 	l_res;
	if ( !(l_res = axt_prm_chk_N_err(i_val, i_min, i_max, i_name)) ) WRITE_ONCE( *v_param, i_val); 
	return l_res;
}

static inline int   axt_aprm_setN32err( int32_t* v_param, const int64_t i_val, const int64_t i_min, const int64_t i_max, const char* i_name) {
	int 	l_res;
	if ( !(l_res = axt_prm_chk_N_err(i_val, i_min, i_max, i_name)) ) WRITE_ONCE( *v_param, i_val); 
	return l_res;
}

//====================== CFG process config file records
  
static int axt_cfg_setNParam(char *i_buf, const int i_line) {
	char 	l_name_buf[31] = {0};  //SDY max param name legth  30
	char 	l_val_buf[81]  = {0};  //SDY max param value legth 80
	int		l_len=0;
	int  	l_res;

	int64_t	l_val=0;
	
	//check last is ']' and send to axt_prm_docmd_bufToNameVal
	l_len = strnlen(i_buf,AXT_MAX_LINELEN);
	if (i_buf[l_len-1] != ']') { //error terminated string
		printk(KERN_WARNING "xt_ANAT ERROR: PRM - Wrong CMD_SET_PAR_N command in config line [%d]. Not terminated by ']'.\n", i_line);
		return -EINVAL;
	}
	if ( (l_res=axt_wst_trimbufNameEqVal(&i_buf[15], &i_buf[l_len-1], l_name_buf, sizeof(l_name_buf),  l_val_buf, sizeof(l_val_buf))) ) {
		printk(KERN_WARNING "xt_ANAT ERROR: PRM - Wrong CMD_SET_PAR_N command format <PARAM_NAME> = <VALUE> in config line [%d]. Error: [%d] (%s).\n", 
								i_line, l_res, axt_wst_ierror(l_res));
		return -EINVAL;
	}
	
	if ( (l_res=axt_wst_valueToInt64(l_val_buf, &l_val)) ) {
		printk(KERN_WARNING "xt_ANAT ERROR: PRM - Wrong CMD_SET_PAR_N <VALUE> is not uint64 value at line [%d]. Error: [%d] (%s).\n",
								i_line, l_res, axt_wst_ierror(l_res));
		return -EINVAL;
	}
	l_res = -EINVAL;
	
	if 		(strcmp(  l_name_buf, "NF9_EVENTS_ON") == 0)   l_res = axt_aprm_setN32err(&axt_aprm_nf9_events_on, l_val,     0,         1, "[NF9_EVENTS_ON]");
	else if (strcmp(  l_name_buf, "NF9_MTU_UDPLOAD") == 0) l_res = axt_vprm_set_u32(&axt_vprm_nf9_pdu_loadsz,  l_val, 400,      8000, "[NF9_MTU_UDPLOAD]");
	else if (strcmp(  l_name_buf, "NF9_TEMPLATE_ID") == 0) l_res = axt_vprm_set_u32(&axt_vprm_nf9_templateID,  l_val, 256, USHRT_MAX, "[NF9_TEMPLATE_ID]");
	else if (strcmp(  l_name_buf, "NF9_SOURCE_ID") 	 == 0) l_res = axt_vprm_set_u32(&axt_vprm_nf9_srcID, 	   l_val,   0,   INT_MAX, "[NF9_SOURCE_ID]");
	else if (strcmp(  l_name_buf, "NF9_TMPL_SQUANT") == 0) l_res = axt_vprm_set_u32(&axt_vprm_nf9_tmpl_sempty, l_val,   0,   INT_MAX, "[NF9_TMPL_SQUANT]");
	else if (strcmp(  l_name_buf, "NF9_TMPL_SEMPTY") == 0) l_res = axt_vprm_set_u32(&axt_vprm_nf9_tmpl_squant, l_val,   0,         1, "[NF9_TMPL_SEMPTY]");
	else if (strcmp(  l_name_buf, "NF9_DELAY_SEC") == 0) l_res = axt_aprm_setN64err(&axt_aprm_nf9_max_delay_sec, l_val,   7,   INT_MAX, "[NF9_TMPL_SEMPTY]");
	else if (strcmp(  l_name_buf, "NF9_SSK_INTRV_S") == 0) {
		(l_res = axt_prm_chk_N_err( l_val, 360, 1000000, "[NF9_SSK_INTRV_S]"));
		axt_aprm_setN32(&axt_aprm_nf9_ssk_intrv_ms, l_val * 1000); 
	}
	//usr session limits
	else if (strcmp(  l_name_buf, "USR_MAX_SS_TCP") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_maxss_tcp, l_val, 0,  USHRT_MAX, "[USR_MAX_SS_TCP]");
	else if (strcmp(  l_name_buf, "USR_MAX_SS_UDP") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_maxss_udp, l_val, 0,  USHRT_MAX, "[USR_MAX_SS_UDP]");
	else if (strcmp(  l_name_buf, "USR_MAX_SS_ICM") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_maxss_icm, l_val, 0,  USHRT_MAX, "[USR_MAX_SS_ICM]");
	else if (strcmp(  l_name_buf, "USR_MAX_SS_OTH") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_maxss_oth, l_val, 0,  USHRT_MAX, "[USR_MAX_SS_OTH]");
	else if	(strcmp(  l_name_buf, "USR_WRN_SS_TCP") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_wrnss_tcp, l_val, 0,  USHRT_MAX, "[USR_WRN_SS_TCP]");
	else if (strcmp(  l_name_buf, "USR_WRN_SS_UDP") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_wrnss_udp, l_val, 0,  USHRT_MAX, "[USR_WRN_SS_UDP]");
	else if (strcmp(  l_name_buf, "USR_WRN_SS_ICM") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_wrnss_icm, l_val, 0,  USHRT_MAX, "[USR_WRN_SS_ICM]");
	else if (strcmp(  l_name_buf, "USR_WRN_SS_OTH") == 0) l_res = axt_aprm_setN32err(&axt_aprm_htb_usr_wrnss_oth, l_val, 0,  USHRT_MAX, "[USR_WRN_SS_OTH]");

	else if (strcmp(  l_name_buf, "MSG_MSRB_SZ2") == 0)   l_res = axt_aprm_setN32err(&axt_aprm_msg_msrb_sz2,   l_val,8,        20, "[MSG_MSRB_SZ2]");
	else if (strcmp(  l_name_buf, "MSG_MSRB_PART") == 0)  l_res = axt_aprm_setN32err(&axt_aprm_msg_msrb_partn, l_val,1, USHRT_MAX, "[MSG_MSRB_PART]");

	else if (strcmp(  l_name_buf, "MSG_TRCB_SZ2") == 0)   l_res = axt_aprm_setN32err(&axt_aprm_msg_trcb_sz2,   l_val,8,        20, "[MSG_MSRB_SZ2]");
	else if (strcmp(  l_name_buf, "MSG_TRCB_PART") == 0)  l_res = axt_aprm_setN32err(&axt_aprm_msg_trcb_partn, l_val,1, USHRT_MAX, "[MSG_MSRB_PART]");

	else if (strcmp(  l_name_buf, "NAT_LOCFRWD_POL") == 0) l_res = axt_aprm_setN32err(&axt_aprm_nat_locfrwd_pol, l_val, 0, 1, "[NAT_LOCFRWD_POL]");

	else if (strcmp(  l_name_buf, "WTM_TMZN_MNT") == 0) l_res = axt_aprm_setN32err(&axt_aprm_wtm_tmzn_mnt, l_val,-15*60, 15*60, "[WTM_TMZN_MNT]");

	else {
		printk(KERN_WARNING "xt_ANAT ERROR: PRM - Wrong CMD_SET_PAR_N <PARAM_NAME> is not found at line [%d].\n", i_line);
		return -EINVAL;
	}
	printk(KERN_INFO "xt_ANAT INFO: PRM CMD_SET_PAR_N line [%d] <PARAM_NAME>: %s <VALUE>: %s (= %lld).\n", i_line, l_name_buf, l_val_buf, l_val);
	return l_res;
}	

static int axt_prm_docmd_SetParam(char *i_buf, const int i_line) {
	int l_errc;
	l_errc = -1;
	if (strncmp( i_buf, "[CMD_SET_PRM_N", 14)  == 0)  l_errc = axt_cfg_setNParam(i_buf,i_line); 
	else {
		printk(KERN_WARNING "xt_ANAT ERROR: PRM - Wrong command CMD_SET_PAR_<T>. Unknown <T>ype at line [%d].\n", i_line);
		return -EINVAL;
	}
	return l_errc;
}
//======================================================================== params print

// params print by /proc/.../statistics >>
static int		axt_prm_params_seq_show(struct seq_file *m, void *v) {
	seq_printf(m, "\n");
	seq_printf(m, "#==== MODULE INIT PARAMS ===============================================================================\n");	
    seq_printf(m, "inout_htsz (INOUT_HTSZ):    %d -- In|out sessions tables hash size. (%d - %d)\n", axt_iprm_htb_INOUT_HTSZ, 1024, INT_MAX);
    seq_printf(m, "user_htsz  (USER_HTSZ):     %d -- Users hash table size. (%d - %d)\n", axt_iprm_htb_USER_HTSZ,1024, INT_MAX);
    seq_printf(m, "nat_htsz   (NATIPSPL_HTSZ): %d -- Nat ip serach port lock hash size. (%d - %d)\n", axt_iprm_htb_NATIPSPL_HTSZ,1024, INT_MAX);
    seq_printf(m, "nfrb_sz2   (NFRB_DATA_SZ2): %d -- [%d] Rec num in nf9 event rbuffer (pow 2). (%d - %d)\n", axt_iprm_nf9_NFRB_DATA_SZ2, 1<<axt_iprm_nf9_NFRB_DATA_SZ2,10, 20);
	seq_printf(m, "\n"); 
	seq_printf(m, "#==== MODULE CHANGEABLE 'N'umeric PARAMS. === Use config command [CMD_SET_PRM_N: <PARAM_NAME> = <VALUE> ] ====\n"); 
	seq_printf(m, "\n");
	seq_printf(m, "#= NET FLOW 9 CONTROL:\n"); 
    seq_printf(m, "NF9_EVENTS_ON:   %d -- Generate session events for nf9. (1=on,0=off)\n", axt_aprm_getN32(&axt_aprm_nf9_events_on));
    seq_printf(m, "NF9_MTU_UDPLOAD: %d -- UDP pk payload max size (MTU & speedup). (%d - %d)\n", axt_vprm_nf9_pdu_loadsz, 400, 8000);
    seq_printf(m, "NF9_TEMPLATE_ID: %d -- Template ID in nf9 packets. (%d - %d)\n", axt_vprm_nf9_templateID, 256, USHRT_MAX);
    seq_printf(m, "NF9_SOURCE_ID:   %d -- Source ID in nf9 packets. (%d - %d)\n", axt_vprm_nf9_srcID, 0, INT_MAX);
	seq_printf(m, "NF9_TMPL_SQUANT: %d -- Send template quant in nf9 pk. (0=no tmpl, 1=always) (%d - %d)\n", axt_vprm_nf9_tmpl_squant, 0, INT_MAX);
	seq_printf(m, "NF9_TMPL_SEMPTY: %d -- Send template in emty nf9 pk. (UDP keepalive) (1=on,0=off)\n", axt_vprm_nf9_tmpl_sempty);
	seq_printf(m, "NF9_DELAY_SEC:   %lld -- Max delay event send nf9 (sec)(UDP keepalive) (%d - %d)\n", axt_aprm_getN64(&axt_aprm_nf9_max_delay_sec), 7, INT_MAX);
	seq_printf(m, "NF9_SSK_INTRV_S: %d -- Active sessions keepalive event send (sec). (max=off) (%d - %d)\n", axt_aprm_getN32(&axt_aprm_nf9_ssk_intrv_ms)/1000, 360, 1000000);
	seq_printf(m, "\n");
	seq_printf(m, "#= USER SESSION NUMBER CONTROL:\n"); 
	seq_printf(m, "USR_MAX_SS_TCP:  %d -- Maximum num of TCP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_maxss_tcp), 0, USHRT_MAX);
	seq_printf(m, "USR_MAX_SS_UDP:  %d -- Maximum num of UDP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_maxss_udp), 0, USHRT_MAX);
	seq_printf(m, "USR_MAX_SS_ICM:  %d -- Maximum num of ICMP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_maxss_icm), 0, USHRT_MAX);
	seq_printf(m, "USR_MAX_SS_OTH:  %d -- Maximum num of OTHER PROTO sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_maxss_oth), 0, USHRT_MAX);
	seq_printf(m, "USR_WRN_SS_TCP:  %d -- Warning num of TCP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_wrnss_tcp), 0, USHRT_MAX);
	seq_printf(m, "USR_WRN_SS_UDP:  %d -- Warning num of UDP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_wrnss_udp), 0, USHRT_MAX);
	seq_printf(m, "USR_WRN_SS_ICM:  %d -- Warning num of ICMP sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_wrnss_icm), 0, USHRT_MAX);
	seq_printf(m, "USR_WRN_SS_OTH:  %d -- Warning num of OTHER PROTO sessions per user. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_usr_wrnss_oth), 0, USHRT_MAX);
	seq_printf(m, "\n");
	seq_printf(m, "#= HASH TABLES CONTROL:\n"); 
	seq_printf(m, "HTB_WRN_RNUM:    %d -- Warning num too much records in htables cell. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm), 1, USHRT_MAX);
	seq_printf(m, "\n");
	seq_printf(m, "#= MESSAGE TABLE BUFFER CONTROL:\n"); 
	seq_printf(m, "MSG_MSRB_SZ2:    %d -- [%d] Rec num in message table (pow 2). FREEZE to change. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_msg_msrb_sz2), 1<<axt_aprm_getN32(&axt_aprm_msg_msrb_sz2), 8, 20);
	seq_printf(m, "MSG_MSRB_PART:   %d -- Message num on /proc/../msgp. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_msg_msrb_partn), 1, USHRT_MAX);
	seq_printf(m, "\n");
	seq_printf(m, "#= TRACE TABLE BUFFER CONTROL:\n"); 
	seq_printf(m, "MSG_TRCB_SZ2:    %d -- [%d] Rec num in trace table (pow 2). FREEZE to change. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_msg_trcb_sz2), 1<<axt_aprm_getN32(&axt_aprm_msg_trcb_sz2), 8, 20);
	seq_printf(m, "MSG_TRCB_PART:   %d -- Message num on /proc/../trcp. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_msg_trcb_partn), 1, USHRT_MAX);
	seq_printf(m, "\n");
	seq_printf(m, "#= TRAFIC CONTROL:\n"); 
	seq_printf(m, "NAT_LOCFRWD_POL: %d -- Local forward policy (DNAT no session found) 0-DROP 1-ACCEPT (%d - %d)\n", axt_aprm_getN32(&axt_aprm_nat_locfrwd_pol), 0, 1);
	seq_printf(m, "#= TIME OUTPUT CONTROL:\n"); 
	seq_printf(m, "WTM_TMZN_MNT:    %d -- Timezone offset (minutes) def +3h GMT MSK. (%d - %d)\n", axt_aprm_getN32(&axt_aprm_wtm_tmzn_mnt), -15*60, 15*60);
	return 0;
}

//  init|done|work /proc/.... entry  
 static int		axt_prm_stat_seq_open(struct inode *inode, struct file *file) {
    return single_open(file, axt_prm_params_seq_show, NULL);
}

static const struct file_operations  axt_prm_stat_seq_fops = {
    .open           = axt_prm_stat_seq_open,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static void  axt_prm_create_proc_fs(struct proc_dir_entry *i_dir_node) {
    proc_create("params", 0644, i_dir_node, &axt_prm_stat_seq_fops);
}

static void  axt_prm_remove_proc_fs(struct proc_dir_entry *i_dir_node) {
	remove_proc_entry( "params", i_dir_node );
}

//======================================================================== module init
// module init params working 

static int axt_prm_init(void) {
	int 				l_res;
	
	if ((l_res=axt_prm_copy_iprm_to_vars())) return l_res;
	return 0;
}

static void axt_prm_done(void) {
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */