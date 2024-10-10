/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 
/*
This measges buffer is not aacuracy. It can do some mistakes on highload and low size! If it happen increment [MSG_MSRB_SZ2] parametr.
Active message full view (/proc/.../msga) output event in reverse order
Part message view (/proc/.../msgp) and freesed mesage view  (/proc/.../msgf) output event in normal order
*/
#ifndef SDY_PKC_F_T_xt_ANAT_pc_message
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_message 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

// e==evtp, m=msdt; p==proto, a==address, o==port, c==code, f==p+a+o; n==nat, u==usr, d==dst; g==user_group
#define AXT_MSGC_FREEPRTNF 		1 	// e=p(n),a(n); m=o(u)  			E-NATP:	ERROR No free port found at axt_htb_search_free_l4_port()
#define AXT_MSGC_FREEPRTLS 		2 	// e=p(n),a(n); m=o(u)				W-NATP:	Long search at axt_htb_search_free_l4_port()
#define AXT_MSGC_USRNATANF 		3 	// e=p(u),a(u); m=a(d),o(u) 		E-NATA:	ERROR No addres found for user address

#define AXT_MSGC_USRLIMWRN 		10 	// e=p(u),a(u),o(g); dt64=l_ss_cnt 	+W-ULIM:	Warning user use %d session more then wrn_limit
#define AXT_MSGC_USRLIMERR 		11 	// e=p(u),a(u),o(g); dt64=l_ss_cnt  +E-ULIM:	ERROR user use all %d session can't allocate more then err_limit
#define AXT_MSGC_USRBLOCKP 		12 	// e=p(u),a(u),o(g); dt64=l_pause 	+W-BLKP:	User on block or pause try create session 

#define AXT_MSGC_HTBUSRWRN 		21 	// e=p(u),a=l_hash),o(g); m=a(u)	+H-HUSR:	Warning user htables too many records 
#define AXT_MSGC_HTBINRWRN 		22 	// e=p(u),a=l_hash),o(g); m=f(u)	+W-HINR:	Warning inner htables too many records 
#define AXT_MSGC_HTBOUTWRN 		23 	// e=p(u),a=l_hash),o(g); m=f(n)	+W-HOUT:	Warning outer htables too many records 

#define AXT_MSGC_NF9BUFOVR 		31 	// e=c+0; dt64=ihead 				E-NFBO: ERROR Nf9 bufeer overflow at ihead: %lld 

#define AXT_MSGC_DBGIP			120 // e=f; m=f 						D-DBIP: DBG IP: .. %lld 
#define AXT_MSGC_DBG64			121 // e=f; dt64=ihead 					D-DB64: DBG 64: .. %lld 

//  ====
#define AXT_MSG_MIN_FREEZETIME 	3	// minimal timeout beetwen commands FREEZE seconds
#define AXT_MSG_MAX_DEEPSR_RPT 	30	// maximal deep of number messages for repeat search
#define AXT_MSG_MAX_DEEPSR_TMS 	60	// counter interval for repeating messages 

//  ====
#define AXT_MSG_TRF_RESULT 		0x01	// result 		=0 NF_DROP 						!=0 NF_ACCEPT
#define AXT_MSG_TRF_SESFND 		0x10	// session  	=0 not found				 	!=0 found
#define AXT_MSG_TRF_DIRECT 		0x20	// direction 	=0 OUT (from user) pkt (SNAT) 	!=0 IN (to user) pkt (DNAT) 
#define AXT_MSG_TRF_READY 		0x80	// is ready 	=0 not ready (writing) 			!=0 IN (to user) pkt (DNAT) 
//---------------------------------------------------
//---------------------------------------------------
struct	axt_msg_mdt_tpf_s {
	uint8_t						tflags;		//trace flags
	uint8_t 					proto;		//protocol
	uint8_t						s_usgr;		//session usgr
	uint8_t						s_trch;		//session trch
} __attribute__ ((packed));

union	axt_msg_mdt_tpf_u {
	struct axt_msg_mdt_tpf_s		d;
	uint32_t						dt32;
} __attribute__ ((packed));

typedef union axt_msg_mdt_tpf_u 	axt_msg_mdt_tpf_t;

struct axt_msg_tr_rec_s {
	axt_msg_mdt_tpf_t			tr;			//trace info
//	uint8_t							tr.d.tflags;		//trace flags
//	uint8_t 						tr.d.proto;			//protocol
//	uint8_t							tr.d.s_usgr;		//session usgr
//	uint8_t							tr.d.s_trch;		//session trch
	uint32_t 					u_addr;		//hton  user ip
	uint32_t 					n_addr;		//hton  nat ip
	uint32_t 					d_addr;		//hton  dest ip
	uint32_t 					s_addr;		//hton  session dest ip
	uint16_t 					u_port;		//hton  user port	
	uint16_t 					n_port;		//hton  nat port	
	uint16_t 					d_port;		//hton  dest port	
	uint16_t 					s_port;		//hton  session dest port	
	uint16_t 					pksz;		//? hton  packet size
	uint16_t 					jif_s;		//(jiffies to seconds) & 0xFFFF 
} __attribute__ ((packed));

typedef struct axt_msg_tr_rec_s 	axt_msg_tr_rec_t;
typedef struct axt_msg_tr_rec_s* 	axt_msg_tr_rec_p;

#define axt_msg_astr(val) ((axt_msg_tr_rec_t*)( val ))
//---------------------------------------------------
struct	axt_msg_mdt_prh_s {
	uint32_t 					addr;   //hton	
	uint16_t 					port;   //hton		
	uint8_t  					proto;  //hton
	int8_t  					code; 
} __attribute__ ((packed));

union axt_msg_mdt_u {
	uint64_t 					dt64;
	struct axt_msg_mdt_prh_s	prh;
	char						ch[4];
} __attribute__ ((packed));

typedef union axt_msg_mdt_u 	axt_msg_mdt_t;
typedef union axt_msg_mdt_u* 	axt_msg_mdt_p;

	
struct axt_msg_ms_rec_s {
    axt_msg_mdt_t				evtp;			//event type code = evtp.dt64
 	axt_msg_mdt_t				msdt;			//extended message data
	uint32_t					count;			//count events happen in deep interval
	uint32_t					sec;			//sec it happen first (axt_wtm_get_cur_s())
};

typedef struct axt_msg_ms_rec_s 	axt_msg_ms_rec_t;
typedef struct axt_msg_ms_rec_s* 	axt_msg_ms_rec_p;

#define axt_msg_asms(val) ((axt_msg_ms_rec_t*)( val ))
//---------------------------------------------------
//rbuf struc for working
struct axt_msg_rmsgb_s {
	//round buffer
	atomic64_t  			ihead;
	int64_t     			isize;  			//rb_data array size - must be^2
	uint64_t    			imask;  			//rb_data mask for ihead и rb_iend to find pos in rb_data
    void*					rb_msg;   			//ptr to array of records axt_nf9_pk_rec_s's	
};

typedef struct axt_msg_rmsgb_s 				axt_msg_rmsgb_t;
typedef struct axt_msg_rmsgb_s* 			axt_msg_rmsgb_p;

struct axt_msg_msbset_s {
	atomic_t			act_msb;   //index active buf in msb[]
	uint64_t			jiff_frz;
	spinlock_t 			lock_frz;
	uint32_t     		recsize;
	axt_msg_rmsgb_p		msb[2];
};

//---------------------------------------------------
typedef int	(*p_axt_msg_show_print_record)(struct seq_file *m, void* i_r);
//return 1 - if rec printed, 0 - if skiped

//---------------------------------------------------
/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_message
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_message 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */
//---------------------------------------------------
struct axt_msg_msbset_s		msbs = {0};
//---------------------------------------------------
struct axt_msg_msbset_s		trcs = {0};

//forward declaration
static inline int64_t  axt_msg_message_count(void);
//---------------------------------------------------

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_message
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_message 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

//======================================================================== buf inits 
static axt_msg_rmsgb_p  axt_msg_msb_create(const int32_t i_szpow2, const uint32_t i_recsize) {
	//i_recsize = sizeof(axt_msg_ms_rec_t)
	size_t 					l_brnum, l_msz;
	void* 					l_rbuf_dt;
	axt_msg_rmsgb_p 		l_rbuf;
	
	l_brnum = 1 << i_szpow2;
	l_msz = i_recsize * l_brnum;
	l_rbuf_dt = kzalloc(l_msz, GFP_KERNEL);
    if (l_rbuf_dt == NULL) {
		printk(KERN_WARNING "xt_ANAT ERROR: Msg/Trc ring buffer records table create error. Rec's: %ld. Mem need: %ld.\n", l_brnum,l_msz);
		return NULL;
	}
	printk(KERN_INFO "xt_ANAT INFO: Msg/Trc ring buffer records table created. Rec's: %ld. Mem used:%ld.\n", l_brnum, l_msz);

	l_msz = sizeof(axt_msg_rmsgb_t);
	l_rbuf = kzalloc(l_msz, GFP_KERNEL);
    if (l_rbuf == NULL) {
		printk(KERN_WARNING "xt_ANAT ERROR: Msg/Trc ring buffer create error. Mem need: %ld.\n", l_msz);
		kfree(l_rbuf_dt);
		return NULL;
	}
	printk(KERN_INFO "xt_ANAT INFO: Msg/Trc ring buffer created. Mem used:%ld.\n",l_msz);

	atomic64_set(&(l_rbuf->ihead), 0);
	l_rbuf->isize = l_brnum;
	l_rbuf->imask = 0xFFFFFFFFFFFFFFFF >> (64-i_szpow2);
	
    l_rbuf->rb_msg 	= l_rbuf_dt;
	return l_rbuf;	
}

static void  axt_msg_msb_free(axt_msg_rmsgb_p *v_rbuf) {
	if (v_rbuf) {
		if ((*v_rbuf) == NULL) return;
		if ((*v_rbuf)->rb_msg!= NULL) kfree((*v_rbuf)->rb_msg);
		kfree(*v_rbuf);
		v_rbuf=NULL;
	}
    printk(KERN_INFO "xt_ANAT INFO: Msg ring buffer free.\n");	
}
	
// msbs init
static int	axt_msg_msbs_init(struct axt_msg_msbset_s* v_msbs,  const size_t i_numsz2, const uint32_t i_recsize) {
	//size_t 				l_numsz2;
	axt_msg_rmsgb_p 	l_msb0, l_msb1;

	l_msb0 = axt_msg_msb_create(i_numsz2, i_recsize);
	if (!l_msb0) return -1; //is NULL
	l_msb1 = axt_msg_msb_create(i_numsz2, i_recsize);
	if (!l_msb1) { //is NULL
		axt_msg_msb_free(&l_msb1);
		return -1; 
	}
	spin_lock_init(&(*v_msbs).lock_frz);	
	(*v_msbs).jiff_frz = 0;
	(*v_msbs).recsize  = i_recsize;
	(*v_msbs).msb[0] = l_msb0;
	(*v_msbs).msb[1] = l_msb1;
	atomic_set(&(*v_msbs).act_msb,0);   //index active buf in msb[]}
	return 0;
}

// msbs done
static void  axt_msg_msbs_done(struct axt_msg_msbset_s* v_msbs) {
	axt_msg_msb_free(&(*v_msbs).msb[0]);
	(*v_msbs).msb[0] = NULL;
	axt_msg_msb_free(&(*v_msbs).msb[1]);
	(*v_msbs).msb[1] = NULL;
}

static int  axt_msg_msbs_freeze(struct axt_msg_msbset_s* v_msbs, size_t i_numsz2) {
	int 				l_actn, l_frizn;
	size_t 				l_brnum;
	axt_msg_rmsgb_p 	l_msbf, l_msbn;
	
	if ((*v_msbs).jiff_frz + AXT_MSG_MIN_FREEZETIME*HZ > get_jiffies_64() ) {
		printk( KERN_WARNING "xt_ANAT ERROR: Between FREEZE must be pause %d seconds.\n", AXT_MSG_MIN_FREEZETIME );
		return -1;
	}
	spin_lock_bh(&(*v_msbs).lock_frz);
	l_brnum = 1 << i_numsz2;

	l_actn  = atomic_read(&(*v_msbs).act_msb);
	l_frizn = 1 - l_actn;

	l_msbf  = (*v_msbs).msb[l_frizn];
	if (l_msbf->isize != l_brnum) { //message buf size must be changed
		l_msbn = axt_msg_msb_create(i_numsz2, (*v_msbs).recsize);
		if (!l_msbn) { //is NULL can't create new buf
			printk(KERN_WARNING "xt_ANAT WARNING: Msg ring buffer change size error. Old size keeped. Wrong size: %ld.\n", l_brnum);
		} else { //change friz buf ptr
			(*v_msbs).msb[l_frizn] = l_msbn;
			wmb();
			axt_msg_msb_free(&l_msbf);
			l_msbf = l_msbn;
		}
	}
	atomic64_set(&(l_msbf->ihead), 0); //reset buf possition
	atomic_set_release(&(*v_msbs).act_msb, l_frizn); 
	(*v_msbs).jiff_frz = get_jiffies_64();

	spin_unlock_bh(&(*v_msbs).lock_frz);
	return 0;
}

//============================================= messages
static int  axt_msg_message_freeze(void) {
	return axt_msg_msbs_freeze(&msbs,axt_aprm_getN32(&axt_aprm_msg_msrb_sz2));
}

static int  axt_msg_message_add_new(const axt_msg_rmsgb_p i_rbuf, const uint32_t i_sec, const uint64_t i_evtp, const uint64_t i_msdt) {
	uint64_t 				l_mpos;
	axt_msg_ms_rec_p 		l_rec;	
	
	l_mpos = (atomic64_inc_return(&i_rbuf->ihead) - 1) & (i_rbuf->imask);
	l_rec  = &(axt_msg_asms(i_rbuf->rb_msg)[l_mpos]);
	WRITE_ONCE(l_rec->count, 0);
	wmb();
	l_rec->evtp.dt64 = i_evtp;
	l_rec->msdt.dt64 = i_msdt;
	l_rec->sec = i_sec;
	wmb();
	WRITE_ONCE(l_rec->count, 1);	
	return 0;
}

static int  axt_msg_message_try_repeat(const axt_msg_rmsgb_p i_rbuf, const uint32_t i_sec, const uint64_t i_evtp) {
	int64_t 				l_spos,l_epos;
	uint64_t				l_mask;
	uint32_t 				e_sec;
	axt_msg_ms_rec_p 		l_rec;	

	l_spos = (atomic64_read(&i_rbuf->ihead));
	l_mask = i_rbuf->imask;
	l_epos = l_spos - AXT_MSG_MAX_DEEPSR_RPT; 	//search repeat in deep 
	l_epos = (l_epos < 0 ? 0 : l_epos); 		//control that we hav enought events for this deep
	e_sec = i_sec - AXT_MSG_MAX_DEEPSR_TMS; 	//search interval repeat in deep 
	l_spos--; 
	while (l_spos >= l_epos) {
		l_rec = &(axt_msg_asms(i_rbuf->rb_msg)[l_spos&l_mask]);
		if (unlikely ( (e_sec > l_rec->sec) ) ) return -1;  // events age more 1 min or buf overload
		if (unlikely ((i_evtp == l_rec->evtp.dt64) && (READ_ONCE(l_rec->count))) ) {
			l_rec->count++;
			return 0;
		}
		l_spos--; 
	}
	return -1;
}	

static int  axt_msg_message_add(const uint64_t i_evtp, const uint64_t i_msdt) {
	axt_msg_rmsgb_p 		l_msb;
	uint32_t 				l_sec;
		
	l_msb = msbs.msb[atomic_read(&msbs.act_msb)];
	if (unlikely (!(l_msb))) return -1; //NULL i_buf
	l_sec = (uint32_t) (axt_wtm_get_cur_s());
	if ((axt_msg_message_try_repeat(l_msb, l_sec, i_evtp))) return axt_msg_message_add_new(l_msb, l_sec, i_evtp, i_msdt);  
	return 0;
}

static inline int  axt_msg_message_ip(const int8_t i_code, uint8_t i_proto, uint32_t i_addr, uint16_t i_port,
											const int8_t i_dcode, uint8_t i_dproto, uint32_t i_daddr, uint16_t i_dport) {
	axt_msg_mdt_t		l_evtp = {.prh.code = i_code,  .prh.proto = i_proto,  .prh.addr = i_addr, .prh.port = i_port};
	axt_msg_mdt_t		l_msdt = {.prh.code = i_dcode, .prh.proto = i_dproto, .prh.addr = i_daddr,.prh.port = i_dport};
	
	return axt_msg_message_add(l_evtp.dt64, l_msdt.dt64);
}

static inline int  axt_msg_message_ipudt64(const int8_t i_code, uint8_t i_proto, uint32_t i_addr, uint16_t i_port, uint64_t i_udt64) {
	axt_msg_mdt_t		l_evtp = {.prh.code = i_code,  .prh.proto = i_proto,  .prh.addr = i_addr, .prh.port = i_port};
	
	return axt_msg_message_add(l_evtp.dt64, i_udt64);
}

//----------- message print

static int		axt_msg_show_print_msg(struct seq_file *m, void* i_r) {
	axt_msg_ms_rec_p 	l_r = (axt_msg_ms_rec_t*) i_r; 
	axt_msg_mdt_t 		e, d;

	e = l_r->evtp;
	d = l_r->msdt;
	
    /*seq_printf(m, "TM:%d CNT:%d    evtp C:%d P:%d A:%d O:%d     mstp:  C:%d P:%d A:%d O:%d  DT:%lld)\n", 
		l_r->sec, l_r->count, e.prh.code, e.prh.proto, e.prh.addr, e.prh.port, d.prh.code, d.prh.proto, d.prh.addr, d.prh.port, d.dt64);
	*/
	// fields addr, proto - are in hton format!!! 
	if (!(l_r->count)) return 0;
	axt_wst_seq_printf_dtm64(m, axt_wtm_utc_to_loc_s(l_r->sec)); 
	seq_printf(m," [%3d] ", l_r->count);
	switch ( e.prh.code ) {
		case  AXT_MSGC_FREEPRTNF : 
			seq_printf(m,"E-NATP: ERROR No free NAT port found!    PR=%d N=%pI4  U=:[%d]\n", e.prh.proto, &e.prh.addr, ntohs(d.prh.port)); 
			break;
		case  AXT_MSGC_FREEPRTLS : 
			seq_printf(m,"W-NATP: Long search free NAT port.       PR=%d N=%pI4  U=:[%d]\n", e.prh.proto, &e.prh.addr, ntohs(d.prh.port));
			break;
		case  AXT_MSGC_USRNATANF : 
			seq_printf(m,"E-NATA: ERROR No NAT addr for user addr! PR=%d U=%pI4:[%d]  D=[%pI4]\n", e.prh.proto, &e.prh.addr, ntohs(d.prh.port), &d.prh.addr );
			break;
		case  AXT_MSGC_USRLIMWRN : 
			seq_printf(m,"W-ULIM: User use a lot of session.       PR=%d U=%pI4 +%02d  SSCNT:[%lld]\n", e.prh.proto, &e.prh.addr, e.prh.port, d.dt64);
			break;
		case  AXT_MSGC_USRLIMERR : 
			seq_printf(m,"E-ULIM: ERROR User use too much session! PR=%d U=%pI4 +%02d  SSCNT:[%lld]\n", e.prh.proto, &e.prh.addr, e.prh.port, d.dt64);
			break;
		case  AXT_MSGC_USRBLOCKP : 
			seq_printf(m,"W-BLKP: User on block or pause try create session. PR=%d U=%pI4 +%02d  PAUSE_JS:[%lld]\n", e.prh.proto, &e.prh.addr, e.prh.port, d.dt64/HZ);
			break;
		case  AXT_MSGC_HTBUSRWRN : 
			seq_printf(m,"H-HUSR: User htbl has a lot of records!  PR=%d HASH=%d  U=[%pI4] +%02d\n", e.prh.proto, e.prh.addr, &d.prh.addr, e.prh.port);
			break;
		case  AXT_MSGC_HTBINRWRN : 
			seq_printf(m,"H-HINR: Inner htbl has a lot of records! PR=%d HASH=%d  U=[%pI4:%d] +%02d\n", e.prh.proto, e.prh.addr, &d.prh.addr, ntohs(d.prh.port), e.prh.port);
			break;
		case  AXT_MSGC_HTBOUTWRN : 
			seq_printf(m,"H-HOUT: Outer htbl has a lot of records! PR=%d HASH=%d  U=[%pI4:%d] +%02d\n", e.prh.proto, e.prh.addr, &d.prh.addr, ntohs(d.prh.port), e.prh.port);
			break;
		case  AXT_MSGC_NF9BUFOVR : 
			seq_printf(m,"E-NFBO: ERROR Nf9 bufeer overflow!       IHEAD=[%lld]\n", d.dt64);
			break;
		case  AXT_MSGC_DBGIP : 
			seq_printf(m,"D-DBIP: DBG IP!  PR=%d (%d)%pI4:%d  [PR=%d (%d)%pI4:%d C:%d]\n", e.prh.proto, e.prh.addr, &e.prh.addr, ntohs(e.prh.port),
					d.prh.proto, d.prh.addr, &d.prh.addr, ntohs(d.prh.port), d.prh.code);
			break;
		case  AXT_MSGC_DBG64 : 
			seq_printf(m,"D-DB64: DBG 64!  PR=%d (%d)%pI4:%d  [%lld]\n", e.prh.proto, e.prh.addr, &e.prh.addr, ntohs(e.prh.port), d.dt64);
			break;
		default :
			seq_printf(m,"E-UNKN: ERROR Unknow message code!       CODE=%d\n", e.prh.code);
	}		
	return 1;
}

//================================== trace
static int  axt_msg_trace_freeze(void) {
	return axt_msg_msbs_freeze(&trcs,axt_aprm_getN32(&axt_aprm_msg_trcb_sz2));
}


static void inline axt_msg_trace_add(const uint8_t i_tflags, const uint8_t i_proto, const uint8_t  i_usgr, const uint8_t  i_trch,
								const uint32_t i_uaddr, const uint32_t i_naddr, const uint32_t i_daddr, const uint32_t i_saddr, 
								const uint16_t i_uport, const uint16_t i_nport, const uint16_t i_dport, const uint16_t i_sport, 
								const uint32_t i_pksz) {
	axt_msg_mdt_tpf_t		l_tr = {.d.tflags=i_tflags, .d.proto=i_proto, .d.s_usgr=i_usgr, .d.s_trch=i_trch};	
	axt_msg_rmsgb_p 		l_msb;
	uint64_t 				l_mpos;
	axt_msg_tr_rec_p 		l_rec;	
		
	l_msb = trcs.msb[atomic_read(&trcs.act_msb)];
	if (unlikely (!(l_msb))) return; //NULL i_buf
	l_mpos = (atomic64_inc_return(&l_msb->ihead) - 1) & (l_msb->imask);
	l_rec  = &(axt_msg_astr(l_msb->rb_msg)[l_mpos]);
	WRITE_ONCE(l_rec->tr.dt32, 0);
	wmb();
	l_rec->u_addr = i_uaddr;
	l_rec->n_addr = i_naddr;
	l_rec->d_addr = i_daddr;
	l_rec->s_addr = i_saddr;
	
	l_rec->u_port = i_uport;
	l_rec->n_port = i_nport;
	l_rec->d_port = i_dport;
	l_rec->s_port = i_sport;
	
	l_rec->pksz   = i_pksz;
	l_rec->jif_s  = axt_wtm_get_cur_jif_s();
	wmb();
	WRITE_ONCE(l_rec->tr.dt32, l_tr.dt32);	
}
 /*
	return 0;
}
	uint8_t						tflags;		//trace flags
	uint8_t 					proto;		//protocol
	uint8_t						s_usgr;		//session usgr
	uint8_t						s_trch;		//session trch
} __attribute__ ((packed));

union	axt_msg_mdt_tpf_u {
	struct axt_msg_mdt_tpf_s		d;
	uint32_t						dt32;
} __attribute__ ((packed));

typedef union axt_msg_mdt_tpf_u 	axt_msg_mdt_tpf_t;

struct axt_msg_tr_rec_s {
	axt_msg_mdt_tpf_t			tr;			//trace info
//	uint8_t							tr.d.tflags;		//trace flags
//	uint8_t 						tr.d.proto;			//protocol
//	uint8_t							tr.d.s_usgr;		//session usgr
//	uint8_t							tr.d.s_trch;		//session trch
	uint32_t 					u_addr;		//hton  user ip
	uint32_t 					n_addr;		//hton  nat ip
	uint32_t 					d_addr;		//hton  dest ip
	uint32_t 					s_addr;		//hton  session dest ip
	uint16_t 					u_port;		//hton  user port	
	uint16_t 					n_port;		//hton  nat port	
	uint16_t 					d_port;		//hton  dest port	
	uint16_t 					s_port;		//hton  session dest port	
	uint16_t 					pksz;		//? hton  packet size
	uint16_t 					jif_s;		//(jiffies to seconds) & 0xFFFF 
	
	*/


//----------- trace print
static int		axt_msg_show_print_trc(struct seq_file *m, void* i_r) {

	axt_msg_tr_rec_p 		l_r = (axt_msg_tr_rec_t*) i_r; 
	axt_msg_mdt_tpf_t 		l_tr;
	uint8_t					l_tflags;
	int32_t					l_cur_js;
	
	l_tr 		= l_r->tr;
	l_tflags 	= l_tr.d.tflags;
    //seq_printf(m, "TM:%d CNT:%d    evtp C:%d P:%d A:%d O:%d     mstp:  C:%d P:%d A:%d O:%d  DT:%lld)\n", 
	//	l_r->sec, l_r->count, e.prh.code, e.prh.proto, e.prh.addr, e.prh.port, d.prh.code, d.prh.proto, d.prh.addr, d.prh.port, d.dt64);
	
	// fields addr, proto - are in hton format!!! 
	if ((l_tflags & AXT_MSG_TRF_READY) == 0) return 0; //was not writen yeat.
	
	l_cur_js = (axt_wtm_get_cur_jif_s() & 0xFFFF) - l_r->jif_s;
	if (l_cur_js < 0) l_cur_js += 0x10000;
	seq_printf( m,"[-%2dh%02dm%02d] %5d %s %s ", l_cur_js/3600, (l_cur_js/60)%60, (l_cur_js%60), l_r->pksz, ((l_tflags & AXT_MSG_TRF_RESULT) == 0 ? "DR" : "AC"),  
		((l_tflags & AXT_MSG_TRF_DIRECT) == 0 ? "->>" : "<<-") );	
	if ((l_tflags & AXT_MSG_TRF_SESFND) == 0) seq_printf(m,"+--^- "); else seq_printf(m,"+%02d^%c ", l_tr.d.s_usgr, l_tr.d.s_trch + 0x40);
	if (l_tr.d.proto == IPPROTO_TCP) seq_printf(m,"TCP ");
	else if (l_tr.d.proto == IPPROTO_UDP) seq_printf(m,"UDP ");
	else if (l_tr.d.proto == IPPROTO_ICMP) seq_printf(m,"ICMP");
	else seq_printf(m, "p%03d", l_tr.d.proto);
	seq_printf(m," U=%pI4:%d  N=%pI4:%d  D=%pI4:%d", &l_r->u_addr, ntohs( l_r->u_port), &l_r->n_addr, ntohs( l_r->n_port), &l_r->d_addr, ntohs( l_r->d_port)); 
	if ((l_tflags & AXT_MSG_TRF_SESFND) != 0) seq_printf(m," (S=%pI4:%d)", &l_r->s_addr, ntohs( l_r->s_port));
	seq_printf(m,"\n");
	return 1;
}

	
// ===================================== msg buf print show
static int		axt_msg_show_active_buf(struct seq_file *m, axt_msg_rmsgb_p i_msb, size_t i_recsize, p_axt_msg_show_print_record i_p_printrec) {
////return >=0 num rec printed, <0 - error code
	int64_t 				l_spos,l_epos, l_size;
	uint64_t				l_mask;
	uint32_t 				l_lines;
	char* 					l_rec;
	char*					l_recbuf;

	if (!(i_msb)) return -EINVAL;
	l_recbuf = kzalloc(i_recsize, GFP_KERNEL);
	if (!(l_recbuf)) {
		printk(KERN_INFO "xt_ANAT ERROR: MEMORY axt_msg_show_active_buf() cold not allocate memory l_recbuf!\n");
		return -ENOMEM;
	}

	l_spos = (atomic64_read(&i_msb->ihead));
	l_mask = i_msb->imask;
	l_size = i_msb->isize;
	l_epos = l_spos - l_size; 	//search repeat in deep part events
	l_epos = (l_epos < 0 ? 0 : l_epos); 		//control that we have more then isize events.
	l_spos--;
	l_lines = 0;
	while (l_spos >= l_epos) {
		l_rec = &(((char*)(i_msb->rb_msg))[(l_spos&l_mask)*i_recsize]); //we need to do full copy
		memcpy(l_recbuf, l_rec, i_recsize);
		rmb();
		if ((atomic64_read(&i_msb->ihead)) >= l_spos+l_size) break; // we find tail
		l_lines=l_lines + (*i_p_printrec)( m, (void*) l_recbuf);
		l_spos--; 
	}
	//seq_printf(m, "Messages: %d messages\n", l_lines);
	kfree(l_recbuf);
	return l_lines;	
}	
	
static int		axt_msg_show_part_buf(struct seq_file *m, axt_msg_rmsgb_p i_msb, int64_t i_from_back, size_t i_recsize, p_axt_msg_show_print_record i_p_printrec) {
////return >=0 num rec printed, <0 - error code
	int64_t 				l_spos,l_epos;
	uint64_t				l_mask;
	uint32_t 				l_lines;
	char*  					l_rec;	
	char*					l_recbuf;

	if (!(i_msb)) return -EINVAL;
	l_recbuf = kzalloc(i_recsize, GFP_KERNEL);
	if (!(l_recbuf)) {
		printk(KERN_INFO "xt_ANAT ERROR: MEMORY axt_msg_show_active_buf() cold not allocate memory l_recbuf!\n");
		return -ENOMEM;
	}

	l_epos = (atomic64_read(&i_msb->ihead));
	l_mask = i_msb->imask;
	l_spos = l_epos - i_from_back; 				//search repeat in deep part events
	l_spos = (l_spos < 0 ? 0 : l_spos); 		//control that we have more then isize events.
	l_lines = 0;
	while (l_spos < l_epos) {
		l_rec = &(((char*)(i_msb->rb_msg))[(l_spos&l_mask)*i_recsize]); //we need to do full copy
		memcpy(l_recbuf, l_rec, i_recsize);
		l_lines=l_lines + (*i_p_printrec)( m, (void*) l_recbuf);
		l_spos++; 
	}
	kfree(l_recbuf);
	return l_lines;	
}

// ===================================== /proc/.../msg<T>  work
// ---------- messages
static int		axt_msg_seq_show_mactive(struct seq_file *m,  void *v ) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	l_msb = msbs.msb[atomic_read(&msbs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Active messages buffer is destroyed or blocked\n");
	else {
		if ((l_res = axt_msg_show_active_buf(m, l_msb, msbs.recsize, axt_msg_show_print_msg)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Active buffer: %d messages\n", l_res);
	}
	return 0;
}

static int		axt_msg_seq_show_mpart(struct seq_file *m, void *v) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	
	l_msb = msbs.msb[atomic_read(&msbs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Active messages buffer is destroyed or blocked\n");
	else {
		if ((l_res = axt_msg_show_part_buf(m, l_msb, axt_aprm_getN32(&axt_aprm_msg_msrb_partn), msbs.recsize, axt_msg_show_print_msg)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Active buffer part: %d messages\n", l_res);
	}
	return 0;
}

static int		axt_msg_seq_show_mfreez(struct seq_file *m, void *v) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	
	l_msb = msbs.msb[1-atomic_read(&msbs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Frozen messages buffer is destroyed or blocked\n");
	else if ( !(spin_trylock(&msbs.lock_frz)) ) seq_printf(m, "Frozen messages is blocked\n");	
	else {
		if ((l_res = axt_msg_show_part_buf(m, l_msb, l_msb->isize, msbs.recsize, axt_msg_show_print_msg)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Frozen buffer: %d messages\n", l_res);
		spin_unlock(&msbs.lock_frz);
	}
	return 0;
}
// ---------- trace
static int		axt_msg_seq_show_tactive(struct seq_file *m,  void *v ) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	l_msb = trcs.msb[atomic_read(&trcs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Active trace buffer is destroyed or blocked\n");
	else {
		if ((l_res = axt_msg_show_active_buf(m, l_msb, trcs.recsize, axt_msg_show_print_trc)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Active buffer: %d pkts\n", l_res);
	}
	return 0;
}

static int		axt_msg_seq_show_tpart(struct seq_file *m, void *v) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	
	l_msb = trcs.msb[atomic_read(&trcs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Trace active buffer is destroyed or blocked\n");
	else {
		if ((l_res = axt_msg_show_part_buf(m, l_msb, axt_aprm_getN32(&axt_aprm_msg_trcb_partn), trcs.recsize, axt_msg_show_print_trc)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Active buffer part: %d pkts\n", l_res);
	}
	return 0;
}

static int		axt_msg_seq_show_tfreez(struct seq_file *m, void *v) {
	axt_msg_rmsgb_p 		l_msb;
	int32_t 				l_res;
	
	l_msb = trcs.msb[1-atomic_read(&trcs.act_msb)]; //get frezz buf
	if (!(l_msb)) seq_printf(m, "Frozen trace buffer is destroyed or blocked\n");
	else if ( !(spin_trylock(&trcs.lock_frz)) ) seq_printf(m, "Frozen messages is blocked\n");	
	else {
		if ((l_res = axt_msg_show_part_buf(m, l_msb, l_msb->isize, trcs.recsize, axt_msg_show_print_trc)) < 0 ) 
			seq_printf(m, "Error: %d messages\n", l_res);
		else  
			seq_printf(m, "Frozen buffer: %d pkts\n", l_res);
		spin_unlock(&trcs.lock_frz);
	}
	return 0;
}
// ===================== init|done|work /proc/.... entry
// -------------- messages
 static int		axt_msg_stat_seq_open_mactive(struct inode *inode, struct file *file) {
    return single_open(file, axt_msg_seq_show_mactive, NULL);
}
 static int		axt_msg_stat_seq_open_mpart(struct inode *inode, struct file *file) {
    return single_open(file, axt_msg_seq_show_mpart, NULL);
}

 static int		axt_msg_stat_seq_open_mfreez(struct inode *inode, struct file *file) {
	return single_open(file, axt_msg_seq_show_mfreez, NULL);
}

static const struct file_operations  axt_msg_stat_seq_fops_mactive = {
    .open           = axt_msg_stat_seq_open_mactive,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static const struct file_operations  axt_msg_stat_seq_fops_mpart = {
    .open           = axt_msg_stat_seq_open_mpart,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static const struct file_operations  axt_msg_stat_seq_fops_mfreez = {
    .open           = axt_msg_stat_seq_open_mfreez,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

// -------------- trace
 static int		axt_msg_stat_seq_open_tactive(struct inode *inode, struct file *file) {
    return single_open(file, axt_msg_seq_show_tactive, NULL);
}
 static int		axt_msg_stat_seq_open_tpart(struct inode *inode, struct file *file) {
    return single_open(file, axt_msg_seq_show_tpart, NULL);
}

 static int		axt_msg_stat_seq_open_tfreez(struct inode *inode, struct file *file) {
	return single_open(file, axt_msg_seq_show_tfreez, NULL);
}

static const struct file_operations  axt_msg_stat_seq_fops_tactive = {
    .open           = axt_msg_stat_seq_open_tactive,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static const struct file_operations  axt_msg_stat_seq_fops_tpart = {
    .open           = axt_msg_stat_seq_open_tpart,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static const struct file_operations  axt_msg_stat_seq_fops_tfreez = {
    .open           = axt_msg_stat_seq_open_tfreez,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};
//--------------- create/remove
static void  axt_msg_create_proc_fs(struct proc_dir_entry *i_dir_node) {
    proc_create("msga", 0644, i_dir_node, &axt_msg_stat_seq_fops_mactive);	//messages active
    proc_create("msgp", 0644, i_dir_node, &axt_msg_stat_seq_fops_mpart);	//messages part 
    proc_create("msgf", 0644, i_dir_node, &axt_msg_stat_seq_fops_mfreez);	//messages frees
	proc_create("trca", 0644, i_dir_node, &axt_msg_stat_seq_fops_tactive);	//trace active
    proc_create("trcp", 0644, i_dir_node, &axt_msg_stat_seq_fops_tpart);	//trace part 
    proc_create("trcf", 0644, i_dir_node, &axt_msg_stat_seq_fops_tfreez);	//trace frees
}

static void  axt_msg_remove_proc_fs(struct proc_dir_entry *i_dir_node) {
	remove_proc_entry( "msga", i_dir_node );
	remove_proc_entry( "msgp", i_dir_node );
	remove_proc_entry( "msgf", i_dir_node );
	remove_proc_entry( "trca", i_dir_node );
	remove_proc_entry( "trcp", i_dir_node );
	remove_proc_entry( "trcf", i_dir_node );
}

// ==================================== cnt repport
static inline int64_t  axt_msg_message_count(void){
	axt_msg_rmsgb_p 		l_msb;
	
	l_msb = msbs.msb[atomic_read(&msbs.act_msb)];
	return (l_msb ? atomic64_read(&l_msb->ihead) : -1);
}

//======================================================================== module init
// nf9 init 
static int   axt_msg_init(void) {	
	if ( axt_msg_msbs_init(&msbs, axt_aprm_getN32(&axt_aprm_msg_msrb_sz2), sizeof(axt_msg_ms_rec_t)) ) return -1; //error at init
	if ( axt_msg_msbs_init(&trcs, axt_aprm_getN32(&axt_aprm_msg_trcb_sz2), sizeof(axt_msg_tr_rec_t)) ) {
		axt_msg_msbs_done(&msbs);
		return -1; //error at init
	}
	return 0;
}

// nf9 done 
static void   axt_msg_done(void) { 
	axt_msg_msbs_done(&msbs);
	axt_msg_msbs_done(&trcs);
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */