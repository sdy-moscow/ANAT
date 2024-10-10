/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* axt_NAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
   
*/ 

#ifndef SDY_PKC_F_T_xt_ANAT_pc_htables
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_htables 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

// users data htable storage (user == inner.ipaddr)
struct axt_htb_htuser_usr_s {
    struct 		rcu_head rcu;
    struct 		hlist_node list_node;
    uint32_t 	addr;					//inner.ipaddr
    uint16_t 	tcp_count;				//tcp session user count
    uint16_t 	udp_count;				//udp session user count
	uint16_t 	icmp_count;				//icmp session user count
    uint16_t 	other_count;			//other proto session user count
    uint64_t 	pause_to_jif64;			//nat paused to jif64 value (after finish set = 0) if = ~0 - it is blocked (if need can be done as 32bit)
	uint8_t		usgr;  					// user group number 0 - default  
	uint8_t 	idle;					//count of timer check have 0 session all types
};
typedef struct axt_htb_htuser_usr_s 		axt_htb_htuser_usr_t;
typedef struct axt_htb_htuser_usr_s* 		axt_htb_htuser_usr_p;

struct axt_htb_htuser_s {
    uint16_t 			use;	//records in user list
    spinlock_t 			lock;	//l_hash entry update lock
    struct hlist_head 	user;	//axt_htb_htuser_usr_s - SDY TODO will be set and use in future - for cnt per user
};
typedef struct axt_htb_htuser_s 	axt_htb_htuser_t;
typedef struct axt_htb_htuser_s* 	axt_htb_htuser_p;

// session in|out htable storage
union axt_htb_ssg_u {				//sstart_gms & garbage list union
  	uint64_t 		sstart_gms;		//! not hton: ses start real time UTC (time from 1970(0) in milliseconds  : axt_wtm_get_cur_ms()
	axt_htl_node_t	grb_node;		//garbage htlist node
} __attribute__ ((packed));

typedef union axt_htb_ssg_u 	axt_htb_ssg_u_t;
//typedef union axt_htb_ssg_u* 	axt_htb_ssg_u_p;


//============== session in|out htable storage === TEST structure start
// --- id 
struct axt_htb_ssi_x_id_s	{
    uint64_t					i64;			//quick search|store 64 bit id
};

typedef struct axt_htb_ssi_x_id_s 	axt_htb_ssi_x_id_t;

// --- h(eader)
struct axt_htb_ssi_h_su_s	{
  	uint64_t 					utcms;			//sstart_gms : ses start real time UTC (time from 1970(0) in milliseconds  : axt_wtm_get_cur_ms()
	axt_htb_htuser_usr_p		usr;			//ptr to usr data set
} __attribute__ ((packed));

typedef struct axt_htb_ssi_h_su_s 	axt_htb_ssi_h_su_t;

struct axt_htb_ssi_h_rc_s	{
    struct rcu_head 			rcu;
};

typedef struct axt_htb_ssi_h_rc_s 	axt_htb_ssi_h_rc_t;

union axt_htb_ssi_h_u	{
	axt_htb_ssi_h_rc_t			rc;
	axt_htb_ssi_h_su_t			su;
};

typedef union axt_htb_ssi_h_u 		axt_htb_ssi_h_t;

// --- d(estination) (a)ddress + pool (r)ule id	
struct axt_htb_ssi_d_ar_s	{
    uint8_t  					trch;	  		//trace char num charcode(<Tchar>) - charcode('A') + 1 ---  ^<char>   
    uint8_t  					usgr;  			//user group number 0 -default  
	
    uint16_t 					port;			//hton	dst_port
    uint32_t 					addr;			//hton	dst_addr
} __attribute__ ((packed));

typedef struct axt_htb_ssi_d_ar_s 	axt_htb_ssi_d_ar_t;

union axt_htb_ssi_d_u	{
	axt_htb_ssi_d_ar_t			ar;				//d(estination) (a)ddress + pool (r)ule id		
	axt_htb_ssi_x_id_t			id;				//quick search|store 64 bit id
};

typedef union axt_htb_ssi_d_u 		axt_htb_ssi_d_t;

// --- o(utside) address + (p)roto + (f)lags	
struct axt_htb_ssi_o_pf_s	{
    uint8_t 					flags;  		//flags
	uint8_t  					proto;  		//hton	proto
    uint16_t 					port;			//hton	out_port
    uint32_t 					addr;			//hton	out_addr
} __attribute__ ((packed));

typedef struct axt_htb_ssi_o_pf_s 	axt_htb_ssi_o_pf_t;

union axt_htb_ssi_o_u	{
	axt_htb_ssi_o_pf_t			pf;				//o(ut) address + (p)roto + (f)lags
	axt_htb_ssi_x_id_t			id;				//quick search|store 64 bit id
};

typedef union axt_htb_ssi_o_u 		axt_htb_ssi_o_t;

// --- i(inside) address + (t)imeout + (k)eepalive nf9 interval	
struct axt_htb_ssi_i_tk_s	{
    uint8_t 					tmt;  			//timeout
	uint8_t  					kaint;  		//keepalive interval nf9 	
    uint16_t 					port;			//hton	in_port
    uint32_t 					addr;			//hton	in_addr
} __attribute__ ((packed));

typedef struct axt_htb_ssi_i_tk_s 	axt_htb_ssi_i_tk_t;

union axt_htb_ssi_i_u	{
	axt_htb_ssi_i_tk_t			tk;				//o(ut) address + (p)roto + (f)lags
	axt_htb_ssi_x_id_t			id;				//quick search|store 64 bit id
};

typedef union axt_htb_ssi_i_u 		axt_htb_ssi_i_t;

//----- session information data storage (lists element inside htb) -----

struct axt_htb_ssi_s	{
	//first 32 - low use data, up 32 most use data
/* --- 0 --- */
	axt_htb_ssi_h_t			h;				//h(eader)
/* 16 	
	struct rcu_head 			h.rc.rcu;
	-----
	uint64_t 					h.su.utcms;  	//ses start real time UTC msec
	axt_htb_htuser_usr_p		h.su.usr;		//ptr to usr data set
*/ 
	uint64_t				nopayload;		//now nopayload - for future use
/* 8 
*/
	axt_htb_ssi_d_t			d;				//d(estination) (a)ddress + pool (r)ule id
/* 8 
    uint8_t  					d.ar.trch;	  	//trace char num charcode(<Tchar>) - charcode('A') + 1 ---  ^<char>   
    uint8_t  					d.ar.usgr;  	//user group namber 0 -default  
    uint16_t 					d.ar.port;		//hton	dst_port
    uint32_t 					d.ar.addr;		//hton	dst_addr
	-----
    uint64_t					d.id.i64;		//quick search|store 64 bit id для d.ar
*/ 
/* --- 32 --- */
	axt_htb_ssi_o_t			o;				//o(utside) address + (p)roto + (f)lags
/* 8 
	uint8_t 					o.pf.flags;  	//flags
	uint8_t  					o.pf.proto;  	//hton	proto
    uint16_t 					o.pf.port;		//hton	out_port
    uint32_t 					o.pf.addr;		//hton	out_addr
	-----
    uint64_t					o.id.i64;		//quick search|store 64 bit id для o.pf
*/ 

    axt_htl_node_t 			out_htln;   	//out_list_node out(er) htl(ist) n(ode) (next ptr)
    axt_htl_node_t 			inn_htln;   	//in_list_node  inn(er) htl(ist) n(ode) (next ptr)
/* 2*8=16
*/ 
	axt_htb_ssi_i_t			i;				//i(inside) address + (t)imeout + (k)eepalive nf9 interval	
/* 8 
    uint8_t 					i.tk.tmt;  		//timeout
	uint8_t  					i.tk.kaint;  	//keepalive interval nf9 	
    uint16_t 					i.tk.port;		//hton	in_port
    uint32_t 					i.tk.addr;		//hton	in_addr
	-----
    uint64_t					i.id.i64;		//quick search|store 64 bit id для o.pf
*/ 
};

typedef struct axt_htb_ssi_s 		axt_htb_ssi_t;
typedef struct axt_htb_ssi_s* 		axt_htb_ssi_p;

// ==========================================================
// new hash headers are *axt_htl_node_s
struct axt_htb_iossi_s {		
    axt_htl_node_t 		hd;			// head ptr for axt_htl_node_t of list ssi
};

typedef  struct axt_htb_iossi_s 		axt_htb_iossi_t;
typedef  struct axt_htb_iossi_s*		axt_htb_iossi_p;

// ==========================================================
// ip in/out hash table
struct axt_htb_inout_s {			// !!! it sizeof() = 64 byte == cashe line size
    struct axt_htb_iossi_s 	ss[6];	// inside struct axt_htb_inout_ses_s
    spinlock_t 				lock;		// update headers lock
    uint16_t 				use[6];		// records in session list

};

typedef struct axt_htb_inout_s 		axt_htb_inout_t;
typedef struct axt_htb_inout_s* 	axt_htb_inout_p;

#define  axt_htb_inout_getjk( j, k, i) ({   \
			j= i / 6;						\
			k= i % 6; })
			
#define  axt_htb_inout_for_each_from_to( j, k, i, fromi, toi)	\
	for ( i = fromi, axt_htb_inout_getjk(j, k, i) ;				\
	     i < toi;  i++, ( k<5 ? k++ : ({ k=0; j++;}) ) )


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_htables
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_htables 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

static axt_htb_htuser_p 	axt_ht_users	 = NULL;		// users l_hash table
static spinlock_t 			*axt_ht_natipspl = NULL;		// nat ip searh port lock l_hash table


static axt_htb_inout_p   	axt_ht_inner	 = NULL;		// inner ip session l_hash table
static axt_htb_inout_p   	axt_ht_outer	 = NULL;		// outer ip session l_hash table


// ==========================================================
// новые таблицы 
/*
static axt_htb_iossi_p   		axt_ht_innssi	 = NULL;		// inner ip session l_hash table
static axt_htb_iossi_p   		axt_ht_outssi	 = NULL;		// outer ip session l_hash table
*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
!!!!!!!!!!!!!!!!!!!!!!!!!!! ATTENTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!

 NEVER NEVER NEVER NEVER NEVER USE 
	axt_ht_innssi[]->hd.next without axt_htl_next_psn()
		if you want next use ONLY:
			axt_htl_next_psn(&ht[i].hd);
			or psn htl methods
		PLEASE check by found all 'hd' word in your code 
		
	for axt_ht_outssi it is recommended for safty code too!
		
!!!!!!!!!!!!!!!!!!!!!!!!!!!! ATTENTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_htables
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_htables 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

//===============================================
//---- basic ht functions
static inline void axt_htb_flag_setb(long i_nr, axt_htb_ssi_p  i_ses) {
		set_bit(i_nr, (void *) &i_ses->o.pf.flags);
}

static inline void axt_htb_flag_clearb(long i_nr, axt_htb_ssi_p  i_ses) {
		clear_bit(i_nr, (void *) &i_ses->o.pf.flags);
}

//-- l_hash make functions for l_hash tables
static inline uint32_t 	axt_htb_hash_for_natipspl(const uint32_t i_addr) {
	return reciprocal_scale(jhash_1word(i_addr, 0), axt_iprm_htb_NATIPSPL_HTSZ);
}

static inline uint32_t 	axt_htb_hash_for_inout(const uint8_t i_proto, const uint32_t i_addr, const uint16_t i_port) {
    return reciprocal_scale(jhash_3words((u32) i_proto, i_addr, (u32) i_port, 0), axt_iprm_htb_INOUT_HTSZ);
}

static inline uint32_t 	axt_htb_hash_for_user(const uint32_t i_addr, uint8_t i_usgr) {
    return reciprocal_scale(jhash_2words(i_addr, (u32) i_usgr, 0), axt_iprm_htb_USER_HTSZ);
}

//===============================================

// add  session in inner&outer hash tables
static void 		axt_htb_add_session(axt_htb_ssi_p  i_ses) {
    uint32_t 				l_hash, j,k, l_cnt;
	int32_t					l_max_htb_nht_rnm;
	uint8_t 				l_proto;	
	
	l_max_htb_nht_rnm = axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm);
	l_proto = i_ses->o.pf.proto;
	
	l_hash  = axt_htb_hash_for_inout(l_proto, i_ses->i.tk.addr, i_ses->i.tk.port);
	axt_htb_inout_getjk( j, k, l_hash);
    spin_lock_bh(&axt_ht_inner[j].lock);
    axt_hla_add_rcu(&i_ses->inn_htln, &axt_ht_inner[j].ss[k].hd);
	l_cnt = axt_wat_inc16_return(&(axt_ht_inner[j].use[k]));
	spin_unlock_bh(&axt_ht_inner[j].lock);
	if (l_cnt > l_max_htb_nht_rnm) {
		//printk(KERN_WARNING "xt_ANAT create_nat_session WARNING: Attantion axt_ht_inner[l_hash].use > wrn \n");
		axt_msg_message_ip(AXT_MSGC_HTBINRWRN, l_proto, l_hash, i_ses->d.ar.usgr, 0, l_proto, i_ses->i.tk.addr, i_ses->i.tk.port);
		axt_cnt_inc(&cnt_ht_mhinner);
 	}	
	axt_cnt_setmax(&cnt_ht_hinnerm, l_cnt);

    l_hash = axt_htb_hash_for_inout(l_proto, i_ses->o.pf.addr, i_ses->o.pf.port);
 	axt_htb_inout_getjk( j, k, l_hash);
	spin_lock_bh(&axt_ht_outer[j].lock);
    axt_hla_add_rcu(&i_ses->out_htln, &axt_ht_outer[j].ss[k].hd);
	l_cnt = axt_wat_inc16_return(&(axt_ht_outer[j].use[k]));
    spin_unlock_bh(&axt_ht_outer[j].lock);
	if (l_cnt > l_max_htb_nht_rnm) {
		//printk(KERN_WARNING "xt_ANAT create_nat_session WARNING: Attantion axt_ht_outer[l_hash].use > wrn \n");
		axt_msg_message_ip(AXT_MSGC_HTBOUTWRN, l_proto, l_hash, i_ses->d.ar.usgr, 0, l_proto, i_ses->o.pf.addr, i_ses->o.pf.port);
		axt_cnt_inc(&cnt_ht_mhouter);
	}	
	axt_cnt_setmax(&cnt_ht_houterm, l_cnt);
}

//===============================================

// lookup  session in inner outer hash tables
static axt_htb_ssi_p		axt_htb_lookup_session_in(const uint8_t i_proto, const uint32_t i_addr, const uint16_t i_port) {
    uint32_t					l_hash, j,k;
    axt_htb_ssi_p				l_ses;
    axt_htl_node_p				l_head;
	axt_htb_inout_p 			l_htb;
	
	l_htb  = axt_ht_inner;
    l_hash = axt_htb_hash_for_inout(i_proto, i_addr, i_port);
	axt_htb_inout_getjk( j, k, l_hash);
	
    //if (axt_wat_get16(&(l_htb[j].use[k])) == 0) return NULL; //it can be use but...
    l_head = &l_htb[j].ss[k].hd;
    axt_hla_for_each_entry_rcu(l_ses, l_head, inn_htln) {
       if ( l_ses->i.tk.addr == i_addr && l_ses->i.tk.port == i_port && l_ses->o.pf.proto == i_proto &&  
					((READ_ONCE(l_ses->o.pf.flags)&AXT_FLAG_DEPRICT) == 0) ) {
           return l_ses;
        }
    }
    return NULL;
}

// find  session in outer table
static axt_htb_ssi_p		axt_htb_lookup_session_out(const uint8_t i_proto, const uint32_t i_addr, const uint16_t i_port) {
    uint32_t 					l_hash, j,k;
    axt_htb_ssi_p				l_ses;
    axt_htl_node_p				l_head;
	axt_htb_inout_p 			l_htb;
	
	l_htb  = axt_ht_outer;
    l_hash = axt_htb_hash_for_inout(i_proto, i_addr, i_port);
	axt_htb_inout_getjk( j, k, l_hash);

	//if (axt_wat_get16(&(l_htb[j].use[k])) == 0) return NULL; //it can be use but...
    l_head = &l_htb[j].ss[k].hd;  
	// if list emtpy we well go to return 0;
    axt_hla_for_each_entry_rcu(l_ses, l_head, out_htln) {
       if ( l_ses->o.pf.addr == i_addr && l_ses->o.pf.port == i_port && l_ses->o.pf.proto == i_proto && 
					((READ_ONCE(l_ses->o.pf.flags)&AXT_FLAG_DEPRICT) == 0) ) { 
            return l_ses;
        }
    }
    return NULL;
}

//===============================================
//---- free nat port search 

//==== SDY new fast lookup

static inline int  axt_htb_lookup_freeport_fast(axt_htb_inout_p i_htb, const uint8_t i_proto, const uint32_t i_addr, const uint16_t i_port) {
    uint32_t 			l_hash, j,k;
	
    l_hash = axt_htb_hash_for_inout(i_proto, i_addr, i_port);
	axt_htb_inout_getjk( j, k, l_hash);	
	return ( !(axt_hla_ptr_isempty(&(i_htb[j].ss[k].hd))) );
}

static uint16_t  axt_htb_search_free_l4_port(const uint8_t i_proto, const uint32_t i_nataddr, const uint16_t i_userport) {  
//N_ SDY TODO REBUILD LOCK AFTER FIND AND CHECK AND ADD  --- move to donat 
    uint16_t 		i, k, ct, l_freeport;

	//SDY at first lets try 16 search by round jumping with 8-64 try in full search 
	//SDY need report not first hit add try 2,3,4 ?
	l_freeport=ntohs(i_userport);
	axt_cnt_inc(&cnt_fps_ft000);
    for(i = 0; i < 16; i++) {
		ct = 8 << (i & 7); 
		if (unlikely(i==1)) axt_cnt_inc(&cnt_fps_ft002);
		else if (unlikely(i==8)) axt_cnt_inc(&cnt_fps_ft009);
		for (k = 0; k < ct; k++) {
			if (l_freeport < 1024) l_freeport += 1024;
			if(!axt_htb_lookup_session_out(i_proto, i_nataddr, htons(l_freeport))) {
				return htons(l_freeport);
			}
			l_freeport++;
			if (unlikely((i==0)&&(k==0))) axt_cnt_inc(&cnt_fps_ft001);
		}
		get_random_bytes( &l_freeport, sizeof (l_freeport) );
    }
	axt_cnt_inc(&cnt_fps_st001);
	axt_msg_message_ip(AXT_MSGC_FREEPRTLS, i_proto, i_nataddr, 0, 0,0,0,i_userport);
	
 	//SDY at the end lets try 6 search by round jumping with 1024-32768 try in fast search
	l_freeport=ntohs(i_userport);
    for(i = 0; i < 6; i++) {
		if (unlikely(i==3)) axt_cnt_inc(&cnt_fps_st003);
		//else if (unlikely(i==4)) axt_cnt_inc(&cnt_fps_st004);
		//else if (unlikely(i==5)) axt_cnt_inc(&cnt_fps_st005);
		ct = 1024 << (i & 7); 
		for (k = 0; k < ct; k++) {
			if (l_freeport < 1024) l_freeport += 1024;
			if(!axt_htb_lookup_freeport_fast(axt_ht_outer, i_proto, i_nataddr, htons(l_freeport))) {
				return htons(l_freeport);
			}
			l_freeport++;
		}
		//l_freeport = rand32();
		get_random_bytes( &l_freeport, sizeof (l_freeport) );
    }
	axt_cnt_inc(&cnt_fps_stnfd ); 
	axt_msg_message_ip(AXT_MSGC_FREEPRTNF, i_proto, i_nataddr, 0, 0,0,0,i_userport);
	
	return 0;
}

//===============================================

//---- user_limit managing  -- check - update 
static int axt_htb_check_user_limits(const u_int8_t i_proto, const uint32_t i_addr, uint8_t i_usgr) {
	int							l_is_found, ret;
    axt_htb_htuser_usr_p		l_user;
    struct hlist_head 			*l_head;
    uint32_t	 				l_hash;
	uint16_t					*l_ss_cnt_p, l_ss_cnt;
	int32_t						*l_ss_max_p, l_ss_max;
	uint64_t					l_pause;
	
    l_is_found	= 0;
	ret			= 1;
	l_ss_cnt 	= 0;
	l_ss_max	= 0;
	
    l_hash = axt_htb_hash_for_user(i_addr, i_usgr);
	
    rcu_read_lock_bh();
    l_head 		= &axt_ht_users[l_hash].user;
	hlist_for_each_entry_rcu(l_user, l_head, list_node) {
        if (READ_ONCE(l_user->idle) < 15 && l_user->addr == i_addr && l_user->usgr == i_usgr) {
            l_is_found = 1;
			break;
        }
    }
    rcu_read_unlock_bh();
	
    if (l_is_found == 1) {	
		l_pause = READ_ONCE(l_user->pause_to_jif64);
		if (l_pause !=0) {
			if (l_pause == ~0) ret=0;
			else if (l_pause > get_jiffies_64()) ret=0;
			else WRITE_ONCE(l_user->pause_to_jif64, 0); //pause period expired clear pause_to_jif64 to faster work 			
			if (ret==0) {
				//printk(KERN_NOTICE "xt_ANAT NOTICE: %pI4 blocked or paused.\n", &i_useraddr); 
				axt_msg_message_ipudt64(AXT_MSGC_USRBLOCKP, i_proto, i_addr, i_usgr, l_pause);
				axt_cnt_inc(&cnt_st_sessions_blocked);           
				return 0;
			}
		}
			
		l_ss_cnt_p		= (	( i_proto==IPPROTO_TCP)  ? &(l_user->tcp_count) : 
							((i_proto==IPPROTO_UDP)  ? &(l_user->udp_count) : 
							((i_proto==IPPROTO_ICMP) ? &(l_user->icmp_count) : &(l_user->other_count)) ) );
		l_ss_cnt=axt_wat_get16(l_ss_cnt_p);	
		
		l_ss_max_p	= (	( i_proto==IPPROTO_TCP)  ? &axt_ucfg.max[i_usgr].c_tcp : 
						((i_proto==IPPROTO_UDP)  ? &axt_ucfg.max[i_usgr].c_udp :
						((i_proto==IPPROTO_ICMP) ? &axt_ucfg.max[i_usgr].c_icm : &axt_ucfg.max[i_usgr].c_oth) ) );
		l_ss_max = axt_aprm_getN32(l_ss_max_p); 
		
		if (l_ss_max < 0) {
			l_ss_max_p = (	( i_proto==IPPROTO_TCP)  ? &axt_aprm_htb_usr_maxss_tcp : 
							((i_proto==IPPROTO_UDP)  ? &axt_aprm_htb_usr_maxss_udp :
							((i_proto==IPPROTO_ICMP) ? &axt_aprm_htb_usr_maxss_icm : &axt_aprm_htb_usr_maxss_oth) ) );
			l_ss_max = axt_aprm_getN32(l_ss_max_p); 
		}
		
        if (l_ss_cnt < l_ss_max) {
            ret=1;
        } else {
			if ( (axt_cfg_u_m_ison(1, i_usgr) != 0) ) {
				//printk(KERN_NOTICE "xt_ANAT NOTICE: %pI4 proto: %d exceed max allowed sessions.\n", &i_useraddr,  i_proto); 
				axt_msg_message_ipudt64(AXT_MSGC_USRLIMERR, i_proto, i_addr, i_usgr, l_ss_cnt);
			}
			axt_cnt_inc(&cnt_usr_exlimit);           
			ret=0;
        }
    }
    return ret;
}

static void axt_htb_update_user_limits(const u_int8_t i_proto, const uint32_t i_addr, uint8_t i_usgr, const int16_t i_operation) {
 	int 						l_is_found;
	axt_htb_htuser_usr_p 		l_user;
    struct hlist_head 			*l_head;
    size_t 						l_sz;
    uint32_t 					l_hash;
	uint16_t					*l_ss_cnt_p, l_ss_cnt, l_cnt;
	int32_t						*l_ss_max_p, l_ss_max;	

    l_is_found 	= 0;
	l_cnt 		= 0;
    l_hash = axt_htb_hash_for_user(i_addr, i_usgr);
	
    spin_lock_bh(&axt_ht_users[l_hash].lock);
    l_head = &axt_ht_users[l_hash].user;
    hlist_for_each_entry(l_user, l_head, list_node) {
        if (READ_ONCE(l_user->idle) < 15 && l_user->addr == i_addr && l_user->usgr == i_usgr) {
            l_is_found = 1;
            break;
        }
    }
	
    if ( likely(l_is_found == 1) ) {
        WRITE_ONCE(l_user->idle,0);
    } else {
        l_sz = sizeof(axt_htb_htuser_usr_t);
        l_user = kzalloc(l_sz, GFP_ATOMIC);

        if (l_user == NULL) {
            printk(KERN_WARNING "xt_ANAT ERROR: FAULT axt_htb_update_user_limits - Cannot allocate memory for new user session axt_htb_htuser_usr_s.\n");
            spin_unlock_bh(&axt_ht_users[l_hash].lock);
			axt_cnt_inc(&cnt_mem_enomempk);
          return;
        }

        l_user->addr 	= i_addr;
 		l_user->idle 	= 0;
		l_user->usgr	= i_usgr;

		l_user->tcp_count 	= 0;
        l_user->udp_count 	= 0;
        l_user->other_count = 0;
        l_user->icmp_count 	= 0;

		
        hlist_add_head_rcu(&l_user->list_node, &axt_ht_users[l_hash].user);
        l_cnt = axt_wat_inc16_return(&(axt_ht_users[l_hash].use));
		
		axt_cnt_setmax(&cnt_ht_husersm, l_cnt);
        axt_cnt_inc(&cnt_st_users_active);
    }
	
	l_ss_cnt_p	= (	 (i_proto==IPPROTO_TCP) ? &(l_user->tcp_count) : 
					((i_proto==IPPROTO_UDP) ? &(l_user->udp_count) : 
					((i_proto==IPPROTO_ICMP) ? &(l_user->icmp_count) : &(l_user->other_count)) ) );
	
	l_ss_cnt 	= (i_operation == -1 ? axt_wat_dec16_return(l_ss_cnt_p) : axt_wat_inc16_return(l_ss_cnt_p));			
    spin_unlock_bh(&axt_ht_users[l_hash].lock);

	l_ss_max_p	= (	( i_proto==IPPROTO_TCP)  ? &axt_ucfg.wrn[i_usgr].c_tcp : 
					((i_proto==IPPROTO_UDP)  ? &axt_ucfg.wrn[i_usgr].c_udp :
					((i_proto==IPPROTO_ICMP) ? &axt_ucfg.wrn[i_usgr].c_icm : &axt_ucfg.wrn[i_usgr].c_oth) ) );
	l_ss_max = axt_aprm_getN32(l_ss_max_p); 
		
	if (l_ss_max < 0) {
		l_ss_max_p = (	 (i_proto==IPPROTO_TCP) ? &axt_aprm_htb_usr_wrnss_tcp : 
						((i_proto==IPPROTO_UDP) ? &axt_aprm_htb_usr_wrnss_udp : 
						((i_proto==IPPROTO_ICMP) ? &axt_aprm_htb_usr_wrnss_icm : &axt_aprm_htb_usr_wrnss_oth) ) );
		l_ss_max = axt_aprm_getN32(l_ss_max_p); 
	}

	if ( unlikely(l_ss_cnt > l_ss_max) ) {
		if ( axt_cfg_u_m_ison(0,i_usgr) ) {
			//printk(KERN_NOTICE "xt_ANAT WARNING: %pI4 i_proto: %d too mach sessions (>1k) per 1 i_proto per 1 l_user %d\n", &i_addr,  i_proto, l_ss_cnt); 
			axt_msg_message_ipudt64(AXT_MSGC_USRLIMWRN, i_proto, i_addr, i_usgr,  l_ss_cnt);
		}
		axt_cnt_inc(&cnt_usr_mslimit);
	}

	if (l_cnt > axt_aprm_getN32(&axt_aprm_htb_htb_wrn_rnm)) {
		//printk(KERN_WARNING "xt_ANAT WARNING: axt_htb_update_user_limits - Attantion axt_ht_users[l_hash].use > 1000 \n");
		axt_msg_message_ipudt64(AXT_MSGC_HTBUSRWRN, i_proto, l_hash, i_usgr,  i_addr);
		axt_cnt_inc(&cnt_ht_mhusers);
	}	
    return;
}

//===============================================
//---- axt_ht_natipspl managing  -- create - remove 

static inline int  axt_htb_natip_spl_htb_create(void) {
    size_t		 	l_sz; /* (bytes) */
	int32_t 		l_pool_size;
    int 			i;

    l_pool_size = axt_iprm_htb_NATIPSPL_HTSZ;
    l_sz = sizeof(spinlock_t) * l_pool_size;
    axt_ht_natipspl = kzalloc(l_sz, GFP_KERNEL);
    if (axt_ht_natipspl == NULL)
        return -ENOMEM;
    for (i = 0; i < l_pool_size; i++) {
        spin_lock_init(&axt_ht_natipspl[i]);
    }
    printk(KERN_INFO "xt_ANAT INFO: Nat ip search port lock htable mem used: %ld.\n", l_sz);
    return 0;
}

static void  axt_htb_natip_spl_htb_remove(void) {
    if (axt_ht_natipspl) kfree(axt_ht_natipspl);
    printk(KERN_INFO "xt_ANAT INFO: Nat ip search port lock htable removed.\n");
}

//====================================
//---- axt_ht_users managing  -- create - remove 

static int  axt_htb_htb_htuser_create(void) {
    size_t			l_sz; /* (bytes) */
    int 			i;

    l_sz = sizeof(axt_htb_htuser_t) * axt_iprm_htb_USER_HTSZ;
    axt_ht_users = kzalloc(l_sz, GFP_KERNEL);
    if (axt_ht_users == NULL)
        return -ENOMEM;
    for (i = 0; i < axt_iprm_htb_USER_HTSZ; i++) {
        spin_lock_init(&axt_ht_users[i].lock);
        INIT_HLIST_HEAD(&axt_ht_users[i].user);
        axt_ht_users[i].use = 0;
    }
    printk(KERN_INFO "xt_ANAT INFO: Users htable mem used: %ld.\n", l_sz);
    return 0;
}

static void   axt_htb_htb_htuser_remove(void) {
    axt_htb_htuser_usr_p 			l_user;
    struct hlist_head 				*l_head;
    struct hlist_node 				*l_next;
    int 							i;
	
	if (axt_ht_users) {
		for (i = 0; i < axt_iprm_htb_USER_HTSZ; i++) {
			spin_lock_bh(&axt_ht_users[i].lock);
			l_head = &axt_ht_users[i].user;
			hlist_for_each_entry_safe(l_user, l_next, l_head, list_node) {
				hlist_del_rcu(&l_user->list_node);
				axt_ht_users[i].use--;
				kfree_rcu(l_user, rcu);
			}
			if (axt_ht_users[i].use != 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: FAULT users_htable_remove - bad 'use' value: %d in element %d.\n", axt_ht_users[i].use, i);
			}
			spin_unlock_bh(&axt_ht_users[i].lock);
		}
		kfree(axt_ht_users);
	}
    printk(KERN_INFO "xt_ANAT INFO: Users htable removed.\n");
    return;
}

//==============================================
//---- axt_ht_inner, axt_ht_outer -- create - remove 

static void    axt_htb_inout_htbs_remove(void) {
    axt_htb_ssi_p 				l_ses;
    axt_htl_node_p 				l_head, l_next;
    int32_t 					j, k, l_i;
		
	if (axt_ht_inner) {
/*		// it is not needed to do axt_ht_inner clean here! we will clean in axt_ht_outer becouse timer can already delete ssi from inner chain!		
		axt_htb_inout_for_each_from_to(j, k, l_i, 0, axt_iprm_htb_INOUT_HTSZ) {
			//spin_lock_bh(&axt_ht_inner[j].lock);
			l_head = &(axt_ht_inner[j].ss[k].hd);
			axt_hla_for_each_entry_safe_rcu(l_ses, l_next, l_head, inn_htln) {			
				//axt_ht_inner[j].use[k]--;
				//axt_hta_list_del_rcu(&l_ses->in_list_node,l_prev);
				//kfree_rcu(l_ses, rcu);
			}
			if (axt_ht_inner[j].use[k] != 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: FAULT nat_htable_remove inner - bad 'use' value: %d in element %d.\n", axt_ht_inner[j].use[k], l_i);
			}
			//spin_unlock_bh(&axt_ht_inner[j].lock);
		}
*/
		kfree(axt_ht_inner);
	}

 	if (axt_ht_outer) {
 		axt_htb_inout_for_each_from_to(j, k, l_i, 0, axt_iprm_htb_INOUT_HTSZ) {
			//spin_lock_bh(&axt_ht_outer[j].lock);
			l_head = &(axt_ht_outer[j].ss[k].hd);
			axt_hla_for_each_entry_safe_rcu(l_ses, l_next, l_head, out_htln) {			
				//we do clear always in single thread mode, so htlist_del_rcu not needed to do, we simple clear all memory entarence
				// zero rcu not need - zero by init 
				//l_ses->h.rc.rcu = {0};  
				l_ses->h.su.usr = 0;    
				l_ses->h.su.utcms = 0; 
				kfree_rcu(l_ses, h.rc.rcu);
				axt_ht_outer[j].use[k]--;
			}
			if (axt_ht_outer[j].use[k] != 0) {
				printk(KERN_WARNING "xt_ANAT ERROR: FAULT nat_htable_remove outer - bad 'use' value: %d in element %d.\n", axt_ht_outer[j].use[k], l_i);
			}
			//spin_unlock_bh(&axt_ht_outer[j].lock);
		}
 		kfree(axt_ht_outer);
	}
	printk(KERN_INFO "xt_ANAT INFO: Sessions inner | outer htable removed.\n");
    return;
}


static int  axt_htb_inout_htbs_create(void) {
    size_t 				l_sz; 
    uint32_t 			j, k, l_i;

 	axt_htb_inout_getjk( j, k, axt_iprm_htb_INOUT_HTSZ);

	l_sz = sizeof(axt_htb_inout_t) * (j+( k >0 ? 1 : 0));
    axt_ht_inner = kzalloc(l_sz, GFP_KERNEL);
    if (axt_ht_inner == NULL) return -ENOMEM;
    printk(KERN_INFO "xt_ANAT INFO: Sessions htable inner mem used: %ld.\n", l_sz);
	
	axt_ht_outer = kzalloc(l_sz, GFP_KERNEL);
    if (axt_ht_outer == NULL) {
		kfree(axt_ht_inner);
		return -ENOMEM;
	}
    printk(KERN_INFO "xt_ANAT INFO: Sessions htable outer mem used: %ld.\n", l_sz);
  
  	axt_htb_inout_for_each_from_to(j, k, l_i, 0, axt_iprm_htb_INOUT_HTSZ) {
        if (k==0) { 
			spin_lock_init(&axt_ht_inner[j].lock);
			spin_lock_init(&axt_ht_outer[j].lock);
		}
		// realy not need!! NULL and 0 already after kzallloc ? TODO ? comment
		axt_hla_init_rcu(&axt_ht_inner[j].ss[k].hd);  
		axt_hla_init_rcu(&axt_ht_outer[j].ss[k].hd);
        axt_ht_inner[j].use[k] = 0;
	    axt_ht_outer[j].use[k] = 0;
    }
    return 0;
}

//==============================================
//---- init  
static int axt_htb_init(void) {	
    printk(KERN_INFO "xt_ANAT INFO: Inout hash table size: %d.\n", axt_iprm_htb_INOUT_HTSZ);
    printk(KERN_INFO "xt_ANAT INFO: Users hash table size: %d.\n", axt_iprm_htb_USER_HTSZ);
    printk(KERN_INFO "xt_ANAT INFO: Nat ip serach port lock hash table size: %d.\n", axt_iprm_htb_NATIPSPL_HTSZ);
	//SDY  debug output 
	printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(axt_htb_ssi_t)        = %ld\n", sizeof(axt_htb_ssi_t));
	printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(axt_htb_inout_t)      = %ld\n", sizeof(axt_htb_inout_t));
	printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(axt_htb_htuser_t)     = %ld\n", sizeof(axt_htb_htuser_t));
	printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(axt_htb_htuser_usr_t) = %ld\n", sizeof(axt_htb_htuser_usr_t));
    printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(struct rcu_head)      = %ld\n", sizeof(struct rcu_head));
    printk(KERN_INFO "xt_ANAT DEBUG:  sizeof(spinlock_t)           = %ld\n", sizeof(spinlock_t));

	if (axt_htb_natip_spl_htb_create() < 0) {
		printk(KERN_INFO "xt_ANAT ERROR: NO MEMORY on pool_table_create().\n");
		return -1;
	}
    if (axt_htb_inout_htbs_create() < 0) {
		printk(KERN_INFO "xt_ANAT ERROR: NO MEMORY on nat_htable_create().\n");
		axt_htb_natip_spl_htb_remove();
		return -1;
	}
    if (axt_htb_htb_htuser_create() < 0) {
		printk(KERN_INFO "xt_ANAT ERROR: NO MEMORY on users_htable_create().\n");
		axt_htb_inout_htbs_remove();
		axt_htb_natip_spl_htb_remove();
		return -1;
	}	
    printk(KERN_INFO "xt_ANAT DEBUG:  &(*axt_ht_innssi)    = %pK\n", &(*axt_ht_inner));
    printk(KERN_INFO "xt_ANAT DEBUG:  &(*axt_ht_outssi)    = %pK\n", &(*axt_ht_outer));
    printk(KERN_INFO "xt_ANAT DEBUG:  &(*axt_ht_users)    = %pK\n", &(*axt_ht_users));
    printk(KERN_INFO "xt_ANAT DEBUG:  &(*axt_ht_natipspl) = %pK\n", &(*axt_ht_natipspl));
	return 0;
}
//---- done
static void axt_htb_done(void) {
    axt_htb_natip_spl_htb_remove();
    axt_htb_htb_htuser_remove();
    axt_htb_inout_htbs_remove();
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */