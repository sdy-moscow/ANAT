/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* axt_NAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
   
https://elixir.bootlin.com/linux/v4.15/source/net/socket.c   


      План работ:
   - 1. циклический буфер - пакетный? счетчики, поле флаг занятости -как парарллельный рост???
		- флаг =0 после отправки
		- новая запись - p=head++ p->data = ... w_barier() p->fplag=1
		- при отправке last to send = if end.flag =1 (last = end; end++}
   - 2. конфиг - адреса отправки в виде чар[]
   - 3. отправлять а) по таймеру с сокращением/ увеличением 50% заполнения, 75% - ускорение, (? параллельный вызов), 90% - экспресс вызов сенд. 
   - 4. флаг авариного вызова процедуры отправки (блокировка повторного вызова)

https://www.programmersought.com/article/2995560244/
This time we showed the socket send buffer with a dashed box because it doesn't exist.The UDP socket has a send buffer size (we can modify it with the
SO_SNDBUF socket option).However, it is only the upper limit of the size of the UDP datagram written to the socket.If the application process writes 
a packet larger than the socket send buffer size, the kernel will return an EMSGSIZE error. Since UDP is unreliable, it does not have to save a copy 
of the application's data, so there is no need for a real send buffer.(The data of the application process is copied to the kernel's buffer in some 
form when it is passed down the protocol. However, the data link layer will discard the copy after sending the data.)
....
A write call from the write UDP socket successfully returns an output queue indicating that the user wrote the datagram or all of its fragments have 
been added to the data link layer. If the queue does not have enough space to hold the datagram or a fragment of it, the kernel will typically return 
an ENOBUFS error to the application.

IP_MTU_DISCOVER  option  - we do not need MTU dicover
*/ 
// https://www.kernel.org/doc/html/latest/networking/kapi.html
// SO_REUSEPORT https://ru.manpages.org/socket/7
// https://docs.huihoo.com/doxygen/linux/kernel/3.7/net_2sock_8h.html
// https://programmerall.com/article/98332055286/
/* threads
 https://russianblogs.com/article/33371579833/
 https://russianblogs.com/article/75001505187/
*/ 

/*SDY DOCS
set_current_state()
Make the current task sleep until timeout jiffies have elapsed. The function behavior depends on the current task state (see also set_current_state() description):
TASK_RUNNING - the scheduler is called, but the task does not sleep at all. That happens because sched_submit_work() does nothing for tasks in TASK_RUNNING state.
TASK_UNINTERRUPTIBLE - at least timeout jiffies are guaranteed to pass before the routine returns unless the current task is explicitly woken up, (e.g. by wake_up_process()).
TASK_INTERRUPTIBLE - the routine may return early if a signal is delivered to the current task or the current task is explicitly woken up.

 https://blablacode.ru/yadro-linux/544
 https://www.linux.org.ru/forum/development/5471746
 https://www.linuxjournal.com/article/8144

we use many sendto() in udp one socket by addr ==  msg.msg_name, his size == msg.msg_namelen. 
 https://ru.manpages.org/sendmsg/2
 https://www.programmersought.com/article/89036503983/ 
 https://www.kernel.org/doc/html/latest/networking/kapi.html?highlight=kernel_sendmsg


*/

//u64 get_jiffies_64(void)
// https://www.kernel.org/doc/html/latest/core-api/timekeeping.html
//u6464 jiffies_64_to_clock_t(u64 x)   Convert jiffies_64 value converted to 64-bit "clock_t" (CLOCKS_PER_SEC)
//time64_t mktime64(const unsigned int year0, const unsigned int mon0, const unsigned int day, const unsigned int hour, 
//		const unsigned int min, const unsigned int sec);

#ifndef SDY_PKC_F_T_xt_ANAT_pc_nf9
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_nf9 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

#define AXT_NF9_THR_SLEEP_MIN_JF			15			// minimal time for shedule send thread sleep
#define AXT_NF9_THR_SLEEP_MAX_JF			3*HZ		// maximal time for shedule send thread sleep

#define AXT_NF9_PDU_LOADSZ_MAX	  			8000   		// max size of UDP load (pk size exclude ip & udp headers) use MTU & speedup

// pdu pk not standart fields id
#define AXT_NF9_PK_ID_EVENT					230			//event: 0-depricated (internal use); 1-new ses create; 2-ses stoped; 3-ses keepalive
#define AXT_NF9_PK_ID_SSTART				231

// pdu pk parts size
#define AXT_NF9_PK_HDR_SIZE 		(sizeof(struct axt_nf9_pk_hdr_s))
#define AXT_NF9_PK_TMPL_SIZE  		(sizeof(struct axt_nf9_pk_tmpl_s))
#define AXT_NF9_PK_DHDR_SIZE 		(sizeof(struct axt_nf9_pk_dhdr_s))
#define AXT_NF9_PK_REC_SIZE    		(sizeof(struct axt_nf9_pk_rec_s))

#define AXT_NF9_PK_RECNUM_MAX	  	((int) ((AXT_NF9_PDU_LOADSZ_MAX-(AXT_NF9_PK_HDR_SIZE+AXT_NF9_PK_TMPL_SIZE+AXT_NF9_PK_DHDR_SIZE))/AXT_NF9_PK_REC_SIZE))

#define AXT_NF9_PK_RBUF_S_SIZE  	(sizeof(struct axt_nf9_rbuf_s))


// One TIC interval and saddr mask for NF9 keepalive event. Using for assinchron sending keepalive message 
#define NF9_SSINT_TIC_ADRMASK		31						// 0x1F = 320sec (< 6 minutes) to send keepalive for all sessions
#define NF9_KEEPALIVE_TIC_MS		10*MSEC_PER_SEC 		// = 10 sec (it is full cicle for htb session timer

//send tread
//============== nf9 packet data structures define
  
//nf9 data record
struct axt_nf9_pk_rec_s {
	__u8		event;				//event: 0-depricated (internal use); 1-new ses create; 2-ses stoped; 3-ses keepalive
    __u8		protocol;
	__be16		s_port;
	__be16		n_port;
 	__be16		d_port;
    __be32		s_addr;
    __be32		n_addr;
    __be32		d_addr;
	__be64		sstart_gms;   		// msec from 0000 UTC 1970 
} __attribute__ ((packed)); 		// this order is for better data read|write allign

typedef struct axt_nf9_pk_rec_s* 	axt_nf9_pk_rec_p;

//nf9 template
struct axt_nf9_pk_tmpl_s {
    __be16		FlowSetId;  		//always = 0 for main template
    __be16		FlowTmplSz;
    __be16		TemplateId;
    __be16		FieldsCount;
    __be16		s_type_id;
    __be16		s_type_len;
    __be16		proto_id;
    __be16		proto_len;
    __be16		s_port_id;
    __be16		s_port_len;
    __be16		n_port_id;
    __be16		n_port_len;
    __be16		d_port_id;
    __be16		d_port_len;	
    __be16		s_addr_id;
    __be16		s_addr_len;
    __be16		n_addr_id;
    __be16		n_addr_len;
    __be16		d_addr_id;
    __be16		d_addr_len;
	__be16		sstart_gms_id;
    __be16		sstart_gms_len;
} __attribute__ ((packed));  		//  order must be equal axt_nf9_pk_rec_s

typedef struct  axt_nf9_pk_tmpl_s* 	axt_nf9_pk_tmpl_p;

//nf9 packet header
struct axt_nf9_pk_hdr_s {
    __be16		version;
    __be16		nr_records;
    __be32		ts_uptime; 			// ms 
    __be32		ts_usecs;  			// s 
    __be32		seq;
    __be32		srcID;
} __attribute__ ((packed));

typedef struct  axt_nf9_pk_hdr_s* 	axt_nf9_pk_hdr_p;

//nf9 packet data header
struct axt_nf9_pk_dhdr_s {	
    __be16		FlowSetId; 			// = TemplateId for records set
    __be16		FlowDataSz;
    
} __attribute__ ((packed));

typedef struct  axt_nf9_pk_dhdr_s* 	axt_nf9_pk_dhdr_p;

//nf9 packet with template 
struct axt_nf9_pk_tpdu_s {	
    struct	axt_nf9_pk_hdr_s  		hdr; 						// pdu header
    struct	axt_nf9_pk_tmpl_s  		tmpl; 						// template flow
    struct	axt_nf9_pk_dhdr_s  		dhdr; 						// data flow header
	struct	axt_nf9_pk_rec_s		drec[AXT_NF9_PK_RECNUM_MAX]; 	// data flow records
// __be32							padding;  					// =0  - not needed we have only one data set and it is last in packet
} __attribute__ ((packed));

//nf9 packet with out template 
struct axt_nf9_pk_dbuf_s {	
    struct	axt_nf9_pk_hdr_s  		hdr; 						// pdu header
    struct	axt_nf9_pk_dhdr_s  		dhdr; 						// data flow header
	struct	axt_nf9_pk_rec_s		drec[AXT_NF9_PK_RECNUM_MAX];  	// data flow records
// __be32							padding;  					// =0  - not needed we have only one data set and it is last in packet
} __attribute__ ((packed));

//rbuf struc for working
struct axt_nf9_rbuf_s {
	//round buffer
	atomic64_t  			ihead;
	atomic64_t  			itail;
	int64_t     			isize;  			//rb_data array size - must be^2
	uint64_t    			imask;  			//rb_data mask for ihead и rb_iend to find pos in rb_data
    axt_nf9_pk_rec_p		rb_data;   			//ptr to array of axt_nf9_pk_rec_s's	
	// udp  work
	struct socket*			udp_sock;			//udp_socket
	// nf9 sequence manage
	uint32_t 				pdu_seq;			//next seq at pkt header
	int64_t					seq_reset_req_jf;	// last done seq reset at axt_aprm_tseq_reset_req_jf
	// pdu settings 
	int64_t					vprm_version;
	__be32					nf9_srcID;			//current nf9 source ID
    __be16					nf9_templateID;		//current nf9 template ID
	uint32_t				tpdu_recmax;		//current max data record in templated packet
	uint32_t				dpdu_recmax;		//current max data record in only data packet
	uint32_t  				tmpl_squant;		//0 - do not send template //1 - repeateevery packet //>1 (n) repeat every (n) packet	
	uint32_t  	 			tmpl_sempty;		//1 - send template NF9_THR_SEND_INTERVAL_MAX_JF if no data
	// pdu data buffers 
	struct axt_nf9_pk_tpdu_s		tpdu; 		// pdu template + data flow pk load buffer 
	struct axt_nf9_pk_dbuf_s		dpdu; 		// pdu only data flow pk load buffer 
};

typedef struct axt_nf9_rbuf_s* 			axt_nf9_rbuf_p;


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_nf9
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_nf9 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

static struct task_struct 		*axt_nf9_send_thread		= NULL;					// send thread task pointer
// rbuf
static axt_nf9_rbuf_p  			axt_nf9_rbuf				= NULL;					// data for axt_nf9_send_thread
// send_thread vars
static atomic_t     			axt_nf9_speedup_flag    	= ATOMIC_INIT(0);		// speedup nf9 send flag
static atomic64_t   			axt_nf9_speedup_jiff64  	= ATOMIC_INIT(0);		// last jiffies64 when first axt_nf9_speedup_flag=2 set
// nf9 seq reset 
static atomic64_t  				axt_nf9_seq_reset_req_jf	= ATOMIC_INIT(0);		// last jiffies64 when seq reset command [CMD_RESET_NF9_SEQ] called 

//forward declaration	
static inline   axt_nf9_rbuf_p axt_nf9_rb_get_actRb(void);

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_nf9
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_nf9 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */

//=========================  Nf9 keep alive workingkeep alive working
// keep alive working for axt_htm_sessions_cleanup_timer_callback() work



static inline uint32_t   axt_nf9_ssk_get_intrv(const uint64_t i_gms) {
	//get inerval for send
	return (i_gms / axt_aprm_getN32(&axt_aprm_nf9_ssk_intrv_ms)) & AXT_TMT_SSINT_MSF; 
}  

static inline uint32_t   axt_nf9_ssk_get_stic(const uint64_t i_gms) {
	//send tics is seconds number from keepalive interval start
	return ((i_gms % axt_aprm_getN32(&axt_aprm_nf9_ssk_intrv_ms)) / NF9_KEEPALIVE_TIC_MS) & NF9_SSINT_TIC_ADRMASK; 
} 

static inline uint32_t	axt_nf9_ssk_addr_hash(uint32_t i_addr) {
	return (i_addr^(i_addr>>5)^(i_addr>>17));
}

static inline int  axt_nf9_ssk_chk_stic(uint32_t i_addr_ton, const uint64_t i_cur_tic) {
	//check address in current tics is seconds number from keepalive interval start
	return ( (axt_nf9_ssk_addr_hash(i_addr_ton) & NF9_SSINT_TIC_ADRMASK) <= i_cur_tic ); 
} 



//=========================  ring buffer work helpers
//get actual rbuf ptr
static inline   axt_nf9_rbuf_p axt_nf9_rb_get_actRb(void) {
	// can return NULL if buffer is not active!
	return axt_nf9_rbuf; 
}

//get index in data array from int64_t pos count
static inline int64_t   axt_nf9_rb_di_from_i( axt_nf9_rbuf_p  i_rbuf, const int64_t  i_indx ) {
	return i_indx & i_rbuf->imask;
}

//get ihead from rbuf
static inline int64_t   axt_nf9_rb_get_ihead(axt_nf9_rbuf_p  i_rbuf) {
	 return atomic64_read(&(i_rbuf->ihead));
}

//get itail from rbuf
static inline int64_t   axt_nf9_rb_get_itail(axt_nf9_rbuf_p  i_rbuf) {
	 return atomic64_read(&(i_rbuf->itail));
}


//=========================  Nf9 add event to send
// speed up send if buffer is filling qick
static void   axt_nf9_speedup_send(axt_nf9_rbuf_p i_rbuf, const int64_t i_isize, const int64_t i_ihead, const int64_t i_itail) {
	int l_oldflag;
	if (likely ( (i_ihead - i_itail) < (i_rbuf->isize >> 4) ) ) return; 		// less then 1/16 used - nothing to do
	// more then 1/16 used
	axt_cnt_inc(&cnt_nf9_speedup);
	l_oldflag = 0;
	if (unlikely (atomic_try_cmpxchg(&axt_nf9_speedup_flag, &l_oldflag, 1))) { 	//else somebody do it before us!
		axt_cnt_inc(&cnt_nf9_speedup_act);
		atomic64_set(&axt_nf9_speedup_jiff64, (int64_t) get_jiffies_64()); 		//remember time it happened
		wmb();
		atomic_set(&axt_nf9_speedup_flag,2);		 							//= 2 - mean axt_nf9_speedup_jiff64 is correct 
		if (!IS_ERR(axt_nf9_send_thread)) wake_up_process(axt_nf9_send_thread);
		//printk(KERN_INFO "xt_ANAT DEBUG: Nf9 ring buffer 1/16 wake_up send thread happened.\n");
	}
	return;
}

//get last ihead in rbuf with overload check and inc
static inline int64_t   axt_nf9_rb_ihead_donext(axt_nf9_rbuf_p i_rbuf, int64_t *v_tail ) { //return -1 if buf is full
	int64_t l_wihead = atomic64_inc_return(&i_rbuf->ihead) - 1;
	if (likely ((l_wihead - (*v_tail = axt_nf9_rb_get_itail(i_rbuf)) ) <  i_rbuf->isize) ) {
		return (l_wihead);
	} 
	// buffer overload! backup ihead by dec and return -1
	atomic64_dec(&i_rbuf->ihead);
	return -1;
}		

//add event in ring buffer
static void   axt_nf9_new_event_tosend(const uint8_t proto, const uint32_t srcaddr, const uint16_t srcport, const uint32_t dstaddr, 
					const uint16_t dstport, const uint32_t nataddr, const uint16_t natport, const int nat_event, const uint64_t natsstart_gms) {
    axt_nf9_rbuf_p		l_rbuf;
	axt_nf9_pk_rec_p  	l_rec;
	int64_t 		 	l_iwhead, l_iwtail, l_irec;
	
	if (unlikely ((l_rbuf = axt_nf9_rb_get_actRb()) == NULL) ) return; 	// buffer is not active!
	if (unlikely (!(axt_aprm_getN32(&axt_aprm_nf9_events_on))) ) return; 		// NF9_EVENTS_ON = 0 (all events is off)
	if (unlikely ((nat_event == 3) && (axt_aprm_getN32(&axt_aprm_nf9_ssk_intrv_ms ) >= 1000000)) )  return; // ssl off by set keepalive intrv >= 1m
	if (unlikely ((l_iwhead = axt_nf9_rb_ihead_donext(l_rbuf, &l_iwtail)) == -1) ) { //buffer overload

		axt_msg_message_ipudt64(AXT_MSGC_NF9BUFOVR, 0, 0, 0, axt_nf9_rb_get_ihead(l_rbuf));
		axt_cnt_inc(&cnt_nf9_rb_overload);
		//printk(KERN_WARNING "xt_ANAT ERROR: Nf9 ring buffer overload! At isize: %lld ihead: %lld itail: %lld\n",
		//			l_rbuf->isize, axt_nf9_rb_get_ihead(l_rbuf), l_iwtail);
		axt_nf9_speedup_send(l_rbuf, l_rbuf->isize, axt_nf9_rb_get_ihead(l_rbuf), l_iwtail);
		return;
	}
	l_irec = axt_nf9_rb_di_from_i(l_rbuf, l_iwhead); //get index in array from count
    l_rec = &(l_rbuf->rb_data[l_irec]);

	//printk(KERN_INFO "xt_ANAT DEBUG: l_rbuf  - isize: %lld imask: %lld &rb_data:%p rb_d size: %ld\n", l_rbuf->isize, l_rbuf->imask, &l_rbuf->rb_data, gbadtest_rbuf_d_sz);

    l_rec->protocol		= proto;
    l_rec->s_port		= srcport;
    l_rec->s_addr		= srcaddr;
    l_rec->d_port		= dstport;
    l_rec->d_addr		= dstaddr;
    l_rec->n_addr		= nataddr;
    l_rec->n_port		= natport;
	l_rec->sstart_gms	= cpu_to_be64(natsstart_gms);
	wmb();
    WRITE_ONCE(l_rec->event, nat_event); 	//set event !=0, mean we write all field and record is correct
	
	axt_nf9_speedup_send(l_rbuf, l_rbuf->isize, l_iwhead, l_iwtail );
}


//=============================  send events by UDP soccket work
//=========================  prepare UDP packet work

static void   	axt_nf9_reset_seq(void)  {
	atomic64_set(&axt_nf9_seq_reset_req_jf, (int64_t) get_jiffies_64());
}

// set config changeable vars
static void   axt_nf9_pdu_setvars(axt_nf9_rbuf_p i_rbuf) {
 	//renew vars if axt_prm_vprm_version changed
	if (i_rbuf->vprm_version != atomic64_read(&axt_prm_vprm_version)) {
		if (( axt_prm_vprm_lock_soft() )) {
			i_rbuf->tpdu_recmax 	= (axt_vprm_nf9_pdu_loadsz - (AXT_NF9_PK_HDR_SIZE+AXT_NF9_PK_TMPL_SIZE+AXT_NF9_PK_DHDR_SIZE)) / AXT_NF9_PK_REC_SIZE ;	
			i_rbuf->dpdu_recmax 	= (axt_vprm_nf9_pdu_loadsz - (AXT_NF9_PK_HDR_SIZE+AXT_NF9_PK_DHDR_SIZE)) / AXT_NF9_PK_REC_SIZE;

			i_rbuf->tmpl_squant 	= axt_vprm_nf9_tmpl_squant;	
			i_rbuf->tmpl_sempty 	= axt_vprm_nf9_tmpl_sempty;		

			i_rbuf->nf9_srcID		= htonl( axt_vprm_nf9_srcID );
			i_rbuf->nf9_templateID	= htons(( uint16_t) axt_vprm_nf9_templateID);	
			i_rbuf->vprm_version	=atomic64_read(&axt_prm_vprm_version);
			axt_prm_vprm_unlock_read();
		}
	}	
	//seq reset if needed
	if ( i_rbuf->seq_reset_req_jf < atomic64_read(&axt_nf9_seq_reset_req_jf) ) {
		i_rbuf->pdu_seq = 0;
		i_rbuf->seq_reset_req_jf = atomic64_read(&axt_nf9_seq_reset_req_jf);
	}
	//set fields in pk load by current var values
	i_rbuf->tpdu.hdr.srcID			= i_rbuf->nf9_srcID;
    i_rbuf->tpdu.tmpl.TemplateId	= i_rbuf->nf9_templateID;
	i_rbuf->tpdu.dhdr.FlowSetId		= i_rbuf->tpdu.tmpl.TemplateId;  			//must be equal TemplateId
	i_rbuf->dpdu.hdr.srcID			= i_rbuf->tpdu.hdr.srcID;  					//copy from tpdu
	i_rbuf->dpdu.dhdr.FlowSetId		= i_rbuf->tpdu.tmpl.TemplateId;  			//must be equal TemplateId
}

// pk data structurs init funcs
static void   axt_nf9_pdu_hdr_init(axt_nf9_pk_hdr_p i_pkd) {
    i_pkd->version		= htons(9);
    i_pkd->nr_records	= 0; 		//change on send 
    i_pkd->ts_uptime	= 0; 		//change on send (jf to msec)
    i_pkd->ts_usecs		= 0; 		//change on send (sec from 0000 UTC 1970)
    i_pkd->seq			= 0; 		//change on send, can be reset on start send
    //axt_nf9_pdubuf.srcID		= htonl(0); //set by axt_nf9_tmpltpdu_varsset() - can be change on start send
}

static void   axt_nf9_pdu_tmpl_init(axt_nf9_pk_tmpl_p i_pkd) {
	//!!! real field order look at axt_nf9_pk_tmpl_s definition
    i_pkd->FlowSetId			= 0; 			//always =0 for nf9 main template set 
    i_pkd->FlowTmplSz		= htons(AXT_NF9_PK_TMPL_SIZE);
    //i_pkd->TemplateId		= htons(0);     //set by axt_nf9_tmpltpdu_varsset() - can be change on start send
    i_pkd->FieldsCount		= htons(9);
    i_pkd->proto_id			= htons(4);
    i_pkd->proto_len		= htons(1);
    i_pkd->s_port_id		= htons(7);
    i_pkd->s_port_len		= htons(2);
    i_pkd->s_addr_id		= htons(8);
    i_pkd->s_addr_len		= htons(4);
    i_pkd->d_port_id		= htons(11);
    i_pkd->d_port_len		= htons(2);
    i_pkd->d_addr_id		= htons(12);
    i_pkd->d_addr_len		= htons(4);
    i_pkd->n_addr_id		= htons(225);
    i_pkd->n_addr_len		= htons(4);
    i_pkd->n_port_id		= htons(227);
    i_pkd->n_port_len		= htons(2);
    i_pkd->s_type_id		= htons(AXT_NF9_PK_ID_EVENT);
    i_pkd->s_type_len		= htons(1);
    i_pkd->sstart_gms_id	= htons(AXT_NF9_PK_ID_SSTART);
    i_pkd->sstart_gms_len	= htons(8);
}

static void   axt_nf9_pdu_dhdr_init(axt_nf9_pk_dhdr_p i_pkd) {
	i_pkd->FlowSetId		= 0; 		//set by axt_nf9_tmpltpdu_varsset() - can be change on start send
	i_pkd->FlowDataSz		= 0; 		//change on send 
}

static void   axt_nf9_pdu_init(axt_nf9_rbuf_p i_rbuf) {	
	// init buf for tempalted pdu
	axt_nf9_pdu_hdr_init(	&(i_rbuf->tpdu.hdr)); 
	axt_nf9_pdu_tmpl_init(	&(i_rbuf->tpdu.tmpl));
	axt_nf9_pdu_dhdr_init(	&(i_rbuf->tpdu.dhdr));
	// init buf for only data pdu
	axt_nf9_pdu_hdr_init(	&(i_rbuf->dpdu.hdr)); 
	axt_nf9_pdu_dhdr_init(	&(i_rbuf->dpdu.dhdr));
	// init eparam variables
	axt_nf9_pdu_setvars(i_rbuf);
}
	
//=========================  ring buffer init done
// create nf9 *rbuf 
static axt_nf9_rbuf_p   axt_nf9_rb_create(const int32_t i_szpow2) { 	
	size_t 					l_brnum, l_msz;
	axt_nf9_pk_rec_p 		l_rbuf_dt;
	axt_nf9_rbuf_p 			l_rbuf;

	l_brnum = 1 << i_szpow2;
	l_msz = AXT_NF9_PK_REC_SIZE * l_brnum;
	l_rbuf_dt = kzalloc(l_msz, GFP_KERNEL);
    if (l_rbuf_dt == NULL) {
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 ring buffer records table create error. Rec's: %ld. Mem need: %ld.\n", l_brnum,l_msz);
		return NULL;
	}
	printk(KERN_INFO "xt_ANAT INFO: Nf9 ring buffer records table created. Rec's: %ld. Mem used:%ld.\n", l_brnum, l_msz);

	l_msz = AXT_NF9_PK_RBUF_S_SIZE;
	l_rbuf = kzalloc(l_msz, GFP_KERNEL);
    if (l_rbuf == NULL) {
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 ring buffer create error. Mem need: %ld.\n", l_msz);
		kfree(l_rbuf_dt);
		return NULL;
	}
	printk(KERN_INFO "xt_ANAT INFO: Nf9 ring buffer created. Mem used:%ld.\n",l_msz);

	atomic64_set(&(l_rbuf->ihead), 0);
	atomic64_set(&(l_rbuf->itail), 0);
	l_rbuf->isize = l_brnum;
	l_rbuf->imask = 0xFFFFFFFFFFFFFFFF >> (64-i_szpow2);
    printk(KERN_INFO "xt_ANAT INFO: Nf9 prb_imask: %lld.\n", l_rbuf->imask);	
	//spin_lock_init(&(l_rbuf->udp_sock_lock)); 
    l_rbuf->rb_data 	= l_rbuf_dt;

	axt_nf9_pdu_init(l_rbuf);	
	return l_rbuf;
}

// done for *rbuf var
static void axt_nf9_rb_free(axt_nf9_rbuf_p *v_rbuf) {
	if (v_rbuf) {
		if ((*v_rbuf) == NULL) return;
		if ((*v_rbuf)->rb_data!= NULL) kfree((*v_rbuf)->rb_data);
		kfree(*v_rbuf);
		v_rbuf=NULL;
	}
    printk(KERN_INFO "xt_ANAT INFO: Nf9 ring buffer free.\n");	
}

//=========================  UDP socket work

// udp socket init
static int   axt_nf9_udpsock_init( axt_nf9_rbuf_p  i_rbuf) {
	struct socket		*l_sock;
    int 				l_error;

	if ((l_error = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &l_sock)) < 0) {
        printk(KERN_WARNING "xt_ANAT ERROR: Nf9 in axt_nf9_udpsock_init sock_create_kern(..) return Error : %d.\n", l_error);
		axt_cnt_inc(&cnt_nf9_sockerr);
        return l_error;
    }
	i_rbuf->udp_sock = l_sock;
	//dbg_printk(KERN_DEBUG "xt_ANAT DEBUG: Nf9 socket created: %pK  %pK udp_sock:\n", l_sock, i_rbuf->udp_sock);
    return 0;
}

// udp socket done
static void   axt_nf9_udpsock_done( axt_nf9_rbuf_p  i_rbuf) {
	if (i_rbuf) {
		if (i_rbuf->udp_sock) {
			sock_release(i_rbuf->udp_sock);
			printk(KERN_INFO "xt_ANAT DEBUG: Nf9 socket released. i_sock : %pK.\n", i_rbuf->udp_sock);
			i_rbuf->udp_sock = NULL;
		}
	}
}

// udp socket check & init if needed
static int   axt_nf9_check_and_init_sock( axt_nf9_rbuf_p  i_rbuf) {
    int			l_error = 0;
	int		 	l_len 	= sizeof (l_error);	
    int			l_retval = 0;
	
	if ((i_rbuf->udp_sock)) {
		l_retval = kernel_getsockopt(i_rbuf->udp_sock, SOL_SOCKET, SO_ERROR, (char*) &l_error, &l_len);
		if (l_retval != 0) { 	/* there was a problem getting the error code */
			printk(KERN_WARNING "xt_ANAT ERROR: Nf9 socket error getsockopt() return l_retval : %d.\n", l_retval);
			axt_cnt_inc(&cnt_nf9_sockerr);
			//we will reinit socket!
			axt_nf9_udpsock_done(i_rbuf);
		}
		if (l_error != 0) {
			printk(KERN_WARNING "xt_ANAT ERROR: Nf9 socket error getsockopt() return Error : %d.\n", l_error);
			axt_cnt_inc(&cnt_nf9_sockerr);
			//we will reinit socket!
			axt_nf9_udpsock_done(i_rbuf);
		}
	}
	//check sock open if not do it now
	if (!(i_rbuf->udp_sock)) {
		l_error = axt_nf9_udpsock_init(i_rbuf);
		if (l_error) {
			printk(KERN_WARNING "xt_ANAT ERROR: Nf9 socket init Error : %d.\n", l_error);
			return -1;
		}
	}
	return 0;
}

//=========================  send events to UDP socket from rbuf work

// nf9 prep udp packet to all listeners 
static axt_nf9_pk_hdr_p   axt_nf9_prep_udppkt(axt_nf9_rbuf_p i_rbuf,  const int64_t i_ifrom, const int64_t i_ito, const int i_pk_type, size_t *v_pktload_sz ) {
	// i_pk_type: 0-only data packet 1 - tmpl packet 
	// return ptr to buf begin (hdr), null if error, size of data to send frombuf returned in v_pktload_sz*
	axt_nf9_pk_hdr_p		l_hdr;   		//return it as result
	axt_nf9_pk_dhdr_p		l_dhdr;
	axt_nf9_pk_rec_p		l_drec;  		
	int 					l_maxrec, l_sendrec, l_idfrom, l_idto;
	struct timespec64 		l_timesec;
	size_t					l_cpsz1, l_cpsz2, l_fsz;
	
	//*tmpl not interest we do not change it in this function!
	if (i_pk_type) { //tmpl
		l_hdr		= &(i_rbuf->tpdu.hdr);
		l_dhdr		= &(i_rbuf->tpdu.dhdr); 
		l_drec		= &(i_rbuf->tpdu.drec[0]);
		l_maxrec	= i_rbuf->tpdu_recmax;
	} else { //only data
		l_hdr		= &(i_rbuf->dpdu.hdr);
		l_dhdr		= &(i_rbuf->dpdu.dhdr); 
		l_drec		= &(i_rbuf->dpdu.drec[0]);
		l_maxrec	= i_rbuf->dpdu_recmax;
	}
	l_sendrec = i_ito - i_ifrom;
	if (l_sendrec > l_maxrec) {
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 axt_nf9_prep_udppkt(..) algoritm error! l_sendrec > l_maxrec. Call s.d.y 1976!\n");
		*v_pktload_sz = 0;
		return NULL;
	}
	//fill every pk send chaned data in pkt
    l_hdr->nr_records	= htons(l_sendrec + (!(i_pk_type) ? 0 : 1)); 	//flow recs number include tmpl if given 
    l_hdr->ts_uptime	= htonl(jiffies_to_msecs(jiffies)); 		  	//jf to msec
    ktime_get_real_ts64(&l_timesec);
	l_hdr->ts_usecs		= htonl((uint32_t) axt_wtm_get_cur_s());						// sec from 0000 UTC 1970
    l_hdr->seq			= htonl(i_rbuf->pdu_seq);   					// nf9 packet seq
	
	l_fsz = (size_t) ( (int64_t) l_dhdr - (int64_t) l_hdr );    		// data size without data rec = dif between &
	if (l_sendrec > 0 ) {
		l_cpsz1 = AXT_NF9_PK_REC_SIZE*l_sendrec;
		l_fsz 	= l_fsz + l_cpsz1 + 4;
		l_dhdr->FlowDataSz	= htons(l_cpsz1 + 4); 						// data flow size with ID and length
		l_idfrom	= axt_nf9_rb_di_from_i(i_rbuf, i_ifrom);
		l_idto 		= axt_nf9_rb_di_from_i(i_rbuf, i_ito);
		l_cpsz1 	= l_sendrec * AXT_NF9_PK_REC_SIZE;
		if (l_idto < l_idfrom) { 					//  buf was gone over [isize]
			l_cpsz2 = l_idto * AXT_NF9_PK_REC_SIZE;
			l_cpsz1 = l_cpsz1 - l_cpsz2;
		} else {
			l_cpsz2 = 0;
		}		
		memcpy(&(l_drec[0]), &(i_rbuf->rb_data[l_idfrom]), l_cpsz1);
		if (l_cpsz2) memcpy(&(l_drec[l_sendrec-l_idto]), &(i_rbuf->rb_data[0]), l_cpsz2); 
	}
	*v_pktload_sz = l_fsz;
	return l_hdr;
}

// nf9 send udp packet to all listeners 
static int   axt_nf9_send_udppkt(axt_nf9_rbuf_p i_rbuf,  const int64_t i_ifrom, const int64_t i_ito, const int i_pk_type ) {
	axt_nf9_pk_hdr_p		l_hdr;
	size_t					l_sendsz;
	int						i, l_retinfo, l_cnt;
	struct msghdr			l_msghdr =	{}; 		// init 0
	struct kvec				l_kvec = {};			// init 0
	struct sockaddr_in		l_scaddr = {};  		// init 0
	axt_cfg_lconfig_t*		l_cfg;
	
	l_hdr = axt_nf9_prep_udppkt(i_rbuf, i_ifrom, i_ito, i_pk_type, &l_sendsz);
	if (!l_hdr) {
		axt_cnt_inc(&cnt_nf9_senderr);
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 Send error -  axt_nf9_prep_udppkt(..) error!\n");
		return -1;
	}
	if ( axt_nf9_check_and_init_sock(i_rbuf)) {
		axt_cnt_inc(&cnt_nf9_senderr);
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 Send error -  axt_nf9_check_and_init_sock(..) error!\n");
		return -1;
	}

	l_msghdr.msg_flags	= MSG_NOSIGNAL; //MSG_DONTWAIT|MSG_NOSIGNAL are we need in UDP in own thread?
    l_kvec.iov_base		= l_hdr; 
    l_kvec.iov_len 		= l_sendsz; 
	
	l_scaddr.sin_family = AF_INET;
	
	l_cfg = axt_cfg_get_actConfig();
	l_cnt = ( l_cfg ? l_cfg->nf9dest_cnt : 0); //if l_cfg null ret 0
	for (i=0; i < l_cnt; i++) {
		//setaddr in struc l_msghdr
		l_scaddr.sin_port		 = htons(l_cfg->nf9dest_arr[i].d_port);
		l_scaddr.sin_addr.s_addr = htonl(l_cfg->nf9dest_arr[i].d_ip);
		l_msghdr.msg_name    = &l_scaddr;    
		l_msghdr.msg_namelen = sizeof(l_scaddr);  
		//printk(KERN_INFO "xt_ANAT DEBUG: Nf9 axt_nf9_send_udppkt - i_rbuf->udp_sock: %pK.\n",i_rbuf->udp_sock);
         l_retinfo = kernel_sendmsg(i_rbuf->udp_sock, &l_msghdr, &l_kvec, 1, l_sendsz ); 
        if (l_retinfo == -EAGAIN) {
			axt_cnt_inc(&cnt_nf9_senderr);
			axt_cnt_inc(&cnt_nf9_sockerr);
			printk(KERN_WARNING "xt_ANAT ERROR: Nf9 Send error - kernel_sendmsg(..) return EAGAIN. May be it is needed to increase sndbuf!\n");
 			return -1;
        } else if (l_retinfo < 0) {
 			axt_cnt_inc(&cnt_nf9_senderr);
			axt_cnt_inc(&cnt_nf9_sockerr);
			printk(KERN_WARNING "xt_ANAT ERROR: Nf9 Send error - kernel_sendmsg(..) return Error: %d . Socket will be reset!\n", l_retinfo);
			axt_nf9_udpsock_done(i_rbuf);
			//closesock       }
 			return -1;
		}
	}
	return 0;	
}

//return itail (+1) ready to send (it will be next itail !
static int64_t   axt_nf9_rb_find_itail_tosend(axt_nf9_rbuf_p i_rbuf, const int64_t i_itail, const int64_t i_max_rec) {
	int64_t     l_maxitail, l_itail;
	l_itail = i_itail;
	l_maxitail = min(axt_nf9_rb_get_ihead(i_rbuf), i_itail+i_max_rec);
	while ( (l_itail<l_maxitail) ) {
		//check for record is already filled by axt_nf9_new_event_tosend (event != 0)
		if 	(!(READ_ONCE(i_rbuf->rb_data[axt_nf9_rb_di_from_i(i_rbuf, l_itail)].event))) break; 
		l_itail ++;
	}
	return l_itail;
}

static inline int   axt_nf9_send_get_next_pk_type(axt_nf9_rbuf_p i_rbuf) {
// return  0-only data packet 1 - tmpl packet 
	uint32_t l_squant = i_rbuf->tmpl_squant;
	if (likely(l_squant <= 1)) {
		return l_squant;
	}
	return (!(i_rbuf->pdu_seq  % l_squant));  //i_rbuf->pdu_seq mod l_squant == 0
}

static int   axt_nf9_send_thr_run(void *v_data) {
        //инициализация переменных
	uint64_t    l_sleep_at_jf, l_sleep_jf, l_lastsend_jf, l_now_jf, l_delay;
	int64_t     l_ihead, l_itail, l_rsendnum, l_next_itail, l_rec_in_pk;
	int 		l_pk_type;
	axt_nf9_rbuf_p  l_rbuf;
	
	l_lastsend_jf 	= get_jiffies_64();
	l_sleep_jf    	= AXT_NF9_THR_SLEEP_MAX_JF;
	while(1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if(kthread_should_stop()) break;
		l_sleep_at_jf = get_jiffies_64();
		atomic_set_release(&axt_nf9_speedup_flag,0); // speedup flag reset
		//goto sleep
		schedule_timeout(l_sleep_jf);
		//wakeed up and do work!
		if (unlikely ((l_rbuf = axt_nf9_rb_get_actRb()) == NULL)) { // buffer is not active!
			l_sleep_jf = AXT_NF9_THR_SLEEP_MAX_JF;
		} else { 
			// count packets to send
			l_ihead = axt_nf9_rb_get_ihead(l_rbuf);
			l_itail = axt_nf9_rb_get_itail(l_rbuf);
			l_rsendnum = l_ihead - l_itail;
			// correct l_sleep_jf
			if (atomic_read(&axt_nf9_speedup_flag)==2) {
				//wake_up on 1/16 space used!!! set less peiod l_sleep_jf for sleep! 
				l_sleep_jf = min(l_sleep_jf >> 2, atomic64_read(&axt_nf9_speedup_jiff64)-l_sleep_at_jf);
			} else if ( l_rsendnum < (l_rbuf->isize >> 6) ) {
				//if rbuf filled less 1/64 (>>6) we can increase l_sleep_jf 
				l_sleep_jf += 10; 
			}
			//check l_sleep_jf bounds
			l_sleep_jf = max( min( l_sleep_jf, (uint64_t) AXT_NF9_THR_SLEEP_MAX_JF) , (uint64_t) AXT_NF9_THR_SLEEP_MIN_JF );
			
			axt_nf9_pdu_setvars(l_rbuf);
			//send rbuf
			set_current_state(TASK_INTERRUPTIBLE);
			l_delay = axt_aprm_getN64(&axt_aprm_nf9_max_delay_sec)*HZ;
			while (1) { 
				l_now_jf  = get_jiffies_64();
				l_pk_type = axt_nf9_send_get_next_pk_type(l_rbuf );
				l_rec_in_pk  = ( l_pk_type ? l_rbuf->tpdu_recmax : l_rbuf->dpdu_recmax );
				l_next_itail = axt_nf9_rb_find_itail_tosend(l_rbuf, l_itail, l_rec_in_pk); 			//find next tail pos 
				
				if ((l_now_jf + l_sleep_jf) < (l_lastsend_jf + l_delay)) {		//if NF9_THR_SEND_INTERVAL_MAX_JF not ended
					if ((l_next_itail - l_itail) < l_rec_in_pk) break;  							//nothing to send now! or we have time for wait send!
				} else if ( l_next_itail <= l_itail) { 			 									//time ended but looks nothing to send
					if ((l_rbuf->tmpl_sempty)) l_pk_type = 1;	 									//l_rbuf->tmpl_sempty == 1 - OK let's send only temlate
						else break;								 									//realy nothing to send
				}
				//printk(KERN_INFO "xt_ANAT DEBUG: Nf9 send thread - send %d itail: %lld - %lld, ihead: %lld /\n", l_pk_type, l_itail, l_next_itail, axt_nf9_rb_get_ihead(l_rbuf));
				// do send UDP packet with records from l_itail to l_next_itail
				if (!axt_nf9_send_udppkt(l_rbuf, l_itail, l_next_itail, l_pk_type)) {
					axt_cnt_inc(&cnt_nf9_sended_pk);
					l_rbuf->pdu_seq++;
					l_lastsend_jf = l_now_jf;

					while (l_itail < l_next_itail) {
						l_rbuf->rb_data[axt_nf9_rb_di_from_i(l_rbuf, l_itail)].event = 0; //clear, WRITE_ONCE not needed (wmb and tail is in lower code)
						l_itail++;
					}

					wmb();
					//move rbuf tail
					atomic64_set(&(l_rbuf->itail), l_next_itail);
				}	
			}			
		}

	}
	// say "Good by."  sdy@mail.ru ;-)
	return 0;
}

// init send thread
static int   axt_nf9_send_thr_init(void) {
    int l_err;
    axt_nf9_send_thread = kthread_create(axt_nf9_send_thr_run, NULL, "xt_anat_nf9s");
    if ( IS_ERR(axt_nf9_send_thread) ) {
        l_err = PTR_ERR(axt_nf9_send_thread);
		printk(KERN_WARNING "xt_ANAT ERROR: Nf9 send thread create error : %d . \n", l_err);
        axt_nf9_send_thread = NULL;
        return l_err;
    }
    // kthread_bind (axt_nf9_send_thread, <N>); // bind to CPU<N>
	get_task_struct(axt_nf9_send_thread);
    wake_up_process(axt_nf9_send_thread); 	
	printk(KERN_INFO "xt_ANAT INFO: Nf9 send thread created [xt_anat_nf9s].\n");
    return 0;	
}

//  done send thread
static int   axt_nf9_send_thr_done(void) {
	if (axt_nf9_send_thread) {
		if ( !(axt_nf9_send_thread->state & (EXIT_DEAD | EXIT_ZOMBIE) ) ) {
			kthread_stop(axt_nf9_send_thread);
		}
		put_task_struct(axt_nf9_send_thread);
		axt_nf9_send_thread = NULL;
    }
 	printk(KERN_INFO "xt_ANAT INFO: Nf9 send thread stoped [xt_anat_nf9s].\n");
    return 0;	
}

//=========================  Nf9 Init / Done
// nf9 init 
static int   axt_nf9_init (void) {	
	//SDY  debug output 
    printk(KERN_INFO "xt_ANAT DEBUG:  AXT_NF9_PK_HDR_SIZE   = %ld\n", AXT_NF9_PK_HDR_SIZE);
    printk(KERN_INFO "xt_ANAT DEBUG:  AXT_NF9_PK_TMPL_SIZE  = %ld\n", AXT_NF9_PK_TMPL_SIZE);
    printk(KERN_INFO "xt_ANAT DEBUG:  AXT_NF9_PK_DHDR_SIZE  = %ld\n", AXT_NF9_PK_DHDR_SIZE);
    printk(KERN_INFO "xt_ANAT DEBUG:  AXT_NF9_PK_REC_SIZE   = %ld\n", AXT_NF9_PK_REC_SIZE);
    printk(KERN_INFO "xt_ANAT DEBUG:  AXT_NF9_PK_RECNUM_MAX = %d\n", AXT_NF9_PK_RECNUM_MAX);

	axt_nf9_rbuf = axt_nf9_rb_create(axt_iprm_nf9_NFRB_DATA_SZ2);
	if (!axt_nf9_rbuf) return -1; //is NULL
	if (axt_nf9_send_thr_init()) return -1; //error at init send thread )
	return 0;
}

// nf9 done 
static void   axt_nf9_done(void) { 
	axt_nf9_send_thr_done();
	axt_nf9_udpsock_done(axt_nf9_rbuf);
	axt_nf9_rb_free(&axt_nf9_rbuf);
}

/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */