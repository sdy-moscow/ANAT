/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 
// xt_ANAT_pc_htlist
// htlist - it is simple list for very big size highload hashe tables with large timeouts, and made for x86i64 64 bit 64byte cash architecture
//   		it do not use linux rcu  and lists because we needd less memory size for elements. It is clean making by timer and garbage fifo list.
//
//   base ideas are:
//		we have some ptr 'head' to the first element
//		we have only ptr 'next' in elements
// 		we always walk from head to the last 
//		last element 'next' is ptr to NULL (POISON_2 ptr)
//		we add elements only in the head by changing ptr head to the new first element ( lock (head); new.next = head; head=new; (unlock (head) );
//		at work we never delete first element (*head)
//		we remove all elements only at the end programm working, 
//		so if we add at once head element - we will be have first element in list to the end of work
//		all deletes are making only in one self locking thread (clear_timer), so we change element.next only in the 'locking' 
//		for selfRCU timeout protect kfree(), we have garbage_list which is used only in clear_timer (so garbage_list is always 'locking' too)
//		in each element we have field ptr 'next_garbage' (it can be union with payload data, buy NOT union with 'next' field!!)
//		clear alghoritm for clear_timer:
//			1. the timeout between clear_timer run mast be enough to selfRCU (we can check jiffies)
//			2. if timeout is enough we clear garbage_list by ( for_each_safe(elem){ kfree(elem);} garbage_list.head=NULL(POISON_2 ptr); 
//			3. we walk by for_each_safe(elem) store last not delete previos ptr ('ndprev') 
//				3.1. if we do not need more in element we set element flag to willdelete state on some timeout (nobody after that can use data on it) 
//				3.2. if it is not first element (*head) and it's in willdelete state with selfRCU timeout - we remove it by:
//					3.2.0. ?set and check flag 'isdeleted'? - realy we do not need it because now we have not hiden rcu timeouts and in locking at fact
//					3.2.1. WRITE_ONCE(ndprev.next, elem.next) (we no need (head) locking, so we can add elements non stop)
//					3.2.2. add element to 'garbage_list' fifo ; elem.next_garbage=garbage_list.head; garbage_list.head = elem;  
//		that is all!!!				
//
/*
	Продоолжение размышлений.
	На саммом деле удалять голову (первый элемент list) можно и нужно ,т.к. элемент у нас сразу в 2-х списках, просто при её удалении надо 
	блокировать изменение head, (как при add_head) При удалении аутер возникают варианты, так как мы идем по списку иннер, конечно, можно искать предыдущий элемент проходом по хэшу аутера,
	а можно хранить предыдущий элемент в списке как  hlist (но механизм будет попроще в нашем случае), нам достаточно только поля prev в аутер, которое
    может меняться только у первого элемента непосредственно перед добавления нового (уже в локировке). Первый ли элемент мы проверяем cur==READ_ONCE(head), 
	есл он не первый сейчас, то первым уже никогда не станет. Для иннера можно опираться на счестик цикла. Но в любом случае если он ппервый, нам надо поставить 
	локировку на хеад и дествовать проверив еще раз (в локировке, что cur==READ_ONCE(head)) если уже нет, локировку можно сбросить и удалять элемент 
	как обычый (не первый) без локировки, НО придется теперь найти кто-же стал элементом перед cur. Если же cur остался первым, то надо менять 
	head-next на cur-next и после этого локировку можно сразу отпускать.
	
	еще интереснее, использовать не флаги блокировки а сам адрес. изначально пустой адрес указывает на нечетный POISON1 (=POISON|1, POISON2=POISON1^1;
	(в реалии нечентных адресов у нас не бывает все выравнено минимум по 2, а по факту по 8 минимум )
	перед тем как изменить адрес с POISON1 на значимый делаем tb=test_and_clear_bit(0, ptr), если tb==1 - мы первые и можем работать, 
	если tb==0 - опоздали, НАДО НАЧИНАТЬ с начала, при этом то что адрес устанавливаем атомарно rcu_assign_pointer(), а проверяем его пустоту или
	занятость другим потоком сравнивая с POISON1 POISON2 или NULL, текущую модификацию (локировку) можно проверить сравнив с POISON2 
	таким образом блокировки становятся абсолютно локальными и вообще не требуют спинлоков.... если еще и избавится от .use в htb - получим идеальнй массив!
	
	механизмы эволюции:
		постулат - нечетных PTR не бывает
		добавление в хвост или удаление хвоста - в нашем случаt это битовая локировка, во избежании подвисаний делать это надо в режиме запрета softirq!
		next меняется строго в наравлениях:
			POISON1 -> POISON2 -> PTR      - перестал быть хвостом
			POISON1 -> POISON2 -> POISON4  - удаленный хвост
		праллельные потоки добавляют элементы только в конец списка:
			пытаются перевести next конца в POISON2 снимая нечетный бит  test_and_clear_bit 
				(для next уже в POISON2 и PTR: test == 0 - надо будет искать опять конец (что было: удалили или продолжили можно будет понять по POISON4!)
			!! прописывают (если надо) prev в новом элементе в состянии POISON2
			добавляют через rcu_assign_pointer(h->next, n);
		удаление производится в моно-потоке (самолокированном)
			удалять все элементы, в том числе из первый можно просто через rcu_assign_pointer(p->next, n->next);
			удалять последний элемент можно только по схеме с локировкой POISON1 -> POISON2 -> POISON4

		
	
*/		
// 		in this file we will make only define 
//				axt_htl_init_head
//				axt_htl_init_head_rcu
//				axt_htl_empty					(islast)
//				axt_htl_add_head
//				axt_htl_add_head_rcu
//				axt_htl_del
//				axt_htl_del_rcu
//				axt_htl_kfree_and_clear
//				axt_htl_for_each_safe_rcu
//		all other is making in htables and htimers 
//
//	ideas for bes locking head of htlist (because we optimse it for use x86i64 with 64 byte cash line it better to)
//		merge work on htlist heads in hash tables by 8 head, alligned to 64 address ( sizeof(prt)*8 = 64 byte == one cash line)
//		so we need 1 lock for 8 head ptr it htable 
//		struct htable {	prt* heads[SZ]; spinlock_t locks[SZ>>3]; }
//			on N : lock(htable.locks(N>>3); ... do somthing with heads[N] ... ; unlock(htable.locks(N>>3); 	

#ifndef SDY_PKC_F_T_xt_ANAT_pc_htlist
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_htlist 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */
/*
	compilation
		head psn 	- on head.next can be odd bit to be eq 1 (head is locked) - need to be clear for use as ptr
		tail psn	- on last.next is eq: POISON_1 - tail not locked, POISON_2 - tail locked, POISON_4 - tail deleted (not in list now)
		
	standart var names
		n 		- new or current element of htlist		
		h 		- head storage of htlist or HEAD storage pointer, we can use f(irst) in not head psn hlist 
		f 		- first in chain list element - it never can be head psn'ed
		l		- last element of htlist
		p	 	- previos element of htlist 
		ptr  	- pointer to axt_htl_node_s
		type 	- type of owner sruct 
		member 	- field fullname (x.d.s) in owner sruct \

	methods
		entry	- taking a ptr to the owner struct
		rcu 	- uses rcu save READ_ONCE WRITE_ONCE
		psn		- thinking that both head ant tail are psn (ALL rcu methods in htlist thinks that that tail is psn)
		hal		- head add list (if it is set, you can't use it for tal)  ALL hal methods is rcu+psn
		tal		- tail add list (if it is set, you can't use it for hal)  ALL tal methods is rcu+psn
		
		hla		- ead lock add - not use POISON - clear NULL use. h ALL tal methods is rcu
		
	!
		in hal tal lists never using NULL as next ptr !!! only POISSON
		in hal empty head(h): h.next can be only POISON2 if unlocked, POISON1 if locked, use axt_htl_init_hal() to init last or head elment
		in tal empty head(h): h.next can be only POISON1 if unlocked, POISON2 if locked, use axt_htl_init_tal() to init last or head elment
		if some one will be want to use tal+hal in one htlist - it is needed no change l.next POISON2/POISON1 for head/tail - do it uself

*/
struct axt_htl_node_s {								//use as node and head!
		struct axt_htl_node_s* next;
};

typedef struct axt_htl_node_s 			axt_htl_node_t;
typedef struct axt_htl_node_s* 			axt_htl_node_p;

//=======================   hla - first release 

#define	axt_hla_ptr_isempty(ptr)																\
			({											\
				( ((ptr) == NULL) );													\
			})

//entry			
#define axt_hla_entry(ptr, type, member)	\
			container_of(ptr, type, member)
			
#define axt_hla_entry_rcu(ptr, type, member)				\
			axt_hla_entry(READ_ONCE((ptr)), type, member)


#define axt_hla_entry_safe_rcu(ptr, type, member)										\
			({ typeof(ptr) ____ptr = READ_ONCE(ptr);									\
			axt_hla_ptr_isempty(____ptr) ? NULL : axt_hla_entry(____ptr, type, member);	\
			})

//cicles
#define axt_hla_for_each_safe_rcu(pos, nxt, head) 									\
	for (pos = READ_ONCE((head)->next);												\
		 !(axt_hla_ptr_isempty((pos))) && ({ nxt = READ_ONCE((pos)->next); 1; }); 	\
	     pos = nxt)

// cicles entry psn_rcu		
#define axt_hla_for_each_entry_rcu(pos, head, member)									\
	for (pos = axt_hla_entry_safe_rcu(((head)->next), typeof(*pos), member);			\
	     pos;  pos = axt_hla_entry_safe_rcu(((pos)->member.next), typeof(*pos), member))


// cicles entry safe_rcu				 
#define axt_hla_for_each_entry_safe_rcu(pos, nxt, head, member)						\
	for (pos = axt_hla_entry_safe_rcu(((head)->next), typeof(*pos), member);		\
	     pos && ({ nxt = READ_ONCE(((pos)->member.next)); 1; });					\
	     pos = axt_hla_entry_safe_rcu(nxt, typeof(*pos), member))
		 

#define axt_hla_for_each_from_entry_safe_rcu(pos, nxt, f, member)		\
	for (pos = axt_hla_entry_safe_rcu(((f)), typeof(*pos), member);		\
	     pos && ({ nxt = READ_ONCE(((pos)->member.next)); 1; });		\
	     pos = axt_hla_entry_safe_rcu(nxt, typeof(*pos), member))
		 
		 

// hlalist rcu  init
static inline void axt_hla_init_rcu(struct axt_htl_node_s *h) {
	rcu_assign_pointer(h->next, NULL);
}

// hlalist rcu  add
static inline void axt_hla_add_rcu(struct axt_htl_node_s *n,	struct axt_htl_node_s *h) {
//use with local lock only
	n->next = READ_ONCE(h->next);
	rcu_assign_pointer(h->next, n);
}

// hlalist rcu  del
static inline void axt_hla_del_rcu(struct axt_htl_node_s *n, struct axt_htl_node_s *p) {
	rcu_assign_pointer(p->next, READ_ONCE(n->next));
}

//test node			
static inline int axt_hla_isnxempty_rcu(const struct axt_htl_node_s *h) {
	//if (*h == NULL) return 1; 
	return axt_hla_ptr_isempty(READ_ONCE(h->next));
}

//==================================================================================================
//=======================   htl - future release may be

/*
#define axt_htl_container_of(ptr, type, member) ({         			\
			const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
			(type *)( (char *)__mptr - offsetof(type,member) );})
*/

/*
//base methods (copy of list.h)
// we take base saffety ptr (not NULL) from linux list 
#define AXT_HTL_POISON1				((void*) ((long long int)LIST_POISON1|1))		//odd  poisson for freelock (struct axt_htl_node_s *)
#define AXT_HTL_POISON2				((void*) ((long long int)AXT_HTL_POISON1^1))	//even poisson for buzylock 
#define AXT_HTL_POISON3				((void*) ((long long int)AXT_HTL_POISON1+2)))	//never used 
#define AXT_HTL_POISON4				((void*) ((long long int)AXT_HTL_POISON2+2))	//deleted tail which was in POISON1
#define AXT_HTL_INIT				AXT_HTL_POISON1

//need it function with tests and debug!!!!
#define axt_htl_clear_psn0(ptr) ( (struct axt_htl_node_s *)( (((long long int) (ptr))|1)^1 ) )



#define	axt_htl_ptr_isempty_psn(ptr)																\
			({	 typeof(ptr) ___tr_em_ptr = (ptr);													\
				( ((((long long int) ___tr_em_ptr)|3) == (((long long int) AXT_HTL_POISON1)|3)) );	\
			})
			
#define	axt_htl_ptr_isempty(ptr)																\
			({	 typeof(ptr) ___tr_em_ptr = (ptr);												\
				( ((((long long int) ___tr_em_ptr)|3) == (((long long int) AXT_HTL_POISON1)|3))	\
				  || ((((long long int) ___tr_em_ptr)|1) == (((long long int) NULL)|1)) );		\
			})

//entry			
#define axt_htl_entry(ptr, type, member)	\
			container_of(ptr, type, member)
			
#define axt_htl_entry_rcu(ptr, type, member)				\
			axt_htl_entry(READ_ONCE((ptr)), type, member)

//safety htl_entry with check ptr is equal NULL or AXT_HTL_POISON, ret NULL if it's. 
#define axt_htl_entry_safe_rcu(ptr, type, member)										\
			({ typeof(ptr) ____ptr = READ_ONCE(ptr);									\
			axt_htl_ptr_isempty(____ptr) ? NULL : axt_htl_entry(____ptr, type, member);	\
			})

#define axt_htl_entry_safe_psn_rcu(ptr, type, member)									\
			({ typeof(ptr) ____ptr = axt_htl_clear_psn0(READ_ONCE(ptr));				\
			axt_htl_ptr_isempty(____ptr) ? NULL : axt_htl_entry(____ptr, type, member);	\
			})

//cicles	

// cicles rcu		 
#define axt_htl_for_each_rcu(pos, head)																\
	for (pos = READ_ONCE((head)->next); (!axt_htl_ptr_isempty(pos)) ; pos = READ_ONCE((pos)->next))
		
#define axt_htl_for_each_safe_rcu(pos, nxt, head) 								\
	for (pos = READ_ONCE((head)->next);											\
		 !axt_htl_ptr_isempty((pos)) && ({ nxt = READ_ONCE((pos)->next); 1; }); \
	     pos = nxt)
		 
// cicles psn_rcu			 
#define axt_htl_for_each_psn_rcu(pos, head)												\
	for (pos = axt_htl_clear_psn0(READ_ONCE((head)->next)); (!axt_htl_ptr_isempty(pos));\
	pos = READ_ONCE((pos)->next))

#define axt_htl_for_each_safe_psn_rcu(pos, nxt, head) 							\
	for (pos = axt_htl_clear_psn0(READ_ONCE((head)->next));						\
		 !axt_htl_ptr_isempty((pos)) && ({ nxt = READ_ONCE((pos)->next); 1; }); \
	     pos = nxt)
		 
// cicles entry psn_rcu		
#define axt_htl_for_each_entry_psn_rcu(pos, head, member)							\
	for (pos = axt_htl_entry_safe_psn_rcu(((head)->next), typeof(*pos), member);	\
	     pos;  pos = axt_htl_entry_safe_rcu(((pos)->member.next), typeof(*pos), member))	 

#define axt_htl_for_each_from_entry_psn_rcu(pos, f, member)											\
	for (pos = axt_htl_entry_safe_psn_rcu(((f)), typeof(*pos), member);								\
	     pos;  pos = axt_htl_entry_safe_rcu(((pos)->member.next), typeof(*pos), member))
		 
// cicles entry safe_psn_rcu				 
#define axt_htl_for_each_entry_safe_psn_rcu(pos, nxt, head, member)					\
	for (pos = axt_htl_entry_safe_psn_rcu(((head)->next), typeof(*pos), member);	\
	     pos && ({ nxt = READ_ONCE(((pos)->member.next)); 1; });						\
	     pos = axt_htl_entry_safe_rcu(nxt, typeof(*pos), member))	 

#define axt_htl_for_each_from_entry_safe_psn_rcu(pos, nxt, f, member)		\
	for (pos = axt_htl_entry_safe_psn_rcu(((f)), typeof(*pos), member);		\
	     pos && ({ nxt = READ_ONCE(((pos)->member.next)); 1; });				\
	     pos = axt_htl_entry_safe_rcu(nxt, typeof(*pos), member))
		 
//init axt_htl methods
// htlist rcu with head add
static inline void axt_htl_init_hal(struct axt_htl_node_s *h) {
	rcu_assign_pointer(h->next, AXT_HTL_POISON2);
}

// htlist rcu with tail add
static inline void axt_htl_init_tal(struct axt_htl_node_s *h) {
	rcu_assign_pointer(h->next, AXT_HTL_POISON1);
}
//test node			
static inline int axt_htl_isempty_next_rcu(const struct axt_htl_node_s *h) {
	//if (*h == NULL) return 1; 
	//struct axt_htl_node_s *n = READ_ONCE(h->next);
	return axt_htl_ptr_isempty(READ_ONCE(h->next));
}

//next psn
static inline struct axt_htl_node_s* axt_htl_next_psn(const struct axt_htl_node_s *n) {
	return axt_htl_clear_psn0(READ_ONCE(n->next));
}

//add 
static inline void axt_htl_add(struct axt_htl_node_s *n,	struct axt_htl_node_s *h) {
	n->next = h->next;
	h->next = n;
}	

static inline void axt_htl_add_rcu(struct axt_htl_node_s *n,	struct axt_htl_node_s *h) {
//use with local lock only
	n->next = READ_ONCE(h->next);
	rcu_assign_pointer(h->next, n);
}


static inline int axt_htl_add_hal(struct axt_htl_node_s *n,	struct axt_htl_node_s *h) {
// it is add n with lock by bit 1
// ret 1 (true) - sucessfuly add, 0 - fail sombody do it already (need try again)
	if (unlikely( (test_and_set_bit(0,(void *) h))) ) return 0; 	 	//some was faster in busylock or its even ptr (not tail!)
	WRITE_ONCE(n->next, axt_htl_clear_psn0(READ_ONCE(h->next)));	//clear bit1 for n.next
	rcu_assign_pointer(h->next, n);  //bit1 = 0 becouse we do not have ptr = 0;
	return 1;	
}


static inline int axt_htl_add_tal(struct axt_htl_node_s *n,	struct axt_htl_node_s *l) {
// it is add n only if l->next is AXT_HTL_POISON1
// ret 1 (true) - sucessfuly add, 0 - fail sombody do it already (need find tail and try again)
// ! n->next - for rcu must be alredy correct pointer for next list part or eq AXT_HTL_POISON1 , we do not change it here
	if (unlikely( !(test_and_clear_bit(0,(void *) n))) ) return 0; 	 //some was faster in busylock or its even ptr (not tail!)
	if (unlikely( READ_ONCE(n->next) != AXT_HTL_POISON2) ) return 0; //some was change addres ptr (no rcu) or error in our code (odd not POISON1 ptr)
	rcu_assign_pointer(l->next, n);
	return 1;
}

static inline void axt_htl_del(struct axt_htl_node_s *n, struct axt_htl_node_s *p) {
	p->next = n->next;
}
			
static inline void axt_htl_del_rcu(struct axt_htl_node_s *n, struct axt_htl_node_s *p) {
	rcu_assign_pointer(p->next, READ_ONCE(n->next));
}

static inline int axt_htl_del_tal(struct axt_htl_node_s *n, struct axt_htl_node_s *p) {
	struct axt_htl_node_s 		*l_next;
	l_next = READ_ONCE(n->next);
	if (unlikely( l_next == AXT_HTL_POISON1) ) {							//it's unlocked tail, lets try lock tail and delete
		if (unlikely( !(test_and_clear_bit(0,(void *) n))) ) return 0; 		//some was faster in busylock
		if (unlikely( READ_ONCE(n->next) != AXT_HTL_POISON2) ) {			//some was faster set some addres ptr (no rcu) or it's some error in our code
			//need kprint debug error + cnt!
			return 0; 	
		}
		rcu_assign_pointer(p->next, AXT_HTL_POISON1);			//change tail - now p is tail
		rcu_assign_pointer(n->next, AXT_HTL_POISON4);			//set deleted tail to POISON4 state if you find it - begin from head again
	} else if (unlikely( (l_next == AXT_HTL_POISON2)) ) { //it's now locked tail 
		return 0; 		
	} else if (unlikely( (l_next == AXT_HTL_POISON4)) ) { //it's already deleteted tail!!! it must not happen!!!
			//need kprint debug error + cnt!
			return 1; 	
	} else 	
		rcu_assign_pointer(p->next, l_next);		 // it was ptr (or NULL) we don't worry
	return 1;	
	
	//rcu_assign_pointer(p->next, READ_ONCE(n->next));
}

static inline int axt_htl_del_hal(struct axt_htl_node_s *n, struct axt_htl_node_s *p) {
	//lets try lock tail and delete
	if (unlikely( (test_and_set_bit(0,(void *) p))) ) return 0; //some already do busylock or we have odd ptrs (can;t be!!!)
	rcu_assign_pointer(p->next, READ_ONCE(n->next));			//clear bit1 for n.next
	return 1;	
}	


//clear list with call kfree for each element  //rcu only for head. list must be locked or unusing!
#define axt_htl_kfree_and_clear(head, type, member) ({ 			\
	if ( !(axt_htl_isempty((head))) _n = READ_ONCE((head)->next);	\
		(type *) __p;			) {								\
		struct axt_htl_node_s *_								\
		rcu_assign_pointer((head)->next, AXT_HTL_INIT);			\
		while ( !(axt_htl_isempty(__n)) ) { 						\
			__p = axt_htl_entry(__n, type, member);				\
			__n = __n->next;									\
			kfree(__p);											\
		}														\
	}															\
})

*/

/*
static inline struct axt_htl_node_s * axt_htl_find_tail_psn_rcu(struct axt_htl_node_s *h) {
// ret ptr to tail (last) or h (head) if is empty list
	struct axt_htl_node_s 		*l_pos, *l_res;
	l_res = h;
	axt_htl_for_each_rcu(l_pos, h) {
		l_res = l_pos;
	}
	return l_res;
}
*/


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_htlist
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_htlist 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_htlist
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_htlist 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */