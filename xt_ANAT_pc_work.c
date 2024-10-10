/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 

#ifndef SDY_PKC_F_T_xt_ANAT_pc_work
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_xt_ANAT_pc_work 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */

//max len of module paprametrs string and line size in config file
#define AXT_MAX_LINELEN  	128


#define AXT_STRE_EMPTY		-1		//empty string
#define AXT_STRE_NOBUF		-2		//buffer error (size to small or nill ptr)
#define AXT_STRE_DELNOTFND	-3		//delimiter not found
#define AXT_STRE_RANGE		-4		//range overflow
#define AXT_STRE_INVAL		-5		//invalid value
#define AXT_STRE_INVALUIPS	-6		//invalid user start IP 
#define AXT_STRE_INVALUIPE	-7		//invalid user end IP 
#define AXT_STRE_INVALNIPS	-8		//invalid nat start IP 
#define AXT_STRE_INVALNIPE	-9		//invalid nat end IP 
#define AXT_STRE_INVALIPRD	-10		//invalid IP range delimiter '-'
#define AXT_STRE_INVALIPPD	-11		//invalid IP delimiter ':'
#define AXT_STRE_INVALMRKF	-12		//invalid mark format
#define AXT_STRE_INVALMRKE	-13		//invalid mark end
#define AXT_STRE_INVALNHST	-14		//invalid nat ip hash type
#define AXT_STRE_INVALHDRD	-15		//invalid header delimiter ':'
#define AXT_STRE_INVALIP	-16		//invalid IP
#define AXT_STRE_INVALPORT	-17		//invalid port
#define AXT_STRE_GARBAGE	-18		//garbage in line
#define AXT_STRE_INVALTRCF	-19		//invalid trace char format
#define AXT_STRE_INVALUSGF	-20		//invalid user group format
#define AXT_STRE_INVALEXCF	-21		//invalid exclude mode format
#define AXT_STRE_INVALPROT	-22		//invalid protocol format

#define AXT_STRE_UNKNOWN	-1000	//unknown
/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_xt_ANAT_pc_work
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_xt_ANAT_pc_work 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_xt_ANAT_pc_work
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_xt_ANAT_pc_work 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */


// ===================================== STRING WORK (axt_wst_xxx)

static char*  axt_wst_ierror(const int i_errcode) {
	char	*l_einfo[23] = {
		"is needed  or unknown err",
		"empty string",
		"buffer error (size to small or nill ptr)",
		"delimiter not found",
		"range overflow",
		"invalid value",
		"invalid user start IP",
		"invalid user end IP",
		"invalid nat start IP",
		"invalid nat end IP",
		"invalid IP range delimiter '-' not found",
		"invalid IP delimiter ':' not found",
		"invalid mark format use dec, hex (0x..) or oct (0..) after!",
		"invalid mark end",
		"invalid nat ip hash type",
		"invalid header - delimiter ':' not present or wrong header format or wrong params order",
		"invalid IP",
		"invalid port",		
		"garbage in line",
		"invalid trace char format, use ^C (C='@','A'..'Z')",
		"invalid user group format, use +NN (NN = '00'..'63')",
		"invalid exclude mode format, use ^N (N='0'..'3')",
		"invalid protocol format, use pU, pT, pI, pO or p<N> (N=0..255)"
	};		
	if ((i_errcode> -1) || (i_errcode <-23)) return l_einfo[0];
	return  l_einfo[-i_errcode];
}

static int axt_wst_derror(const int i_errcode) {
//decode error to STRE_xxx
	if (i_errcode == -ERANGE) return AXT_STRE_RANGE;
	else if (i_errcode == -EINVAL) return AXT_STRE_INVAL;
	return AXT_STRE_UNKNOWN;
}	

/*
static int axt_wst_valueToUInt64(const char *i_buf, int64_t* v_int64res) {
// i_buf /0 ended to u64; retutn 0 if ok, or STRE error code
	int  	l_res;	
	if ( (l_res=kstrtoull(i_buf, 10, v_int64res)) ) return axt_wst_derror(l_res);  	//kstrtoll - int64_t,  kstrtoull - uint64_t
	return 0;
}
*/
static int axt_wst_valueToInt64(const char *i_buf, int64_t* v_int64res) {
// i_buf /0 ended to u64; retutn 0 if ok, or STRE error code
	int  	l_res;	
	if ( (l_res=kstrtoll(i_buf, 10, v_int64res)) ) return axt_wst_derror(l_res);  	//kstrtoll - int64_t,  kstrtoull - uint64_t
	return 0;
}

static inline char* axt_wst_posltrim(const char *i_start, char *i_tonext) {
//return ltrim pos in buf i_start, and end control
	char *s = (char *) i_start;
	while ((*s==' ') && (&s[0] < &i_tonext[0])) s++;
	return s;
}
static inline char* axt_wst_posrtrim(const char *i_start, char *i_tonext) {
//return rtrim pos in buf i_start from i_tonext, and start control
	char *s = (char *) i_tonext;
	while ( (&s[0] > &i_start[0]) ) { if(s[-1] != ' ') break; s--; }
	return s;
}

static  int axt_wst_trimtobuf(char *i_start,  char *i_tonext, char *v_buf, const int i_buf_sz) {
//i_start - substring begin, i_tonext - substring end (next char or \0.  ; retutn 0 if ok, or  STRE error code
	char	*sn, *sf;
	size_t  l_cpz;
	v_buf[0] = '\0';
	sn = axt_wst_posltrim(i_start,i_tonext);
	if (&sn[0] >= &i_tonext[0] ) return AXT_STRE_EMPTY; // it is empty string part;
	sf = axt_wst_posrtrim(sn, i_tonext); 
	if (!(l_cpz = &sf[0]-&sn[0])) return AXT_STRE_EMPTY; // it is empty
	//printk(KERN_INFO "xt_ANAT DEBUG: axt_prm_gettrimbuf sn : %s sf: %s l_cpz %ld\n", sn ,sf, l_cpz);
	if (l_cpz > i_buf_sz-1) return AXT_STRE_NOBUF; // it is too long
	strlcpy(v_buf, sn, l_cpz+1);
	v_buf[l_cpz] = '\0';
	return 0;
}

// <PARAM_NAME> = <VALUE>  substing process
 
static int inline axt_wst_isemty( char *i_start, char *i_tonext) {
	char	*sn;
	sn = axt_wst_posltrim(i_start,i_tonext);
	return ((&sn[0]>=&i_tonext[0]) || (sn[0]=='\0') || (sn[0]=='\n'));
}
 
static int inline axt_wst_finddelim( char **v_pos, char *i_start, char *i_tonext, const char i_delim_char){
//if  i_delim_char not found or \0 found, set (*v_pos) = i_tonext !!!
	*v_pos = strnchr(i_start, &i_tonext[0]-&i_start[0], i_delim_char);
	if (!(*v_pos)) { *v_pos = i_tonext; return AXT_STRE_DELNOTFND; } // not found 
	return 0;
}

static int axt_wst_trimbuf2part( char *i_start, char *i_tonext, char *v_left_buf, const int i_left_sz, char *v_right_buf, 
									const int i_right_sz, const char i_delim_char) {
// get trimmed <LEFT_PART> and <RIGHT_PART> from path sring from i_start to i_tonext or \0  divied string by path by first founded i_delim_char 
// retutn 0 if ok, or  STRE error code
// i_start, i_tonext - must be checked for correct value (less or eq  \0 pos) before call, i_start - must be NULL terminated string!
// v_left_buf and v_right_buf will set as \0 terminated trimed strings, i_left_sz i_right_sz - max buf size including \0
	char	*s;
	int  	l_res;
	v_left_buf[0] = '\0';
	v_right_buf[0]  = '\0';
	if ( (l_res=axt_wst_finddelim(&s,i_start,i_tonext, i_delim_char)) ) return l_res; 				// Delimiter char not found
	if ( (l_res=axt_wst_trimtobuf(i_start,	s, 	  		v_left_buf,  i_left_sz)) ) return l_res;	//error parse <LEFT_PART>
	if ( (l_res=axt_wst_trimtobuf(&s[1],	i_tonext,  v_right_buf, i_right_sz)) ) return l_res;	//error parse <RIGHT_PART>
	return 0;
}

static inline int axt_wst_trimbufNameEqVal( char *i_start, char *i_tonext, char *v_Name_buf, const int i_Name_sz, char *v_Val_buf, 
									const int i_Val_sz) {
// get trimmed  <NAME> and <VALUE> from " <NAME> = <VALUE> " path sring from i_start to i_tonext or \0 	
// retutn 0 if ok, or  STRE error code	
	return	axt_wst_trimbuf2part(i_start,i_tonext,v_Name_buf,i_Name_sz,v_Val_buf,i_Val_sz,'=');
}   
   
   
// load configs file records

static int 	axt_wst_take_uint32(char *i_start, char* i_tonext, char **v_sf, uint32_t *v_value) { //'  :  n'
//return <0 - error (-err_str (v_sf at first not ' 'char)), 0 - not found (v_sf at first not ' 'charat first not ' 'char), 1 - found (v_sf at first char after field)
	char			*s;
	
	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (!isdigit(*s))  return 0;	    	// no digits present
 	*v_value = simple_strtoul(s, &s, 10);	//use value only in dec format
	*v_sf = s;
	return 1;	
}

static int 	axt_wst_take_trch(char *i_start, char* i_tonext, char **v_sf, uint8_t *v_trch) { //'  ^C'
//return <0 - error (-err_str (v_sf at first not ' 'char)), 0 - not found (v_sf at first not ' 'charat first not ' 'char), 1 - found (v_sf at first char after field)
	char		*s;
	
	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (s[0] == '^') { // it is trace char id
		s++;
		if ((s[0]<'@') || (s[0]>'Z')) return AXT_STRE_INVALTRCF; 	    // no char '@','A'..'Z'
		*v_trch = (uint8_t)s[0] - 0x40; //'@', 'A'==1		
		*v_sf = ++s;
		return 1;
	}
	return 0;
}

static int 	axt_wst_take_usgr(char *i_start, char* i_tonext, char **v_sf, uint8_t *v_usgr) { //'  +UG'
//return <0 - error (-err_str (v_sf at first not ' 'char)), 0 - not found (v_sf at first not ' 'charat first not ' 'char), 1 - found (v_sf at first char after field)
	char		*s;
	uint8_t		l_usgr;
	
	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (s[0] == '+') { // it is user group can be here
		s++;
		if (!isdigit(s[0]) || !isdigit(s[1])) return AXT_STRE_INVALUSGF; 	    // no 2 digits after '^'  present
		l_usgr = ((uint8_t)s[0] - 0x30)*10 + ((uint8_t)s[1] - 0x30); 	//0x30 == '0'
		if (l_usgr > 63) return AXT_STRE_INVALUSGF;  //user group value can be 0-63
		*v_usgr = l_usgr;
		s++;
		*v_sf = ++s;
		return 1;
	}	
	return 0;
}

static int 	axt_wst_take_ip4h(char *i_start, char* i_tonext, char **v_sf, uint32_t *v_ip) { //'  x.x.x.x'
//return <0 - error or  not found (-err_str (v_sf at first not ' 'char)); 1 - found (v_sf at first char after field)
	char			*s;
	__be32			l_addrn;
	const char		*se;	

	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (!isdigit(*s))  return 0;	    		// no digits present
	if (!in4_pton(s, &i_tonext[0]-&s[0], (u8 *)&l_addrn, -1, &se)) return AXT_STRE_INVALIP; // ip not present or wrong value
	*v_ip = ntohl(l_addrn);
	*v_sf = (char *) se;
	return 1;	
}

static int 	axt_wst_take_porth(char *i_start, char* i_tonext, char **v_sf, uint16_t *v_port) { //'  :  n'
//return <0 - error (-err_str (v_sf at first not ' 'char)), 0 - not found (v_sf at first not ' 'charat first not ' 'char), 1 - found (v_sf at first char after field)
	uint32_t 		l_val1; 
	uint16_t		l_port;
	char			*s;
	
	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (*s != ':') return 0;	  	// ':' not present
	if (axt_wst_take_uint32(++s,i_tonext,&s,&l_val1) !=1) return AXT_STRE_INVALPORT;	 // no digits after ':'  present	
	if ( (l_port = (uint16_t) (l_val1)) != l_val1) return AXT_STRE_INVALPORT;		 // port value overflow
	*v_port = l_port;
	*v_sf = s;
	return 1;	
}

static int 	axt_wst_take_proto(char *i_start, char* i_tonext, char **v_sf, uint16_t *v_proto) { //'  p<proto> ' U-udp, T-tcp, I-icmp, O-other, <N> - num
//return <0 - error (-err_str (v_sf at first not ' 'char)), 0 - not found (v_sf at first not ' 'charat first not ' 'char), 1 - found (v_sf at first char after field)
// vproto other = 256!
	uint32_t 		l_val1; 
	uint16_t		l_proto;
	char			*s;
	
	s = axt_wst_posltrim(i_start, i_tonext);
	*v_sf = s;
	if (*s != 'p') return 0;	  	// 'p' not present
	s++;
	if (*s == 'T') {l_proto = IPPROTO_TCP;  goto proto_found;}
	if (*s == 'U') {l_proto = IPPROTO_UDP;  goto proto_found;}
	if (*s == 'I') {l_proto = IPPROTO_ICMP; goto proto_found;}
	if (*s == 'O') {l_proto = 256; goto proto_found;}
	if (axt_wst_take_uint32(s,i_tonext,&s,&l_val1) !=1) return AXT_STRE_INVALPROT;	 // no digits after ':'  present	
	if ( (l_proto = (uint8_t) (l_val1)) != l_val1) return AXT_STRE_INVALPROT;		 // port value overflow
	s--;
  proto_found:
	s++;
	*v_proto = l_proto;
	*v_sf = s;
	return 1;	
}

static int 	axt_wst_loadrec_natpool(char *i_start, char* i_tonext,
										uint32_t* v_uips, uint32_t* v_uipe, uint32_t* v_nips, uint32_t* v_nipe, 
										uint32_t* v_mark, uint32_t* v_marked, uint32_t* v_hashtype, uint32_t* v_exclude,
										uint8_t* v_trch, uint8_t* v_usgr) {
// *i_start must be \0 terminated string!!!,  return 0 or error code (<0)
	uint32_t 		l_uips, l_uipe, l_nips, l_nipe;
	uint32_t		l_mark, l_marked, l_hashtype, l_exclude;
	uint8_t  		l_trch, l_usgr; //trace char , user group
	int				l_havehead, l_havehasht, l_res;
	char			*s,*sf;

//  [ [^<T>] [+<UG>] [&<E>] [*L(inear)|*H(ash)] [!<mark>] : ] [ <usr_ip_start> - <usr_ip_end> :] <nat_ip_start> - <nat_ip_end>
	//default values

	l_mark 		= 0;  //mark value (if rule use mark !0 - the rule is ONLY for non marked trafic, if no !mark - rule is for all trafic)
	l_marked 	= 0;  //bool is !mark use in this line
	l_hashtype	= 0;  //0 - linear (reciprocal_scale only) 1-hash (jhash+reciprocal_scale)
	l_exclude 	= 0;  //0 - use all nat ir, 1- exclude x.x.x.0 (move to x.1), '2'- exclude x.x.x.255 (move to x.254), '3'- both (1) and (2))
	l_trch		= 0;  //trace_code for trace packets to msg: <C>-one char from 'A' to 'Z', default = '@' (store as charcode(C) - 40, 0=='@')
	l_usgr 		= 0;  //user group number 0-63, 0 - default  

	l_uips 		= 0;
	l_uipe 		= UINT_MAX;
	l_havehead  = 0;
	
	if ( (l_res = axt_wst_take_trch(i_start, i_tonext, &s, &l_trch)) < 0) return l_res;
	l_havehead += l_res;
	if ( (l_havehasht = axt_wst_take_usgr(s, i_tonext, &s, &l_usgr)) < 0) return l_havehasht;
	l_havehead += l_havehasht;
	s = axt_wst_posltrim(s, i_tonext);
	if (s[0] == '&') { // it is exclude mode can be here
		s++;
		if (!isdigit(s[0])) return AXT_STRE_INVALEXCF; // no digits after '&'  present
		l_exclude = (uint8_t)s[0] - 0x30; //0x30 == '0'
		if (l_exclude > 3) return AXT_STRE_INVALEXCF;  //exclude mode value can be 0-3
		s = axt_wst_posltrim(++s, i_tonext);
		l_havehead =1;
	}	
	if (s[0] == '*') { // it is hash method can be here
		s++;
		if (s[0] == 'L')  l_hashtype = 0;// it is nat ip method linear
		else if (s[0] == 'H') l_hashtype = 1; // it is nat ip method linear hash
		else return AXT_STRE_INVALNHST;
		s = axt_wst_posltrim(++s, i_tonext);
		l_havehead =1;
	}
	if (s[0] == '!') { // it is mark value can be here
		s++;
		if (!isdigit(s[0])) return AXT_STRE_INVALMRKF; 	    // no digits after '!'  present
		l_mark = simple_strtoul(s, &s, 0);	//use mark value in dec, hex (0x...) or oct (0..) format
		if (&(s[0]) > &i_tonext[0]) return AXT_STRE_INVALMRKE; //we have gone over path string end - it is abnormal
		s = axt_wst_posltrim(s, i_tonext);
		l_marked = 1;
		l_havehead =1;
	} 
	if (l_havehead) {
		if (s[0] != ':') return AXT_STRE_INVALHDRD;		// ':' header end not present
		s = axt_wst_posltrim(++s, i_tonext);
	}
	
	if ( !(axt_wst_finddelim(&sf, s, i_tonext, ':')) ) { // ':' present (not default pool)
		if ( axt_wst_take_ip4h(s, i_tonext, &s, &l_uips) < 0 )  return AXT_STRE_INVALUIPS; // ip not present or wrong value 
		
		s = axt_wst_posltrim(s, i_tonext);
		if (s[0] != '-') return AXT_STRE_INVALIPRD;		// '-' not present

		if ( axt_wst_take_ip4h(++s, i_tonext, &s, &l_uipe) < 0 )  return AXT_STRE_INVALUIPE; // ip not present or wrong value 
		
		s = axt_wst_posltrim(s, i_tonext);
		if (s[0] != ':') return AXT_STRE_INVALIPPD;	  	// ':' not present
		s++;
	} else {  // ':' not present (it is default pool)
		l_hashtype = (l_havehasht ? l_hashtype : 1); 
	}
	
	if ( axt_wst_take_ip4h(s, i_tonext, &s, &l_nips) < 0 )  return AXT_STRE_INVALNIPS; // ip not present or wrong value 

	s = axt_wst_posltrim(s, i_tonext);
	if (s[0] != '-') return AXT_STRE_INVALIPRD;	// '-' not present

	if ( axt_wst_take_ip4h(++s, i_tonext, &s, &l_nipe) < 0 )  return AXT_STRE_INVALNIPE; // ip not present or wrong value 

	s = axt_wst_posltrim(s, i_tonext);
	if (s[0] != '\0') return AXT_STRE_GARBAGE; // some garbage in line

	*v_uips = l_uips;
	*v_uipe = l_uipe;
	*v_nips = l_nips;
	*v_nipe = l_nipe;
	
	*v_mark 	= l_mark;
	*v_marked 	= l_marked;
	*v_hashtype = l_hashtype;
	*v_exclude 	= l_exclude;
	*v_trch		= l_trch;
	*v_usgr 	= l_usgr;
	
	return 0; 
}
					
static int	axt_wst_loadrec_nf9dest(char *i_start, char* i_tonext, uint32_t* v_ip, uint16_t *v_port ) {
	// return 0 or error code (<0)
	uint32_t		l_ip;
	uint16_t		l_port;
	int				l_res;
	char			*s;

	if ( (l_res = axt_wst_take_ip4h(i_start, i_tonext, &s, &l_ip)) <= 0 )  return l_res; // ip not present or wrong value 
	if ( (l_res = axt_wst_take_porth(s, i_tonext, &s, &l_port)) <0 )  return l_res;	  			// port value error
	if (l_res==0) return AXT_STRE_INVALIPPD;	// ':' not present
	s = axt_wst_posltrim(s, i_tonext);	
	if (*s != '\0') return AXT_STRE_GARBAGE; // some garbage in line
	
	*v_ip 	 = l_ip;
	*v_port  = l_port;
	return 0; 
}

static void	axt_wst_seq_printf_dtm64(struct seq_file *m, time64_t i_tm64 ) {
	struct tm 			l_tm;
	
	time64_to_tm(i_tm64, 0, &l_tm);
	seq_printf(m,"%02ld.%02d.%02d %02d:%02d:%02d", (l_tm.tm_year - 100), (l_tm.tm_mon+1), l_tm.tm_mday, l_tm.tm_hour, l_tm.tm_min, l_tm.tm_sec);
}

// ======================= TIME WORK (axt_wtm_xxx)

static inline uint64_t   axt_wtm_utc_to_loc_s( uint64_t i_utcs) {
//convert UTC time in sec to local time sec
	return (i_utcs + (axt_aprm_getN32(&axt_aprm_wtm_tmzn_mnt) * 60));
}

static inline uint64_t   axt_wtm_get_cur_ms(void) {
//get current real time UTC (time from 1970(00:00) in milliseconds 
	return (ktime_get_real_ns()/NSEC_PER_MSEC);
	//return (ktime_get_coarse_real_ns()/NSEC_PER_MSEC); // beter use for linux v5 ...}  
}

static inline int64_t   axt_wtm_get_cur_s(void) {
//get current real time UTC (time from 1970(00:00) in seconds 
	return ktime_get_real_seconds();
}  

static inline u_int64_t 	axt_wtm_get_cur_jif_s(void) {
	return  (get_jiffies_64() / HZ);
}

// ======================= atomic WORK (axt_wat_xxx) 16 bit & etc
//-- 16 bit counters work
//we do not have atomic 16 bit, so... lets think it will be work! someone can change it! i do not want!
// realy it is needed to use atomic_t or remove counters
//!!!!NEED SDY TODO future something - it is can be realy not atomic now!!!!

/* //now not used
static void axt_wat_inc16(volatile int16_t* i_var16) {
	((*i_var16)++);   
}
*/

static void axt_wat_dec16(volatile int16_t* i_var16) {
	((*i_var16)--);
}
		
static int16_t axt_wat_inc16_return(volatile int16_t* i_var16) {
	return (++(*i_var16));
}

static int16_t axt_wat_dec16_return(volatile int16_t* i_var16) {
	return (--(*i_var16));
}

static inline int16_t axt_wat_get16(int16_t* i_var16) {
	return READ_ONCE((*i_var16)); //SDY TODO 
}



/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */