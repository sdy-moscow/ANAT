/*
 ver 06:
 	pool format:
	 [ [^<T>] [+<UG>] [&<E>] [*L(inear)|*H(ash)] [!<mark>] : ] [ <usr_ip_start> - <usr_ip_end> :] <nat_ip_start> - <nat_ip_end>\n");
	 ^ - trace_code for trace packets to msg: <T>-one char from 'A' to 'Z', default = '@'
	 + - user_group <UG>='00'..'63': (must be 2 digits, use '01' not '1'), deafult = '00'
	 & - nat_use <E>-one digit: '0'- use all NAT ip , '1'- exclude x.x.x.0 (move to x.1), '2'- exclude x.x.x.255 (move to x.254), '3'- both (1) and (2)), default = '0'
	 * - nat_hash ip method : 'L' - linear, 'H' - jhash, default is: 'H'- for defaults pool (0-255.255.255.255) 'L'- for all other pools
	 ! - mark (take rule only for <mark> marked trafic (if !0 - it the rule is ONLY for non marked trafic, if no !<mark> - rule is for ALL trafic), default - no


	 USER-GROUP (0-63) - поле в ssi и user - каждый юзер добавляется с этим полем, поле включено в hash()
		0-63 -  для каждой из них можно задать не дефолтные лимиты и варнинги по количеству пакетов из массива лимитов и можно включить счетчики пакетов
		достаточно 1 uint64_t для проверки на включенные счетчики



	    счетчики
		пакетов in всего
		пакетов out всего
		байтов in всего
		байтов out всего
		таких 64 счетика --> 32 64байтных строки.... 
		
		
		пакетов in   всего на момент х
		пакетов out  всего на момент х
		байтов in 	 всего на момент х	
		байтов out 	 всего на момент х
		
		
		структура на 64байта на каждый ЦПУ, копируем в X в момент перехода jiffies для цпу....
		
		
		x - next jiffies > N jifiies >> 
	  
	+:match (mark) packets process for different pool select in config sets!
		марк маск в сессиях не нужен (будет ссылка на юзера), храним rule_id создания
		описание работы с марком
		логично - проверять марк в только в момент создания сессии (связки портов в первый раз) и сохранить в пуле данные по марку (ид строки пула)
		 также в пуле можно указать какую группу лимитов сессий (счетчиков) использовать!!!	и использовать юзера с этой группой счетчиков
		т.е. мы будем делить пользователей не по марк пакетов, а по группе счетчиков (массив+дефолт (-1) в массиве)
		т.к. мы редко добаляем пользователей и ищем по ним (теперь только при создании сессии), то для удобства анализа группу счетчиков не включаем
		:rule_id ид строки пула = 2 символа =XX= , по умолчанию =<N>= (N-номер строки пула формат =000= можно например делать 'SP' 'DD' и потом grep =SP=, =DD=
		axt_config_defnat_start, axt_config_defnat_end - удалить!
    +:исключение 0/255 адресов
    +:+cоnfig for address pool to nat address proces translation (scalar or hash) in config set line!
	+ :config pull line

	+: store trch&usgr nat pool value to ssi
	+: add trch & usgr to show sses
	
	+: add user var usgr to users struct 
	+: do search for new and update user counts + jhash with  usgr
	+: add usgr in show users - may be take nat ip by usgr filter too!!!
	+: add session print d_addr (start to)
	
	+: -- CHECK IT IN DEBUG CODE by direct call -- +: get pull nat ip create on new pool rool + mark test
	
	+: make trch on|off global var (32 bit set)
	+: add commands trace_X on|off
		CMD_TRACE_ON_<CHAR>
		CMD_TRACE_OFF_<CHAR>
		CMD_TRACE_START	
		CMD_ TRACE_STOP	
	+: add show in config trace state+rebuild config out
	+:add commands
		CMD_TRACE_USER_ON { <IP> [+<UG>] }|{ +<UG> }  - трассировка отдельного пользователя или user groupe - (включить можно только для1 !!!) (через глобальные переменные
		CMD_TRACE_USER_OFF

	+:add commands (сброс сессий пользователя - WILLBEDELETED = 1 по комманде для сессий с start < now_
		CMD_KILL_USER <IP>[p<roto>][:port][+<UG>][^<T>]    proto pU pT pI pO p<N>
		CMD_KILL_NAT  <IP>[:port][+<UG>][^<T>]
		CMD_KILL_ALL  [+<UG>][^<T>]
		
		CMD_NAT_BLOCK_ON  [<IP>][+<UG>]		- делаем через поле в user, проверяем в чек user, (работает только для существующих пользователей)
		CMD_NAT_BLOCK_OFF [<IP>][+<UG>]		- BLOCK_OFF не снимает PAUSE_ON

		CMD_NAT_PAUSE_ON   <TIME_S> [<IP>][+<UG>]		- делаем через поле в user (pause_jifiies !=0) - > - сбрасываем, проверяем в чек user, (работает только для существующих пользователей)
		CMD_NAT_PAUSE_OFF [<IP>][+<UG>]		- PAUSE_OFF не снимает BLOCK_ON
	+:show paused and block in user 
	---
	+:make process of CMD_KILL_XXX
	+:make process of CMD_NAT_XXX
	+:nat block/pause add to check user (+count) + user timer idle = 0 on pause&block
	+:timer user 
	+:add proto to CMD_KILL_XXX	
	+:test ses kill
	+:add counter+message for blocked or paused users
  	+:(look ALL PLACE msg format for trace char and usgr show)
	+:test nat block
	+:test nat pause\
 	---
	+:trace rbuf
		- 4 адреса - user + nat(out) + dest real + dest sessii + proto(1) = (24+1)  ==25 
		  +байт размер пакета = 2 байта, usgr(1) + trch(1) == 29 + флаг = направление+polici )(1) == 30 
		  (время = 2 байта) - секунды jiffies по маске - вычитаем из текущего при выводеб если минус то еще прибавит 0x100000000
		- остальное как в msg
	+:add donat - trace to trc 
	+:добавить trace_droped + trace_local_in 
	+:добавить политику для локального трафика rool for LOCAL_IN trafic donat
	+:добавить фильры trace по  proto/user-ip:port / nat-ip:port/  dest_real-ip:port/ 
		TRACE_FILTER_ON
		TRACE_FILTER_OFF
		TRACE_FILTER_SET_P p000 - 100 s00000-00000 dI|O|B  rA|D|B    <proto> <pksz> <direction - IN|OUT|BOTH>  <result - DROP|ACCEPT|BOTH
		TRACE_FILTER_SET_U 1.1.1.1 - 2.2.2.2 : 20000 - 30000
		TRACE_FILTER_SET_D 1.1.1.1 - 2.2.2.2 : 20000 - 30000 
		TRACE_FILTER_SET_N 1.1.1.1 - 2.2.2.2 : 20000 - 30000 
		TRACE_FILTER_SET_S 1.1.1.1 - 2.2.2.2 : 20000 - 30000
	+:test trace char 
	+:test usertrace_on 
	+:test_ip - привязка 1 из йп (любого, даже неи из пулов) к 1 любому нат ип + (+UG) +(^@) === для тестов админам
		TEST_IP_SET <user_ip> <nat_ip> +<UG> ^<T>
	---	
	+: add user groups limits array
	+: add user group limits to check&add user
	+: add show user groups limits 
	+: add show config info about see user groups limits & see params
	+: add commands to set user groups limits 
		USGR_SET_MAX <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]   (<nnn> - num or 'D' - def) if not set - not changed - deafult '*'
		USGR_SET_WRN <UG> [m-|m+] [t<nnn>] [u<nnn>] [i<nnn>] [o<nnn>]  m-messages (- off, + on, def +) t-tcp, u-udp, i-icmp, o-other
			<UG> - user group or 'ALL'
			default state [CMD_USGR_LIM_SET_ALL m+ t* u* i* o*] & [CMD_USGR_WRN_SET_ALL m+ t* u* i* o*]
	+: test user groups limits
	---
wv0_09(1_01b)
	+: Общие счетчики трафика in|out - байт
	+: erors count ресет [CMD_RESET_CNT_ER]
	+ Статик сессионс - порт мэппинг [CMD_STATIC_MAP_xxx]
	+ CMD_TEST_IP_SET - исправлен небольшой баг
	+ переименован счетчик CNT MM_ERBAG -> MM_ERBUG
	
	!!!!!!!!!!!!!!!!!IN FUTURE!!!!!!!!!!!!!
	STATIC_MAP для других протоколов (проблема номеров портов....) ? сделать еще поиск для портов = 0 ?
	
	:denied_nat_ip + hash смещение для денаид ИП в т.ч. .0 и .255 === для заблоченных ИП (до 10 шт)
	:доработка до работы other proto в режиме полного conntrack без jhash сжатия 
	-------------------
		: atomic 16 bit for usr counts in hashes + use 'use' as not empty state (! v0.8 - use can be incorrect some time)
	--- OR -- 
		:Статистика нагрузки хэший во время работы таймеров....	
		: CHANGE use to bits
	-------------------
	:механизмы пользователей
		переход счетчиков сеесий на атомик
		уборка локировок при поисках и обновлении счетчика сессий.  !!!! проблема идл -> 15
		механизм добавления - что-то может по аналогии  сесииям (ньюли) или повторный посик с блокировкой, веротяность не найти все-же ниже чем у сессий!
	-------------------
	:механизм создания сессии - переделка на поиск со вставкой newly локировка по newly
		добавить пропись пользователя сразу в сессию (всё равно вызываем тесты!) - для счетчиков в будущем
		механизм поиска свободных ип убрать полную блокировку - сделать спекулятивный поиск без блокировки с попыткой захватить после найденого
		(возможно сделать спекулятивным по числу попыток) начиная со второго случайного прыжка	:счетчики - переделать с обращения к переменной на вызов инкримент и реад по ид и разделить их по кэш строкам и добавить пер_цпу для нагруженных  
	---
	:Общие счетчики по группам пользователй  с привязкой к процессору
	: add commands ugcnt_X on|off
		ugcnton_<UG>
		ugcntoff_<UG>		
		ugcntdisable
		ugcntenable
	---
	:Cчетчики трафика для пользоввателей + show топ100 через вытесняющую сортировку через /proc/...  --- а надо ли? Сделаеть только под заказ! Или если сильно захочется.
 	:show only bloked and paused ? grep -PAUSE- -BLOCK-
	
    8. description of mark,hash,trace work
    d1. session nf9 keepalive description ( quick send interval = 360 (6 minutes) )
    d2. nf9 work description
    d3. configs desription adn swap

    15. //proc/.. >> in vars format
    f1. dbg_kprint

  SDY TODO future
	:?- Убрать use для хтсессий и юзеров 
		сейчас есть плюс, т.к. там где хэши пустые - удалили и еще 20 сек висит сессия с мусором - проверка use чуть ускоряет)
		счет можно перенсти в таймер = пока-же просто обернул dec/inc в всевдо функции - могут врать, но удалятся если что
	:ГЛОБАЛЬНО - синхронизация 2-х серверов между собой....
	:Упаковать юзера в 32 байта - не очень реально с hlist! да и нет смысла пока-что пользователей не больше 10000 на сервер 
 	:64bit id for quick search and translation (порт можно объединить с флагами), есть смысл только для очень длинных хешей!!! 
	:Убрать lock для хтсессий - переход на POISSON1, POISSON2 с добавлением для inner в хвост, для оут в хеад ( версия 06bad )
 	:Механизм поиска свободных ип не очень хорош для высоко загруженных NAT адресов
 	:Look at linux/percpu_counter.h for cnt_pkt_allint  cnt_pkt_allext  cnt_pkt_dnat_dropped
	https://elixir.bootlin.com/linux/v4.17.19/source/include/linux/percpu_counter.h
	
	https://www.menog.org/presentations/menog-10/Amir%20Tabdili%20-%20Carrier%20Grade%20NAT.pdf	

  подумать
    for SDY  look like work RCU free timeout in sessions! if we are in different thread...
    хэши юзеров сейчас 16 битные наборы хеадера 8б, лок4, и счетчик 16 бит выровнен до 32 бита (сделать атомик?) или просто 32 бита и не парится...   
	поле use в хэш таблица - а надо ли оно вообще? всегда можно посчитать при проходе таймера...

 идейки:
   Сжатые атомик счетчики 16 бит.
	1 счетчик в нижние 2 байта - изм (+/-)1, второй в верхние два байта (+/-)1*0x10000, верхние биты пар можно использовать как признак оверлоад 
	с выдачей ошибки (отдельный счетчиу ошибо и мессэдж при чем в - можно и в дмесдж, а в больший типа  - ваша дата ту матч... :-)
	но пока обойдемся и axt_wat_xxx16
	
   Счетчики пользователей.
	В usr добавим в начальные 64 бита счечики и флаги, а list структуры и проверяеммые данные во вторые 64 
	(они практически не меняются, но читаются часто). Т.о. кэш себя будет лучшечувствовать при апдейтах и ондовременном поиске...
	В счетчики 4 64 битных атомик ин/оут пакеты/объем = 32 байта, 32 битные копии 'кусочков shr' счетчиков на начало джифеса = 4*32=16 байт, 
	последний джифес сброса кусочков счета = 32 бит (4 байта) с извратом подсчета, период = джифес/... = 8-16 бит = 1-2 байта, флаги =1-2 байта, 
	счетчики сессий по протоколам 4*2=8байт.
	измеряем скорости (дельты счетчиков) в джифес периоды, при смене периода,при смене периода джифеса, смотрим сожранненые кусочки и текущие, 
	делим на разницу в текущем и сохранном джифес ну и куда-то накапливаем итоги (например еще в 4 периода джифеса - 64 байта) 
   Топ 100 (N) пользователей
    Проходим по пользователям по запросу и собираем топ 100 верхних значений каких либо счетчиков или их сумм. сделать можно через вытясняющий буфер:
	запись {показания, следующий [N]} команда реодер - выстраивает через 'следующий' цепочку по возрастанию, мы помним минимальный и максимальный, 
	берем показание, если меньше минимального - пропускаем, если больше минимального, но меньше второго снизу - заменяем минимальный на наш  сохранением 
	'следующий', если больше максимального, записываем на место минимального, но добавлем в цепочку 'следующий' в вверх перед максимумом, сдвигая текущий 
	минимальный и максимальный 	вверх. 
	Если же в не попал в начало или конец, то добавляем на место минимального и создаем НОВУЮ (вторую) цепочку. И теперь при добавлении элемента 
	проделываем вставку так-же но уже с учетом двух цепочек и их нижних концов вытесняя минимальные из основной или низа новой цепочки и вставляя если что в 
	вверх новой цепочки, если вытеснить из обоих цепочек не получается, делаем реодер всех данных с учетом уже наличия сортировки в основной цепочке
	и ее отсутвия в новой отсортировав предварительно новую и потом проходя и меняя индексы новой на индексы в основной.
*/
// local_bh_disable()  local_bh_enable()

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/ctype.h>
//#include <endian.h>
#include <net/tcp.h>
#include <linux/sched.h>   //wake_up_process()
#include <linux/kthread.h> //kthread_create()、kthread_run()
#include <linux/err.h>
#include <linux/sched/task.h>
#include "compat.h"
#include "xt_ANAT.h"

//================== debug work
#define PRINT_DBG 1
#define axtdbg(a) { if (PRINT_DBG) a; }

//================== global axt settings and var
#define AXT_TCP_SYN_ACK 		0x12
#define AXT_TCP_FIN_RST 		0x05

#define AXT_FLAG_ACTIVED_BN   		0 			// 0x01h  user (inside) was active or we take first time reply tm (will be reset = reset_tm)  
#define AXT_FLAG_REPLIED_BN  		1 			// 0x02h  was replied from outside (reset_tm (0) = 30s, (1) = isICMP : 30s ? 300s )
#define AXT_FLAG_TCP_FIN_BN   		2 			// 0x04h  was tcp_fin (if AXT_FLAG_ACTIVED_BN == 0 then tm will be set = 0); 
#define AXT_FLAG_ITSICMP_BN   		3 			// 0x08h  It is ICMP proto - max reset_tm = 30
#define AXT_FLAG_ISNEWLY_BN   		4 			// 0x10h  It is ICMP proto - max reset_tm = 30
#define AXT_FLAG_WILLDEL_BN   		5 			// 0x20h  session will be deleted (tm=0) all new operation is depricated
#define AXT_FLAG_DELFRIN_BN   		6 			// 0x40h  already deleted form innssi chain list (sets only with AXT_FLAG_WILLDEL_BN
#define AXT_FLAG_DELETED_BN   		7 			// 0x80h  session was deleted all operation is depricated

#define AXT_FLAG_ACTIVED   		(1 << AXT_FLAG_ACTIVED_BN) 
#define AXT_FLAG_REPLIED   		(1 << AXT_FLAG_REPLIED_BN)
#define AXT_FLAG_TCP_FIN   		(1 << AXT_FLAG_TCP_FIN_BN)
#define AXT_FLAG_ITSICMP  		(1 << AXT_FLAG_ITSICMP_BN) 
#define AXT_FLAG_ISNEWLY   		(1 << AXT_FLAG_ISNEWLY_BN)  
#define AXT_FLAG_WILLDEL   		(1 << AXT_FLAG_WILLDEL_BN)
#define AXT_FLAG_DELFRIN   		(1 << AXT_FLAG_DELFRIN_BN)
#define AXT_FLAG_DELETED   		(1 << AXT_FLAG_DELETED_BN)

#define AXT_FLAG_DEPRICT		(AXT_FLAG_WILLDEL|AXT_FLAG_DELETED|AXT_FLAG_DELFRIN)

// session timeouts
#define AXT_TMT_SSTMT_STA   	(101)   //sesssion is static (timeout =100 do not dec!)
#define AXT_TMT_SSTMT_SHS   	(50)    //sesssion timeout 0 shift to use unsigned values

// session keepalive event interval, prevent double sent keepalive nf9
#define AXT_TMT_SSINT_MSF		(0xFF)


// working dir handler (/proc/... )
static struct proc_dir_entry 	*axt_proc_dir = NULL;

static int axt_debug(void);

/* \/ ================= SDY partial kernel coding (PKC) for modules START ================= \/ */
/* ================= SDY PKC for modules TYPES================= */
#define SDY_PKC_S_TYPES 1
	#include "xt_ANAT_pc_work.c"
	#include "xt_ANAT_pc_htlist.c"
	#include "xt_ANAT_pc_param.c"
	#include "xt_ANAT_pc_config.c"
	#include "xt_ANAT_pc_message.c"
	#include "xt_ANAT_pc_cnt.c"
	#include "xt_ANAT_pc_htables.c"
	#include "xt_ANAT_pc_donat.c"
	#include "xt_ANAT_pc_nf9.c"
	#include "xt_ANAT_pc_htimers.c"
	#include "xt_ANAT_pc_hshow.c"
#undef SDY_PKC_S_TYPES 

/* ================= SDY PKC for modules VARS ================= */
#define SDY_PKC_S_VARS 1
	#include "xt_ANAT_pc_work.c"
	#include "xt_ANAT_pc_htlist.c"
	#include "xt_ANAT_pc_param.c"
	#include "xt_ANAT_pc_config.c"
	#include "xt_ANAT_pc_cnt.c"
	#include "xt_ANAT_pc_message.c"
	#include "xt_ANAT_pc_htables.c"
	#include "xt_ANAT_pc_donat.c"
	#include "xt_ANAT_pc_nf9.c"
	#include "xt_ANAT_pc_htimers.c"
	#include "xt_ANAT_pc_hshow.c"
#undef SDY_PKC_S_VARS 
	
/* ================= SDY PKC for modules CODE ================= */
#define SDY_PKC_S_CODE 1
	#include "xt_ANAT_pc_work.c"
	#include "xt_ANAT_pc_htlist.c"
	#include "xt_ANAT_pc_param.c"
	#include "xt_ANAT_pc_cnt.c"
	#include "xt_ANAT_pc_message.c"
	#include "xt_ANAT_pc_nf9.c"
	#include "xt_ANAT_pc_config.c"
	#include "xt_ANAT_pc_htables.c"
	#include "xt_ANAT_pc_donat.c"
	#include "xt_ANAT_pc_htimers.c"
	#include "xt_ANAT_pc_hshow.c"
#undef SDY_PKC_S_CODE 

/* /\ ================= SDY partial kernel coding (PKC) for modules END ================= /\*/	
	
	
// xt_regisration
static struct xt_target		axt_nat_tg_reg __read_mostly = {
    .name     = "ANAT",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .hooks    = (1 << NF_INET_FORWARD) | (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING),
    .target   = axt_dnt_nat_tg,
    .targetsize = sizeof(struct axt_nat_tginfo),
    .me       = THIS_MODULE,
};

//==== DEBUG BEGIN
/*
static void	axt_dbg_printktm64( time64_t i_tm64 ) {
	struct tm 			l_tm;
	
	time64_to_tm(i_tm64, 0, &l_tm);
	printk("%02ld.%02d.%02d %02d:%02d:%02d\n", (l_tm.tm_year + 1900), (l_tm.tm_mon+1), l_tm.tm_mday, l_tm.tm_hour, l_tm.tm_min, l_tm.tm_sec);
}
*/
static int axt_debug(void) {
/*	uint32_t		l_ip, l_nip, l_nipnat, i;
	uint8_t  		l_trch, l_usgr; //trace char , user group
	
	l_ip  = 10*256*256*256+253;
	printk(KERN_INFO "xt_ANAT DBG: --- M=10 ---");	
	for (i = 0; i<6; i++, l_ip++) {
		l_nip = htonl(l_ip);
		l_nipnat = axt_cfg_get_nataddr(l_nip, &l_trch, &l_usgr, 0, 10, 1);
		printk(KERN_INFO "xt_ANAT DBG: ip: %d - %pI4 >> %pI4", l_ip, &l_nip, &l_nipnat);
	}

	l_ip  = 10*256*256*256+253;
	printk(KERN_INFO "xt_ANAT DBG: --- M=11 ---");
	for (i = 0; i<6; i++, l_ip++) {
		l_nip = htonl(l_ip);
		l_nipnat = axt_cfg_get_nataddr(l_nip, &l_trch, &l_usgr, 0, 11, 1);
		printk(KERN_INFO "xt_ANAT DBG: ip: %d - %pI4 >> %pI4", l_ip, &l_nip, &l_nipnat);
	}	

	l_ip  = 10*256*256*256+253;
	l_usgr = 24;
	printk(KERN_INFO "xt_ANAT DBG: --- U=24 ---");	
	for (i = 0; i<6; i++, l_ip++) {
		l_nip = htonl(l_ip);
		l_nipnat = axt_cfg_get_nataddr(l_nip, &l_trch, &l_usgr, 1, 0, 0);
		printk(KERN_INFO "xt_ANAT DBG: ip: %d - %pI4 >> %pI4", l_ip, &l_nip, &l_nipnat);
	}	

*/	
	
//	u64 			l_sc;
/*	l_sc = ktime_get_boot_fast_ns();
	printk(KERN_INFO "xt_ANAT DBG: ktime_get_boot_fast_ns() l_sc: %lld, l_sc/NSEC_PER_SEC: %lld DTl_sc: \n",l_sc,l_sc/NSEC_PER_SEC);
	axt_dbg_printktm64(l_sc/NSEC_PER_SEC);

	l_sc = get_jiffies_64();
	printk(KERN_INFO "xt_ANAT DBG: get_jiffies_64() l_sc: %lld, l_sc/HZ: %lld DTl_sc: \n",l_sc,l_sc/HZ);
	axt_dbg_printktm64(l_sc/HZ); 
	
	l_sc = jiffies64_to_nsecs(get_jiffies_64());
	printk(KERN_INFO "xt_ANAT DBG: jiffies64_to_nsecs() l_sc: %lld, l_sc/NSEC_PER_SEC: %lld DTl_sc: \n",l_sc,l_sc/NSEC_PER_SEC);
	axt_dbg_printktm64(l_sc/NSEC_PER_SEC);
	
	l_sc = axt_wtm_get_cur_s();
	printk(KERN_INFO "xt_ANAT DBG: axt_wtm_get_cur_s() l_sc: %lld ",l_sc);
	axt_dbg_printktm64(l_sc); 
	
	printk(KERN_INFO "xt_ANAT DBG: sys_tz.tz_minuteswest: %d ", sys_tz.tz_minuteswest);
	//sys_tz.tz_minuteswest
	//seq_printf(m," [%3d] ", i_r->count);
*/	
    return 0;
}
//==== DEBUG END

static void    axt_nat_do_done(void) {
	//all called function from this method must be self protected for not init done! 
 	//remove timers
	axt_htm_timers_del();
	// remove /proc/... entry	
	if (axt_proc_dir) {
		axt_hsh_remove_proc_fs(axt_proc_dir);	
		axt_cnt_remove_proc_fs(axt_proc_dir);
		axt_cfg_remove_proc_fs(axt_proc_dir);
		axt_prm_remove_proc_fs(axt_proc_dir);	
		axt_msg_remove_proc_fs(axt_proc_dir);
		//remove dir in /proc
		proc_remove(axt_proc_dir);
	}
	//done
	axt_nf9_done();
	axt_htb_done();
	axt_msg_done();
	axt_cfg_done();
	axt_prm_done();
}

static int __init   axt_nat_tg_init(void) {
	printk(KERN_INFO "xt_ANAT INFO: Module xt_ANAT starting...\n");
	//init params
	if (axt_prm_init()) goto err_exit;
	//init and load some config from init params
  	if (axt_cfg_init()) goto err_exit;
	//init messages	
 	if (axt_msg_init()) goto err_exit;
	//init htables
	if (axt_htb_init()) goto err_exit;
	//init nf9
 	if (axt_nf9_init()) goto err_exit;
	//init /proc dir
	axt_proc_dir = proc_mkdir("ANAT",init_net.proc_net);
 	//init /proc dir entires
	axt_hsh_create_proc_fs(axt_proc_dir);
	axt_cnt_create_proc_fs(axt_proc_dir);
	axt_cfg_create_proc_fs(axt_proc_dir);
	axt_prm_create_proc_fs(axt_proc_dir);
	axt_msg_create_proc_fs(axt_proc_dir);
	//init timers

	axt_htm_timers_setup();
	//register xt_ANAT - it is must to be last we do on load (register xt_target) we do not unregister on error!!!
	if (xt_register_target(&axt_nat_tg_reg)) goto err_exit; 
 	printk(KERN_INFO "xt_ANAT INFO: Module xt_ANAT loaded.\n");
   return 0;
	
  err_exit:
	printk(KERN_INFO "xt_ANAT ERROR: Module xt_ANAT load error! Exit on error started.\n");
	axt_nat_do_done();
    printk(KERN_INFO "xt_ANAT INFO: Module xt_ANAT not loaded.\n");
	return -1;
}

static void __exit   axt_nat_tg_exit(void) {
    printk(KERN_INFO "xt_ANAT INFO: Module xt_ANAT finishing...\n");
   // unregister xt_ANAT
	xt_unregister_target(&axt_nat_tg_reg);
	axt_nat_do_done();
    printk(KERN_INFO "xt_ANAT INFO: Module xt_ANAT unloaded.\n");
}

module_init( axt_nat_tg_init );
module_exit( axt_nat_tg_exit );

MODULE_DESCRIPTION(	"Xtables: ANAT (Advanced xt NAT) v.1.01b(0.09)" );
MODULE_AUTHOR(		"Serbulov Dmitry <sdy@a-n-t.ru>, xt_nat based on xt NAT by Andrei Sharaev <andr.sharaev@gmail.com>" );
MODULE_LICENSE(		"GPL" );
MODULE_ALIAS(		"ipt_ANAT" ); 

