/* ================= SDY partial kernel coding (PKC) for modules ================= */
/* xt_ANAT kernel module working with counters v0.01
   for correct build USE $make clean BEFORE $make all OR $make clean && make all
   BEFORE USE CHANGE <FileName> to Real filename xt_ANAT_pc_<xxx> (please be accuracy)
*/ 

#ifndef SDY_PKC_F_T_<FileName>
#ifdef SDY_PKC_S_TYPES
#define SDY_PKC_F_T_<FileName> 1
/* \/ ================= SDY PKC TYPES DEFINE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC TYPES END  ================= /\*/
#endif /* SDY_PKC_S_TYPES */
#endif /* SDY_PKC_F_T_xxx*/

#ifndef SDY_PKC_F_V_<FileName>
#ifdef SDY_PKC_S_VARS
#define SDY_PKC_F_V_<FileName> 1
/* \/ ================= SDY PKC VAR DEFINE SECTION for modules ================= \/ */

/* /\ ================= SDY PKC VARS END  ================= /\ */
#endif /* SDY_PKC_S_VARS */
#endif /* SDY_PKC_F_V_xxx */

#ifndef SDY_PKC_F_C_<FileName>
#ifdef SDY_PKC_S_CODE
#define SDY_PKC_F_C_<FileName> 1
/* \/ ================= SDY PKC CODE SECTION for modules ================= \/ */


/* /\ ================= SDY PKC CODE END  ================= /\ */
#endif /* SDY_PKC_S_CODE */
#endif /* SDY_PKC_F_C_xt_xxx */