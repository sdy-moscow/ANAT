#ifndef _LINUX_NETFILTER_XT_ANAT_H
#define _LINUX_NETFILTER_XT_ANAT_H 1

enum axt_nat_target_variant {
    XTNAT_SNAT,
    XTNAT_DNAT,
};

struct axt_nat_tginfo {
    uint8_t variant;
};

#endif /* _LINUX_NETFILTER_XT_ANAT_H */
