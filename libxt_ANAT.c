#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_ANAT.h"

enum {
    F_SNAT  = 1 << 0,
    F_DNAT  = 1 << 1,
};

static const struct option axt_nat_tg_opts[] = {
    {.name = "snat", .has_arg = false, .val = 's'},
    {.name = "dnat", .has_arg = false, .val = 'd'},
    {NULL},
};

static void axt_nat_tg_help(void)
{
    printf(
        "ANAT target options:\n"
        "  --snat    Create ANAT translation from Inside to Outside\n"
        "  --dnat    Allow ANAT for revert traffic from Outside to Inside\n");
}

static int axt_nat_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_target **target)
{
    struct axt_nat_tginfo *info = (void *)(*target)->data;

    switch (c) {
    case 's':
        info->variant = XTNAT_SNAT;
        *flags |= F_SNAT;
        return true;
    case 'd':
        info->variant = XTNAT_DNAT;
        *flags |= F_DNAT;
        return true;
    }
    return false;
}

static void axt_nat_tg_check(unsigned int flags)
{
    if (flags == (F_SNAT | F_DNAT))
        xtables_error(PARAMETER_PROBLEM,
                      "ANAT: only one action can be used at a time");
}

static void axt_nat_tg_save(const void *ip,
                        const struct xt_entry_target *target)
{
    const struct axt_nat_tginfo *info = (const void *)target->data;

    switch (info->variant) {
    case XTNAT_SNAT:
        printf(" --snat ");
        break;
    case XTNAT_DNAT:
        printf(" --dnat ");
        break;
    }
}

static void axt_nat_tg_print(const void *ip,
                         const struct xt_entry_target *target, int numeric)
{
    printf(" -j ANAT");
    axt_nat_tg_save(ip, target);
}

static struct xtables_target axt_nat_tg_reg = {
    .version       = XTABLES_VERSION,
    .name          = "ANAT",
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct axt_nat_tginfo)),
    .userspacesize = XT_ALIGN(sizeof(struct axt_nat_tginfo)),
    .help          = axt_nat_tg_help,
    .parse         = axt_nat_tg_parse,
    .final_check   = axt_nat_tg_check,
    .print         = axt_nat_tg_print,
    .save          = axt_nat_tg_save,
    .extra_opts    = axt_nat_tg_opts,
};

static __attribute__((constructor)) void axt_nat_tg_ldr(void)
{
    xtables_register_target(&axt_nat_tg_reg);
}

