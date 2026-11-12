/*
 * netswitch_filter.c: the network filters (nwfilter) of the ports of a
 * libvirt_netswitch switch
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * What ebtables/iptables, or nftables, do with the rules of nwfilter on the
 * TAP device of a guest on Linux, for the ports of the switch: the program
 * the netswitch tech driver of nwfilter compiled for an interface (see
 * src/nwfilter/nwfilter_netswitch_driver.c for its format and semantics)
 * runs on each frame to or from the port, with the connection tracking of
 * netfilter for the rules that match states.
 */

#include <config.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netswitch_filter.h"

#define NS_MAX_DEPTH 16

enum {
    NS_ETH, NS_INET,
};

enum {
    NS_DIR_IN, NS_DIR_OUT,
};

typedef enum {
    NS_V_NONE,
    NS_V_ACCEPT,
    NS_V_DROP,
    NS_V_REJECT,
    NS_V_RETURN,
    NS_V_CONTINUE,
    NS_V_JUMP,
} nsRuleVerdict;

typedef enum {
    NS_M_SMAC,
    NS_M_DMAC,
    NS_M_ETYPE,
    NS_M_VLAN_ID,
    NS_M_VLAN_TYPE,
    NS_M_ARP_HTYPE,
    NS_M_ARP_PTYPE,
    NS_M_ARP_OP,
    NS_M_ARP_SPA,
    NS_M_ARP_TPA,
    NS_M_ARP_SHA,
    NS_M_ARP_THA,
    NS_M_ARP_GARP,
    NS_M_SRC,
    NS_M_DST,
    NS_M_PROTO,
    NS_M_SPORT,
    NS_M_DPORT,
    NS_M_DSCP,
    NS_M_ICMP_TYPE,
    NS_M_ICMP_CODE,
    NS_M_L3,
    NS_M_L4,
    NS_M_TCP_FLAGS,
    NS_M_TCP_OPTION,
    NS_M_CONNLIMIT,
    NS_M_CT_DIR,
    NS_M_CT_STATE,
    NS_M_STP_TYPE,
    NS_M_STP_FLAGS,
    NS_M_STP_ROOT_PRIO,
    NS_M_STP_ROOT_ADDR,
    NS_M_STP_ROOT_COST,
    NS_M_STP_SENDER_PRIO,
    NS_M_STP_SENDER_ADDR,
    NS_M_STP_PORT,
    NS_M_STP_AGE,
    NS_M_STP_MAX_AGE,
    NS_M_STP_HELLO,
    NS_M_STP_FWD_DELAY,
} nsMatchKey;

typedef enum {
    NS_T_MAC,                   /* MAC[/MASK] */
    NS_T_IP,                    /* IP[/LEN] or IP-IP */
    NS_T_NUM,                   /* N[-N] */
    NS_T_FLAGS,                 /* MASK/FLAGS */
    NS_T_WORD,
} nsMatchType;

static const struct {
    const char *name;
    nsMatchKey key;
    nsMatchType type;
} nsMatchKeys[] = {
    { "smac", NS_M_SMAC, NS_T_MAC },
    { "dmac", NS_M_DMAC, NS_T_MAC },
    { "etype", NS_M_ETYPE, NS_T_NUM },
    { "vlan-id", NS_M_VLAN_ID, NS_T_NUM },
    { "vlan-type", NS_M_VLAN_TYPE, NS_T_NUM },
    { "arp-htype", NS_M_ARP_HTYPE, NS_T_NUM },
    { "arp-ptype", NS_M_ARP_PTYPE, NS_T_NUM },
    { "arp-op", NS_M_ARP_OP, NS_T_NUM },
    { "arp-spa", NS_M_ARP_SPA, NS_T_IP },
    { "arp-tpa", NS_M_ARP_TPA, NS_T_IP },
    { "arp-sha", NS_M_ARP_SHA, NS_T_MAC },
    { "arp-tha", NS_M_ARP_THA, NS_T_MAC },
    { "arp-garp", NS_M_ARP_GARP, NS_T_NUM },
    { "src", NS_M_SRC, NS_T_IP },
    { "dst", NS_M_DST, NS_T_IP },
    { "proto", NS_M_PROTO, NS_T_NUM },
    { "sport", NS_M_SPORT, NS_T_NUM },
    { "dport", NS_M_DPORT, NS_T_NUM },
    { "dscp", NS_M_DSCP, NS_T_NUM },
    { "icmp-type", NS_M_ICMP_TYPE, NS_T_NUM },
    { "icmp-code", NS_M_ICMP_CODE, NS_T_NUM },
    { "l3", NS_M_L3, NS_T_WORD },
    { "l4", NS_M_L4, NS_T_WORD },
    { "tcp-flags", NS_M_TCP_FLAGS, NS_T_FLAGS },
    { "tcp-option", NS_M_TCP_OPTION, NS_T_NUM },
    { "connlimit", NS_M_CONNLIMIT, NS_T_NUM },
    { "ct-dir", NS_M_CT_DIR, NS_T_WORD },
    { "ct-state", NS_M_CT_STATE, NS_T_WORD },
    { "stp-type", NS_M_STP_TYPE, NS_T_NUM },
    { "stp-flags", NS_M_STP_FLAGS, NS_T_NUM },
    { "stp-root-prio", NS_M_STP_ROOT_PRIO, NS_T_NUM },
    { "stp-root-addr", NS_M_STP_ROOT_ADDR, NS_T_MAC },
    { "stp-root-cost", NS_M_STP_ROOT_COST, NS_T_NUM },
    { "stp-sender-prio", NS_M_STP_SENDER_PRIO, NS_T_NUM },
    { "stp-sender-addr", NS_M_STP_SENDER_ADDR, NS_T_MAC },
    { "stp-port", NS_M_STP_PORT, NS_T_NUM },
    { "stp-age", NS_M_STP_AGE, NS_T_NUM },
    { "stp-max-age", NS_M_STP_MAX_AGE, NS_T_NUM },
    { "stp-hello", NS_M_STP_HELLO, NS_T_NUM },
    { "stp-fwd-delay", NS_M_STP_FWD_DELAY, NS_T_NUM },
};

typedef struct {
    nsMatchKey key;
    bool neg;
    int alen;                   /* 6 (MAC), 4 or 16 (IP) */
    uint8_t a[16];
    uint8_t m[16];              /* mask */
    bool range;                 /* a..a2 */
    uint8_t a2[16];
    uint32_t lo, hi;
    int states;
} nsMatch;

typedef struct {
    nsMatch *m;
    size_t nm;
    nsRuleVerdict verdict;
    int jump;                   /* chain index */
    char *jumpName;
} nsRule;

typedef struct {
    char *name;
    GArray *rules;              /* nsRule */
} nsChain;

struct _nsFilter {
    GPtrArray *chains;          /* nsChain */
    int root[2][2];             /* [NS_ETH|NS_INET][NS_DIR_IN|NS_DIR_OUT] */
    bool ct;
    size_t nrules;
};


static uint16_t
nsRd16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}


/* ---------------------------------------------------------------------
 * Frames
 */

static void
nsPktParseL4(nsPkt *pk, uint8_t proto, const uint8_t *l4, size_t l4len)
{
    pk->l4proto = proto;
    pk->l4 = l4;
    pk->l4len = l4len;
    if (!l4)
        return;

    switch (proto) {
    case IPPROTO_TCP:
        if (l4len >= 20) {
            size_t doff = (l4[12] >> 4) * 4;

            pk->ports = true;
            pk->sport = nsRd16(l4);
            pk->dport = nsRd16(l4 + 2);
            pk->tcp = true;
            pk->tcpFlags = l4[13];
            if (doff > 20 && doff <= l4len) {
                pk->tcpOpts = l4 + 20;
                pk->tcpOptsLen = doff - 20;
            }
        }
        break;
    case IPPROTO_UDP:
    case 136:                   /* UDP-Lite */
    case 132:                   /* SCTP */
    case 33:                    /* DCCP */
        if (l4len >= 4) {
            pk->ports = true;
            pk->sport = nsRd16(l4);
            pk->dport = nsRd16(l4 + 2);
        }
        break;
    case IPPROTO_ICMP:
    case 58:                    /* ICMPv6 */
        if (l4len >= 4) {
            pk->icmp = true;
            pk->icmpType = l4[0];
            pk->icmpCode = l4[1];
            if (l4len >= 8)
                pk->icmpId = nsRd16(l4 + 4);
        }
        break;
    }
}


void
nsPktParse(nsPkt *pk, const uint8_t *frame, size_t len)
{
    const uint8_t *nh;
    size_t nhlen;

    memset(pk, 0, sizeof(*pk));
    pk->f = frame;
    pk->len = len;
    if (len < 14)
        return;
    pk->etype = nsRd16(frame + 12);
    nh = frame + 14;
    nhlen = len - 14;

    if (pk->etype == 0x8100 && nhlen >= 4) {
        pk->vlan = true;
        pk->vlanId = nsRd16(nh) & 0x0fff;
        pk->vlanType = nsRd16(nh + 2);
    }

    if ((pk->etype == 0x0806 || pk->etype == 0x8035) && nhlen >= 8) {
        pk->arp = true;
        pk->arpHtype = nsRd16(nh);
        pk->arpPtype = nsRd16(nh + 2);
        pk->arpOp = nsRd16(nh + 6);
        if (nh[4] == 6 && nh[5] == 4 && nhlen >= 28) {
            pk->arpSha = nh + 8;
            pk->arpSpa = nh + 14;
            pk->arpTha = nh + 18;
            pk->arpTpa = nh + 24;
        }
        return;
    }

    if (pk->etype == 0x0800 && nhlen >= 20 && (nh[0] >> 4) == 4) {
        size_t ihl = (nh[0] & 0x0f) * 4;
        size_t tot = nsRd16(nh + 2);

        if (ihl < 20 || ihl > nhlen)
            return;
        if (tot > nhlen || tot < ihl)
            tot = nhlen;
        pk->l3 = 4;
        memcpy(pk->src, nh + 12, 4);
        memcpy(pk->dst, nh + 16, 4);
        pk->ipProto = nh[9];
        pk->dscp = nh[1] >> 2;
        /* the transport header is in the first fragment only */
        if ((nsRd16(nh + 6) & 0x1fff) == 0)
            nsPktParseL4(pk, nh[9], nh + ihl, tot - ihl);
        else
            nsPktParseL4(pk, nh[9], NULL, 0);
        return;
    }

    if (pk->etype == 0x86dd && nhlen >= 40 && (nh[0] >> 4) == 6) {
        size_t pay = nsRd16(nh + 4);
        const uint8_t *p = nh + 40;
        size_t left;
        uint8_t next = nh[6];
        bool first = true;
        int hops;

        if (pay > nhlen - 40)
            pay = nhlen - 40;
        left = pay;
        pk->l3 = 6;
        memcpy(pk->src, nh + 8, 16);
        memcpy(pk->dst, nh + 24, 16);
        pk->ipProto = next;
        pk->dscp = ((nh[0] & 0x0f) << 2) | (nh[1] >> 6);

        /* the extension headers, to the transport one */
        for (hops = 0; hops < 8; hops++) {
            size_t hlen;

            if (next == 0 || next == 43 || next == 60) {
                if (left < 8)
                    break;
                hlen = (p[1] + 1) * 8;
            } else if (next == 44) {
                if (left < 8)
                    break;
                if (nsRd16(p + 2) & 0xfff8)
                    first = false;
                hlen = 8;
            } else if (next == 51) {
                if (left < 8)
                    break;
                hlen = (p[1] + 2) * 4;
            } else {
                break;
            }
            if (hlen > left)
                break;
            next = p[0];
            p += hlen;
            left -= hlen;
        }
        nsPktParseL4(pk, next, first ? p : NULL, first ? left : 0);
    }
}


/* ---------------------------------------------------------------------
 * Programs
 */

static void
nsRuleClear(void *data)
{
    nsRule *r = data;

    g_free(r->m);
    g_free(r->jumpName);
}


static void
nsChainFree(void *data)
{
    nsChain *c = data;

    g_free(c->name);
    g_array_unref(c->rules);
    g_free(c);
}


void
nsFilterFree(nsFilter *f)
{
    if (!f)
        return;
    g_ptr_array_unref(f->chains);
    g_free(f);
}


static int
nsFilterChain(nsFilter *f, const char *name)
{
    nsChain *c;
    size_t i;

    for (i = 0; i < f->chains->len; i++) {
        c = g_ptr_array_index(f->chains, i);
        if (strcmp(c->name, name) == 0)
            return i;
    }
    c = g_new0(nsChain, 1);
    c->name = g_strdup(name);
    c->rules = g_array_new(FALSE, TRUE, sizeof(nsRule));
    g_array_set_clear_func(c->rules, nsRuleClear);
    g_ptr_array_add(f->chains, c);
    return f->chains->len - 1;
}


static bool
nsParseMac(const char *s, uint8_t *mac)
{
    unsigned int b[6];
    char tail;
    size_t i;

    if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return false;
    for (i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return false;
        mac[i] = b[i];
    }
    return true;
}


static bool
nsParseIP(const char *s, uint8_t *a, int *alen)
{
    if (strchr(s, ':')) {
        if (inet_pton(AF_INET6, s, a) != 1)
            return false;
        *alen = 16;
    } else {
        if (inet_pton(AF_INET, s, a) != 1)
            return false;
        *alen = 4;
    }
    return true;
}


static bool
nsParseNum(const char *s, uint32_t *v)
{
    char *end;
    unsigned long long n;

    if (!*s)
        return false;
    n = strtoull(s, &end, 0);
    if (*end || n > 0xffffffffULL)
        return false;
    *v = n;
    return true;
}


static void
nsPrefixMask(uint8_t *m, int alen, unsigned int bits)
{
    int i;

    for (i = 0; i < alen; i++) {
        if (bits >= 8) {
            m[i] = 0xff;
            bits -= 8;
        } else {
            m[i] = (0xff << (8 - bits)) & 0xff;
            bits = 0;
        }
    }
}


static bool
nsParseMatch(nsMatch *m, const char *key, const char *value)
{
    g_autofree char *v = NULL;
    char *sep;
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(nsMatchKeys); i++) {
        if (strcmp(nsMatchKeys[i].name, key) == 0)
            break;
    }
    if (i == G_N_ELEMENTS(nsMatchKeys))
        return false;

    memset(m, 0, sizeof(*m));
    m->key = nsMatchKeys[i].key;
    if (*value == '!') {
        m->neg = true;
        value++;
    }
    v = g_strdup(value);

    switch (nsMatchKeys[i].type) {
    case NS_T_MAC:
        m->alen = 6;
        memset(m->m, 0xff, 6);
        if ((sep = strchr(v, '/'))) {
            *sep++ = '\0';
            if (!nsParseMac(sep, m->m))
                return false;
        }
        return nsParseMac(v, m->a);

    case NS_T_IP: {
        uint32_t bits;

        if ((sep = strchr(v, '-'))) {
            int alen2;

            *sep++ = '\0';
            m->range = true;
            return nsParseIP(v, m->a, &m->alen) &&
                nsParseIP(sep, m->a2, &alen2) && alen2 == m->alen;
        }
        if ((sep = strchr(v, '/')))
            *sep++ = '\0';
        if (!nsParseIP(v, m->a, &m->alen))
            return false;
        if (!sep) {
            bits = m->alen * 8;
        } else if (strchr(sep, '.')) {
            /* a dotted mask */
            int mlen;

            if (!nsParseIP(sep, m->m, &mlen) || mlen != m->alen)
                return false;
            return true;
        } else if (!nsParseNum(sep, &bits) || bits > (uint32_t)m->alen * 8) {
            return false;
        }
        nsPrefixMask(m->m, m->alen, bits);
        return true;
    }

    case NS_T_NUM:
        if ((sep = strchr(v + 1, '-'))) {
            *sep++ = '\0';
            return nsParseNum(v, &m->lo) && nsParseNum(sep, &m->hi);
        }
        if (!nsParseNum(v, &m->lo))
            return false;
        m->hi = m->lo;
        return true;

    case NS_T_FLAGS:
        if (!(sep = strchr(v, '/')))
            return false;
        *sep++ = '\0';
        return nsParseNum(v, &m->lo) && nsParseNum(sep, &m->hi);

    case NS_T_WORD:
        if (m->key == NS_M_L3) {
            if (strcmp(v, "ip") == 0)
                m->lo = 4;
            else if (strcmp(v, "ip6") == 0)
                m->lo = 6;
            else
                return false;
        } else if (m->key == NS_M_L4) {
            static const struct { const char *n; uint32_t p; } l4[] = {
                { "tcp", 6 }, { "udp", 17 }, { "udplite", 136 }, { "esp", 50 },
                { "ah", 51 }, { "sctp", 132 }, { "icmp", 1 }, { "icmpv6", 58 },
                { "igmp", 2 },
            };
            size_t j;

            for (j = 0; j < G_N_ELEMENTS(l4); j++) {
                if (strcmp(v, l4[j].n) == 0)
                    break;
            }
            if (j == G_N_ELEMENTS(l4))
                return false;
            m->lo = l4[j].p;
        } else if (m->key == NS_M_CT_DIR) {
            if (strcmp(v, "original") == 0)
                m->lo = 0;
            else if (strcmp(v, "reply") == 0)
                m->lo = 1;
            else
                return false;
        } else if (m->key == NS_M_CT_STATE) {
            g_auto(GStrv) states = g_strsplit(v, ",", 0);
            size_t j;

            for (j = 0; states[j]; j++) {
                if (strcmp(states[j], "new") == 0)
                    m->states |= NS_CT_NEW;
                else if (strcmp(states[j], "established") == 0)
                    m->states |= NS_CT_ESTABLISHED;
                else if (strcmp(states[j], "related") == 0)
                    m->states |= NS_CT_RELATED;
                else if (strcmp(states[j], "invalid") == 0)
                    m->states |= NS_CT_INVALID;
                else if (*states[j])
                    return false;
            }
        }
        return true;
    }
    return false;
}


static void
nsFilterRootChains(nsFilter *f)
{
    static const char *names[2][2] = {
        { "eth-in", "eth-out" },
        { "inet-in", "inet-out" },
    };
    size_t t, d, i;

    for (t = 0; t < 2; t++) {
        for (d = 0; d < 2; d++) {
            f->root[t][d] = -1;
            for (i = 0; i < f->chains->len; i++) {
                nsChain *c = g_ptr_array_index(f->chains, i);

                if (strcmp(c->name, names[t][d]) == 0)
                    f->root[t][d] = i;
            }
        }
    }
}


nsFilter *
nsFilterLoad(const char *path, char **error)
{
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    g_autoptr(GError) err = NULL;
    nsFilter *f;
    size_t i, j;

    *error = NULL;
    if (!g_file_get_contents(path, &text, NULL, &err)) {
        if (!g_error_matches(err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            *error = g_strdup(err->message);
        return NULL;
    }

    f = g_new0(nsFilter, 1);
    f->chains = g_ptr_array_new_with_free_func(nsChainFree);
    lines = g_strsplit(text, "\n", 0);

    for (i = 0; lines[i]; i++) {
        g_auto(GStrv) tok = NULL;
        nsRule r = { 0 };
        nsChain *c;
        int ci;

        g_strstrip(lines[i]);
        if (!*lines[i] || *lines[i] == '#')
            continue;
        tok = g_strsplit_set(lines[i], " \t", 0);
        if (g_strv_length(tok) < 3 || strcmp(tok[0], "rule") != 0)
            goto syntax;

        ci = nsFilterChain(f, tok[1]);

        if (strcmp(tok[2], "accept") == 0)
            r.verdict = NS_V_ACCEPT;
        else if (strcmp(tok[2], "drop") == 0)
            r.verdict = NS_V_DROP;
        else if (strcmp(tok[2], "reject") == 0)
            r.verdict = NS_V_REJECT;
        else if (strcmp(tok[2], "return") == 0)
            r.verdict = NS_V_RETURN;
        else if (strcmp(tok[2], "continue") == 0)
            r.verdict = NS_V_CONTINUE;
        else if (g_str_has_prefix(tok[2], "jump:"))
            r.verdict = NS_V_JUMP;
        else
            goto syntax;
        if (r.verdict == NS_V_JUMP)
            r.jumpName = g_strdup(tok[2] + 5);

        r.m = g_new0(nsMatch, g_strv_length(tok));
        for (j = 3; tok[j]; j++) {
            char *eq;

            if (!*tok[j])
                continue;
            if (!(eq = strchr(tok[j], '='))) {
                nsRuleClear(&r);
                goto syntax;
            }
            *eq = '\0';
            if (!nsParseMatch(&r.m[r.nm], tok[j], eq + 1)) {
                *eq = '=';
                *error = g_strdup_printf("line %zu: invalid match '%s'", i + 1, tok[j]);
                nsRuleClear(&r);
                nsFilterFree(f);
                return NULL;
            }
            if (r.m[r.nm].key == NS_M_CT_DIR || r.m[r.nm].key == NS_M_CT_STATE ||
                r.m[r.nm].key == NS_M_CONNLIMIT)
                f->ct = true;
            r.nm++;
        }

        c = g_ptr_array_index(f->chains, ci);
        g_array_append_val(c->rules, r);
        f->nrules++;
        continue;

     syntax:
        *error = g_strdup_printf("line %zu: syntax error", i + 1);
        nsFilterFree(f);
        return NULL;
    }

    /* the targets of the jumps */
    for (i = 0; i < f->chains->len; i++) {
        nsChain *c = g_ptr_array_index(f->chains, i);

        for (j = 0; j < c->rules->len; j++) {
            nsRule *r = &g_array_index(c->rules, nsRule, j);

            if (r->verdict == NS_V_JUMP)
                r->jump = nsFilterChain(f, r->jumpName);
        }
    }
    nsFilterRootChains(f);
    return f;
}


/* a filter that drops everything, both ways */
nsFilter *
nsFilterDropAll(void)
{
    nsFilter *f = g_new0(nsFilter, 1);
    const char *chains[] = { "eth-in", "eth-out" };
    size_t i;

    f->chains = g_ptr_array_new_with_free_func(nsChainFree);
    for (i = 0; i < G_N_ELEMENTS(chains); i++) {
        nsRule r = { .verdict = NS_V_DROP };
        nsChain *c = g_ptr_array_index(f->chains, nsFilterChain(f, chains[i]));

        g_array_append_val(c->rules, r);
        f->nrules++;
    }
    nsFilterRootChains(f);
    return f;
}


bool
nsFilterUsesConntrack(const nsFilter *f)
{
    return f && f->ct;
}


size_t
nsFilterRuleCount(const nsFilter *f)
{
    return f ? f->nrules : 0;
}


/* ---------------------------------------------------------------------
 * Connection tracking, as netfilter's
 */

typedef struct {
    uint8_t l3;
    uint8_t proto;
    uint16_t sport;
    uint16_t dport;
    uint8_t src[16];
    uint8_t dst[16];
} nsCtKey;

struct _nsCtEntry {
    nsCtKey key;                /* the original direction */
    bool replied;
    bool finOrig, finReply, reset;
    gint64 expires;             /* ms */
};

struct _nsConntrack {
    GHashTable *table;          /* nsCtKey -> nsCtEntry */
    gint64 lastExpire;
};


static guint
nsCtHash(const void *k)
{
    const uint8_t *p = k;
    guint h = 2166136261u;
    size_t i;

    for (i = 0; i < sizeof(nsCtKey); i++)
        h = (h ^ p[i]) * 16777619u;
    return h;
}


static gboolean
nsCtEqual(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(nsCtKey)) == 0;
}


nsConntrack *
nsConntrackNew(void)
{
    nsConntrack *ct = g_new0(nsConntrack, 1);

    ct->table = g_hash_table_new_full(nsCtHash, nsCtEqual, NULL, g_free);
    return ct;
}


void
nsConntrackFree(nsConntrack *ct)
{
    if (!ct)
        return;
    g_hash_table_unref(ct->table);
    g_free(ct);
}


static gint64
nsCtNow(void)
{
    return g_get_monotonic_time() / 1000;
}


static bool
nsIcmpIsError(int l3, uint8_t type)
{
    if (l3 == 4)
        return type == 3 || type == 4 || type == 5 || type == 11 || type == 12;
    return type >= 1 && type <= 4;
}


static bool
nsIcmpIsQuery(int l3, uint8_t type, bool *reply)
{
    *reply = false;
    if (l3 == 4) {
        switch (type) {
        case 8: case 13: case 15: case 17:
            return true;
        case 0: case 14: case 16: case 18:
            *reply = true;
            return true;
        }
        return false;
    }
    if (type == 128)
        return true;
    if (type == 129) {
        *reply = true;
        return true;
    }
    return false;
}


/* the tuple of @pk, false when it is not tracked */
static bool
nsCtKeyOf(const nsPkt *pk, nsCtKey *key)
{
    bool reply;

    memset(key, 0, sizeof(*key));
    if (!pk->l3)
        return false;
    key->l3 = pk->l3;
    key->proto = pk->l4proto;
    memcpy(key->src, pk->src, pk->l3 == 4 ? 4 : 16);
    memcpy(key->dst, pk->dst, pk->l3 == 4 ? 4 : 16);
    if (pk->ports) {
        key->sport = pk->sport;
        key->dport = pk->dport;
    } else if (pk->icmp) {
        if (!nsIcmpIsQuery(pk->l3, pk->icmpType, &reply))
            return false;
        key->sport = key->dport = pk->icmpId;
    } else if (pk->l4proto == IPPROTO_TCP || pk->l4proto == IPPROTO_UDP) {
        /* a fragment */
        return false;
    }
    return true;
}


static void
nsCtReverse(const nsCtKey *k, nsCtKey *r)
{
    *r = *k;
    memcpy(r->src, k->dst, 16);
    memcpy(r->dst, k->src, 16);
    r->sport = k->dport;
    r->dport = k->sport;
}


void
nsConntrackLookup(nsConntrack *ct, nsPkt *pk)
{
    nsCtKey key;
    nsCtKey rev;
    nsCtEntry *e;
    gint64 now = nsCtNow();

    pk->ctTracked = false;
    pk->ctState = 0;
    pk->ctEntry = NULL;
    pk->ctReply = false;
    pk->ctRelated = false;
    if (!pk->l3)
        return;

    /* an ICMP error about a tracked connection is related to it */
    if (pk->icmp && nsIcmpIsError(pk->l3, pk->icmpType) && pk->l4 && pk->l4len > 8) {
        nsPkt inner;
        g_autofree uint8_t *buf = NULL;
        size_t ilen = pk->l4len - 8;

        /* the packet in the error, as a frame to parse */
        buf = g_malloc(14 + ilen);
        memset(buf, 0, 12);
        buf[12] = pk->l3 == 4 ? 0x08 : 0x86;
        buf[13] = pk->l3 == 4 ? 0x00 : 0xdd;
        memcpy(buf + 14, pk->l4 + 8, ilen);
        nsPktParse(&inner, buf, 14 + ilen);
        if (inner.l3 == pk->l3 && nsCtKeyOf(&inner, &key)) {
            nsCtReverse(&key, &rev);
            if (((e = g_hash_table_lookup(ct->table, &key)) && e->expires > now) ||
                ((e = g_hash_table_lookup(ct->table, &rev)) && e->expires > now)) {
                pk->ctTracked = true;
                pk->ctRelated = true;
                pk->ctState = NS_CT_RELATED;
                pk->ctReply = memcmp(e->key.src, pk->src, 16) != 0;
                return;
            }
        }
        pk->ctTracked = true;
        pk->ctState = NS_CT_INVALID;
        return;
    }

    if (!nsCtKeyOf(pk, &key)) {
        /* not tracked by netfilter as a connection either */
        pk->ctTracked = true;
        pk->ctState = NS_CT_NEW;
        return;
    }
    pk->ctTracked = true;
    nsCtReverse(&key, &rev);

    if ((e = g_hash_table_lookup(ct->table, &key)) && e->expires > now) {
        pk->ctEntry = e;
        pk->ctState = e->replied ? NS_CT_ESTABLISHED : NS_CT_NEW;
    } else if ((e = g_hash_table_lookup(ct->table, &rev)) && e->expires > now) {
        pk->ctEntry = e;
        pk->ctReply = true;
        pk->ctState = NS_CT_ESTABLISHED;
    } else {
        /* netfilter takes up TCP connections in the middle too */
        pk->ctState = NS_CT_NEW;
    }
}


void
nsConntrackConfirm(nsConntrack *ct, nsPkt *pk)
{
    nsCtEntry *e = pk->ctEntry;
    gint64 now = nsCtNow();
    gint64 timeout;
    nsCtKey key;

    if (!pk->ctTracked || pk->ctRelated || pk->ctState == NS_CT_INVALID)
        return;

    if (!e) {
        if (!nsCtKeyOf(pk, &key))
            return;
        /* an expired entry of the same tuple is replaced */
        e = g_new0(nsCtEntry, 1);
        e->key = key;
        g_hash_table_replace(ct->table, &e->key, e);
        pk->ctEntry = e;
    } else if (pk->ctReply) {
        e->replied = true;
    }

    if (pk->tcp) {
        if (pk->tcpFlags & 0x04)
            e->reset = true;
        if (pk->tcpFlags & 0x01) {
            if (pk->ctReply)
                e->finReply = true;
            else
                e->finOrig = true;
        }
        if (e->reset)
            timeout = 10 * 1000;
        else if (e->finOrig && e->finReply)
            timeout = 120 * 1000;
        else if (e->replied)
            timeout = 5LL * 24 * 3600 * 1000;
        else
            timeout = 120 * 1000;
    } else if (pk->l4proto == IPPROTO_UDP || pk->l4proto == 136) {
        timeout = e->replied ? 120 * 1000 : 30 * 1000;
    } else if (pk->icmp) {
        timeout = 30 * 1000;
    } else {
        timeout = 600 * 1000;
    }
    e->expires = now + timeout;
}


void
nsConntrackExpire(nsConntrack *ct)
{
    GHashTableIter iter;
    nsCtEntry *e;
    gint64 now = nsCtNow();

    if (now - ct->lastExpire < 5000)
        return;
    ct->lastExpire = now;
    g_hash_table_iter_init(&iter, ct->table);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&e)) {
        if (e->expires <= now)
            g_hash_table_iter_remove(&iter);
    }
}


/* ct count: the connections the source of @pk opened */
static uint32_t
nsConntrackCount(nsConntrack *ct, const nsPkt *pk)
{
    GHashTableIter iter;
    nsCtEntry *e;
    gint64 now = nsCtNow();
    uint32_t n = 0;

    if (!ct || !pk->l3)
        return 0;
    g_hash_table_iter_init(&iter, ct->table);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&e)) {
        if (e->expires > now && e->key.l3 == pk->l3 &&
            memcmp(e->key.src, pk->src, 16) == 0 &&
            !(e->finOrig && e->finReply) && !e->reset)
            n++;
    }
    return n;
}


/* ---------------------------------------------------------------------
 * Running a program
 */

static bool
nsMaskEqual(const uint8_t *v, const uint8_t *a, const uint8_t *m, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if ((v[i] & m[i]) != (a[i] & m[i]))
            return false;
    }
    return true;
}


static bool
nsAddrMatch(const nsMatch *m, const uint8_t *v)
{
    if (m->range)
        return memcmp(v, m->a, m->alen) >= 0 && memcmp(v, m->a2, m->alen) <= 0;
    return nsMaskEqual(v, m->a, m->m, m->alen);
}


static bool
nsNumMatch(const nsMatch *m, uint32_t v)
{
    return v >= m->lo && v <= m->hi;
}


/* the field of a BPDU at @off of the network header, @len bytes */
static bool
nsStpField(const nsPkt *pk, size_t off, size_t len, uint32_t *v)
{
    size_t i;

    if (pk->len < 14 + off + len)
        return false;
    *v = 0;
    for (i = 0; i < len; i++)
        *v = (*v << 8) | pk->f[14 + off + i];
    return true;
}


static bool
nsTcpHasOption(const nsPkt *pk, uint32_t kind)
{
    size_t i = 0;

    while (i < pk->tcpOptsLen) {
        uint8_t k = pk->tcpOpts[i];

        if (k == kind)
            return true;
        if (k == 0)
            break;
        if (k == 1) {
            i++;
            continue;
        }
        if (i + 1 >= pk->tcpOptsLen || pk->tcpOpts[i + 1] < 2)
            break;
        i += pk->tcpOpts[i + 1];
    }
    return false;
}


/* -1 when the frame has not the header of the match: the rule does not
 * match, negated or not, as nftables adds the dependency on the protocol */
static int
nsMatchOne(const nsMatch *m, const nsPkt *pk, nsConntrack *ct)
{
    uint32_t v;

    switch (m->key) {
    case NS_M_SMAC:
        return nsMaskEqual(pk->f + 6, m->a, m->m, 6);
    case NS_M_DMAC:
        return nsMaskEqual(pk->f, m->a, m->m, 6);
    case NS_M_ETYPE:
        return nsNumMatch(m, pk->etype);
    case NS_M_VLAN_ID:
        return pk->vlan ? nsNumMatch(m, pk->vlanId) : -1;
    case NS_M_VLAN_TYPE:
        return pk->vlan ? nsNumMatch(m, pk->vlanType) : -1;
    case NS_M_ARP_HTYPE:
        return pk->arp ? nsNumMatch(m, pk->arpHtype) : -1;
    case NS_M_ARP_PTYPE:
        return pk->arp ? nsNumMatch(m, pk->arpPtype) : -1;
    case NS_M_ARP_OP:
        return pk->arp ? nsNumMatch(m, pk->arpOp) : -1;
    case NS_M_ARP_SPA:
        return pk->arpSpa && m->alen == 4 ? nsAddrMatch(m, pk->arpSpa) : -1;
    case NS_M_ARP_TPA:
        return pk->arpTpa && m->alen == 4 ? nsAddrMatch(m, pk->arpTpa) : -1;
    case NS_M_ARP_SHA:
        return pk->arpSha ? nsMaskEqual(pk->arpSha, m->a, m->m, 6) : -1;
    case NS_M_ARP_THA:
        return pk->arpTha ? nsMaskEqual(pk->arpTha, m->a, m->m, 6) : -1;
    case NS_M_ARP_GARP:
        return pk->arpSpa ? memcmp(pk->arpSpa, pk->arpTpa, 4) == 0 : -1;
    case NS_M_SRC:
        if (!pk->l3 || m->alen != (pk->l3 == 4 ? 4 : 16))
            return -1;
        return nsAddrMatch(m, pk->src);
    case NS_M_DST:
        if (!pk->l3 || m->alen != (pk->l3 == 4 ? 4 : 16))
            return -1;
        return nsAddrMatch(m, pk->dst);
    case NS_M_PROTO:
        return pk->l3 ? nsNumMatch(m, pk->ipProto) : -1;
    case NS_M_SPORT:
        return pk->ports ? nsNumMatch(m, pk->sport) : -1;
    case NS_M_DPORT:
        return pk->ports ? nsNumMatch(m, pk->dport) : -1;
    case NS_M_DSCP:
        return pk->l3 ? nsNumMatch(m, pk->dscp) : -1;
    case NS_M_ICMP_TYPE:
        return pk->icmp ? nsNumMatch(m, pk->icmpType) : -1;
    case NS_M_ICMP_CODE:
        return pk->icmp ? nsNumMatch(m, pk->icmpCode) : -1;
    case NS_M_L3:
        return pk->l3 == (int)m->lo;
    case NS_M_L4:
        return pk->l3 ? pk->l4proto == m->lo : -1;
    case NS_M_TCP_FLAGS:
        return pk->tcp ? (pk->tcpFlags & m->lo) == m->hi : -1;
    case NS_M_TCP_OPTION:
        return pk->tcp ? nsTcpHasOption(pk, m->lo) : -1;
    case NS_M_CONNLIMIT:
        return pk->ctTracked ? nsConntrackCount(ct, pk) > m->lo : -1;
    case NS_M_CT_DIR:
        return pk->ctTracked ? pk->ctReply == (m->lo == 1) : -1;
    case NS_M_CT_STATE:
        return pk->ctTracked ? (pk->ctState & m->states) != 0 : -1;
    case NS_M_STP_TYPE:
        return nsStpField(pk, 6, 1, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_FLAGS:
        return nsStpField(pk, 7, 1, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_ROOT_PRIO:
        return nsStpField(pk, 8, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_ROOT_ADDR:
        return pk->len >= 14 + 16 ? nsMaskEqual(pk->f + 14 + 10, m->a, m->m, 6) : -1;
    case NS_M_STP_ROOT_COST:
        return nsStpField(pk, 16, 4, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_SENDER_PRIO:
        return nsStpField(pk, 20, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_SENDER_ADDR:
        return pk->len >= 14 + 28 ? nsMaskEqual(pk->f + 14 + 22, m->a, m->m, 6) : -1;
    case NS_M_STP_PORT:
        return nsStpField(pk, 28, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_AGE:
        return nsStpField(pk, 30, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_MAX_AGE:
        return nsStpField(pk, 32, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_HELLO:
        return nsStpField(pk, 34, 2, &v) ? nsNumMatch(m, v) : -1;
    case NS_M_STP_FWD_DELAY:
        return nsStpField(pk, 36, 2, &v) ? nsNumMatch(m, v) : -1;
    }
    return -1;
}


static bool
nsRuleMatches(const nsRule *r, const nsPkt *pk, nsConntrack *ct)
{
    size_t i;

    for (i = 0; i < r->nm; i++) {
        int rc = nsMatchOne(&r->m[i], pk, ct);

        if (rc < 0)
            return false;
        if (!!rc == r->m[i].neg)
            return false;
    }
    return true;
}


static nsRuleVerdict
nsChainRun(const nsFilter *f, int ci, const nsPkt *pk, nsConntrack *ct, int depth)
{
    nsChain *c = g_ptr_array_index(f->chains, ci);
    size_t i;

    for (i = 0; i < c->rules->len; i++) {
        const nsRule *r = &g_array_index(c->rules, nsRule, i);
        nsRuleVerdict v;

        if (!nsRuleMatches(r, pk, ct))
            continue;
        switch (r->verdict) {
        case NS_V_ACCEPT:
        case NS_V_DROP:
        case NS_V_REJECT:
        case NS_V_RETURN:
            return r->verdict;
        case NS_V_JUMP:
            if (depth >= NS_MAX_DEPTH)
                return NS_V_DROP;
            v = nsChainRun(f, r->jump, pk, ct, depth + 1);
            if (v == NS_V_ACCEPT || v == NS_V_DROP || v == NS_V_REJECT)
                return v;
            break;
        case NS_V_CONTINUE:
        case NS_V_NONE:
            break;
        }
    }
    return NS_V_NONE;
}


nsFilterVerdict
nsFilterRun(const nsFilter *f, bool toGuest, const nsPkt *pk, nsConntrack *ct)
{
    int dir = toGuest ? NS_DIR_IN : NS_DIR_OUT;
    int t;

    if (!f || pk->len < 14)
        return NS_FILTER_ACCEPT;

    /* the ethernet table, then the inet table: accept ends a table only */
    for (t = NS_ETH; t <= NS_INET; t++) {
        int root = f->root[t][dir];

        if (root < 0)
            continue;
        nsRuleVerdict v = nsChainRun(f, root, pk, ct, 0);

        if (v == NS_V_DROP)
            return NS_FILTER_DROP;
        if (v == NS_V_REJECT)
            return NS_FILTER_REJECT;
    }
    return NS_FILTER_ACCEPT;
}


/* ---------------------------------------------------------------------
 * reject: an ICMP port unreachable to the sender, as iptables' REJECT
 */

static uint32_t
nsSum(uint32_t sum, const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (p[i] << 8) | p[i + 1];
    if (len & 1)
        sum += p[len - 1] << 8;
    return sum;
}


static uint16_t
nsFold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
}


size_t
nsFilterRejectFrame(const nsPkt *pk, uint8_t *out, size_t outsize)
{
    const uint8_t *ip = pk->f + 14;
    size_t iplen = pk->len - 14;
    uint8_t *o;
    size_t quote;
    size_t total;
    uint16_t sum;

    /* not for ICMP errors, nor broadcasts */
    if (!pk->l3 || (pk->icmp && nsIcmpIsError(pk->l3, pk->icmpType)) || (pk->f[0] & 1))
        return 0;

    memcpy(out, pk->f + 6, 6);
    memcpy(out + 6, pk->f, 6);

    if (pk->l3 == 4) {
        size_t ihl = (ip[0] & 0x0f) * 4;

        quote = MIN(iplen, ihl + 8);
        total = 14 + 20 + 8 + quote;
        if (total > outsize)
            return 0;
        out[12] = 0x08;
        out[13] = 0x00;
        o = out + 14;
        memset(o, 0, 28);
        o[0] = 0x45;
        o[2] = (20 + 8 + quote) >> 8;
        o[3] = (20 + 8 + quote) & 0xff;
        o[8] = 64;
        o[9] = IPPROTO_ICMP;
        memcpy(o + 12, pk->dst, 4);
        memcpy(o + 16, pk->src, 4);
        sum = nsFold(nsSum(0, o, 20));
        o[10] = sum >> 8;
        o[11] = sum & 0xff;
        o += 20;
        o[0] = 3;               /* destination unreachable */
        o[1] = 3;               /* port unreachable */
        memcpy(o + 8, ip, quote);
        sum = nsFold(nsSum(0, o, 8 + quote));
        o[2] = sum >> 8;
        o[3] = sum & 0xff;
        return total;
    } else {
        uint32_t psum = 0;
        uint8_t ph[8] = { 0 };

        quote = MIN(iplen, 1280 - 40 - 8);
        total = 14 + 40 + 8 + quote;
        if (total > outsize)
            return 0;
        out[12] = 0x86;
        out[13] = 0xdd;
        o = out + 14;
        memset(o, 0, 48);
        o[0] = 0x60;
        o[4] = (8 + quote) >> 8;
        o[5] = (8 + quote) & 0xff;
        o[6] = 58;
        o[7] = 64;
        memcpy(o + 8, pk->dst, 16);
        memcpy(o + 24, pk->src, 16);
        o += 40;
        o[0] = 1;               /* destination unreachable */
        o[1] = 4;               /* port unreachable */
        memcpy(o + 8, ip, quote);
        psum = nsSum(psum, pk->dst, 16);
        psum = nsSum(psum, pk->src, 16);
        ph[2] = (8 + quote) >> 8;
        ph[3] = (8 + quote) & 0xff;
        ph[7] = 58;
        psum = nsSum(psum, ph, 8);
        sum = nsFold(nsSum(psum, o, 8 + quote));
        o[2] = sum >> 8;
        o[3] = sum & 0xff;
        return total;
    }
}
