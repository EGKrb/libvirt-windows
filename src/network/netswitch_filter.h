/*
 * netswitch_filter.h: the network filters (nwfilter) of the ports of a
 * libvirt_netswitch switch
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glib.h>

/* ct state */
#define NS_CT_NEW          (1 << 0)
#define NS_CT_ESTABLISHED  (1 << 1)
#define NS_CT_RELATED      (1 << 2)
#define NS_CT_INVALID      (1 << 3)

typedef struct _nsCtEntry nsCtEntry;

/* what the filters look at in a frame */
typedef struct _nsPkt nsPkt;
struct _nsPkt {
    const uint8_t *f;
    size_t len;
    uint16_t etype;             /* the ether type of the frame */

    bool vlan;
    uint16_t vlanId;
    uint16_t vlanType;          /* the ether type in the 802.1Q header */

    bool arp;                   /* ARP or RARP */
    uint16_t arpHtype, arpPtype, arpOp;
    const uint8_t *arpSha, *arpSpa, *arpTha, *arpTpa;   /* Ethernet/IPv4 */

    int l3;                     /* 4, 6, or 0 without IP */
    uint8_t src[16], dst[16];
    uint8_t ipProto;            /* IPv4 protocol, IPv6 first next header */
    uint8_t l4proto;            /* after the IPv6 extension headers */
    uint8_t dscp;
    const uint8_t *l4;          /* NULL for a fragment that is not the first */
    size_t l4len;
    bool ports;
    uint16_t sport, dport;
    bool icmp;
    uint8_t icmpType, icmpCode;
    uint16_t icmpId;
    bool tcp;
    uint8_t tcpFlags;
    const uint8_t *tcpOpts;
    size_t tcpOptsLen;

    /* connection tracking */
    bool ctTracked;
    int ctState;
    bool ctReply;
    nsCtEntry *ctEntry;
    bool ctRelated;
};

typedef enum {
    NS_FILTER_ACCEPT,
    NS_FILTER_DROP,
    NS_FILTER_REJECT,
} nsFilterVerdict;

typedef struct _nsFilter nsFilter;
typedef struct _nsConntrack nsConntrack;

void nsPktParse(nsPkt *pk, const uint8_t *frame, size_t len);

nsFilter *nsFilterLoad(const char *path, char **error);
nsFilter *nsFilterDropAll(void);
void nsFilterFree(nsFilter *f);
bool nsFilterUsesConntrack(const nsFilter *f);
size_t nsFilterRuleCount(const nsFilter *f);
nsFilterVerdict nsFilterRun(const nsFilter *f, bool toGuest,
                            const nsPkt *pk, nsConntrack *ct);

nsConntrack *nsConntrackNew(void);
void nsConntrackFree(nsConntrack *ct);
void nsConntrackLookup(nsConntrack *ct, nsPkt *pk);
void nsConntrackConfirm(nsConntrack *ct, nsPkt *pk);
void nsConntrackExpire(nsConntrack *ct);

size_t nsFilterRejectFrame(const nsPkt *pk, uint8_t *out, size_t outsize);
