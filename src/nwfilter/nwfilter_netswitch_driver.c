/*
 * nwfilter_netswitch_driver.c: network filters applied by the switch of a
 * libvirt network on Windows (libvirt_netswitch)
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * On Linux, the filters of an interface become ebtables/iptables or
 * nftables rules on its TAP device in the bridge.  On Windows a guest of a
 * libvirt network is a port of the network's switch, libvirt_netswitch,
 * which plays the bridge: the rules of the interface are compiled into a
 * program the switch runs on each frame to or from that port.
 *
 * The program follows the layout of the nftables driver:
 *
 *   - an ethernet table: the chains eth-in (frames to the guest) and
 *     eth-out (frames from the guest), whose rules are the root rules of
 *     the ethernet protocols and, at their priority, jumps to the sub
 *     chains (eth-in-arp...) taken by the frames of their protocol;
 *   - an inet table: the chains inet-in and inet-out, with the rules of the
 *     IP protocols (tcp, udp, icmp, all...) in priority order, and the
 *     connection tracking of nftables (ct state, ct direction, the reverse
 *     rules accepting the replies, ct count).
 *
 * A frame passes the ethernet table, then the inet table, of the port it
 * comes from, then of the port it goes to; accept ends a table, drop and
 * reject end the frame, return goes back to the calling chain, and a frame
 * that reaches the end of a root chain is accepted, as with the accept
 * policy of the base chains of nftables.
 *
 * One rule per line, its chain, its verdict and its matches:
 *
 *   rule eth-out-mac drop smac=!52:54:00:12:34:56
 *   rule eth-out jump:eth-out-arp etype=0x0806
 *   rule inet-in accept l3=ip l4=tcp dport=22 ct-dir=original ct-state=new,established
 *
 * The program of the interface vnet0 is RUNSTATEDIR/libvirt/network/
 * nwfilter/vnet0; the switch of the network of the port (its port file)
 * reads it again when notified.
 */

#include <config.h>

#include "internal.h"

#include "virbuffer.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "virnetdevbridge.h"
#include "nwfilter_conf.h"
#include "nwfilter_netswitch_driver.h"
#include "nwfilter_tech_driver.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_netswitch_driver");

typedef struct {
    GString *prog;
    const char *ifname;
} nsProgram;


static char *
nsFilterDir(void)
{
    return g_strdup_printf("%s/nwfilter",
                           VIR_INSTALL_PATH(RUNSTATEDIR "/libvirt/network"));
}


static char *
nsFilterPath(const char *ifname, const char *suffix)
{
    g_autofree char *dir = nsFilterDir();

    return g_strdup_printf("%s/%s%s", dir, ifname, suffix ? suffix : "");
}


/* the switch of the port: it reads the programs again */
static void
nsNotify(const char *ifname)
{
    g_autofree char *brname = NULL;
    virMacAddr mac;

    if (virNetDevBridgeSwitchPortGet(ifname, &brname, &mac) < 0) {
        virResetLastError();
        return;
    }
    virNetDevBridgeSwitchNotify(brname);
}


static int
nsWriteProgram(const char *ifname, const char *suffix, const char *text)
{
    g_autofree char *dir = nsFilterDir();
    g_autofree char *path = nsFilterPath(ifname, suffix);

    if (g_mkdir_with_parents(dir, 0777) < 0) {
        virReportSystemError(errno, _("cannot create directory %1$s"), dir);
        return -1;
    }
    if (virFileRewriteStr(path, 0644, text) < 0)
        return -1;
    return 0;
}


/* key=value, value prefixed with ! when the item is negated */
static int
nsAddItem(GString *line,
          virNWFilterVarCombIter *vars,
          const char *key,
          nwItemDesc *item,
          bool hex)
{
    char buf[INET6_ADDRSTRLEN + 8];

    if (!HAS_ENTRY_ITEM(item))
        return 0;
    if ((hex ? virNWFilterPrintDataTypeAsHex(vars, buf, sizeof(buf), item) :
               virNWFilterPrintDataType(vars, buf, sizeof(buf), item)) < 0)
        return -1;
    g_string_append_printf(line, " %s=%s%s", key,
                           ENTRY_WANT_NEG_SIGN(item) ? "!" : "", buf);
    return 0;
}


/* key=[!]ADDR/MASK, with @defmask without a mask */
static int
nsAddAddrMask(GString *line,
              virNWFilterVarCombIter *vars,
              const char *key,
              nwItemDesc *addr,
              nwItemDesc *mask,
              const char *defmask)
{
    char a[INET6_ADDRSTRLEN + 8];
    char m[INET6_ADDRSTRLEN + 8];

    if (!HAS_ENTRY_ITEM(addr))
        return 0;
    if (virNWFilterPrintDataType(vars, a, sizeof(a), addr) < 0)
        return -1;
    if (mask && HAS_ENTRY_ITEM(mask)) {
        if (virNWFilterPrintDataType(vars, m, sizeof(m), mask) < 0)
            return -1;
    } else if (defmask) {
        g_strlcpy(m, defmask, sizeof(m));
    } else {
        m[0] = '\0';
    }
    g_string_append_printf(line, " %s=%s%s%s%s", key,
                           ENTRY_WANT_NEG_SIGN(addr) ? "!" : "", a,
                           m[0] ? "/" : "", m);
    return 0;
}


/* key=[!]LOW[-HIGH] */
static int
nsAddRange(GString *line,
           virNWFilterVarCombIter *vars,
           const char *key,
           nwItemDesc *lo,
           nwItemDesc *hi,
           bool hex)
{
    char a[64];
    char b[64];

    if (!HAS_ENTRY_ITEM(lo))
        return 0;
    if ((hex ? virNWFilterPrintDataTypeAsHex(vars, a, sizeof(a), lo) :
               virNWFilterPrintDataType(vars, a, sizeof(a), lo)) < 0)
        return -1;
    g_string_append_printf(line, " %s=%s%s", key,
                           ENTRY_WANT_NEG_SIGN(lo) ? "!" : "", a);
    if (hi && HAS_ENTRY_ITEM(hi)) {
        if ((hex ? virNWFilterPrintDataTypeAsHex(vars, b, sizeof(b), hi) :
                   virNWFilterPrintDataType(vars, b, sizeof(b), hi)) < 0)
            return -1;
        g_string_append_printf(line, "-%s", b);
    }
    return 0;
}


static int
nsAddEthHdr(GString *line,
            virNWFilterVarCombIter *vars,
            ethHdrDataDef *eth,
            bool reverse)
{
    if (nsAddAddrMask(line, vars, reverse ? "dmac" : "smac",
                      &eth->dataSrcMACAddr, &eth->dataSrcMACMask, NULL) < 0 ||
        nsAddAddrMask(line, vars, reverse ? "smac" : "dmac",
                      &eth->dataDstMACAddr, &eth->dataDstMACMask, NULL) < 0)
        return -1;
    return 0;
}


static int
nsAddPorts(GString *line,
           virNWFilterVarCombIter *vars,
           portDataDef *ports,
           bool reverse)
{
    if (nsAddRange(line, vars, reverse ? "sport" : "dport",
                   &ports->dataDstPortStart, &ports->dataDstPortEnd, false) < 0 ||
        nsAddRange(line, vars, reverse ? "dport" : "sport",
                   &ports->dataSrcPortStart, &ports->dataSrcPortEnd, false) < 0)
        return -1;
    return 0;
}


/* the matches of an ethernet rule (nftablesHandleEthernetRule) */
static int
nsEthernetRule(GString *line,
               virNWFilterVarCombIter *vars,
               virNWFilterRuleDef *rule,
               bool reverse)
{
    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
        if (nsAddEthHdr(line, vars, &rule->p.ethHdrFilter.ethHdr, reverse) < 0 ||
            nsAddItem(line, vars, "etype",
                      &rule->p.ethHdrFilter.dataProtocolID, true) < 0)
            return -1;
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_IP: {
        ipHdrDataDef *ip = &rule->p.ipHdrFilter.ipHdr;

        g_string_append_printf(line, " etype=%s0x0800",
                               ENTRY_WANT_NEG_SIGN(&ip->dataProtocolID) ? "!" : "");
        if (nsAddEthHdr(line, vars, &rule->p.ipHdrFilter.ethHdr, reverse) < 0 ||
            nsAddAddrMask(line, vars, reverse ? "dst" : "src",
                          &ip->dataSrcIPAddr, &ip->dataSrcIPMask, NULL) < 0 ||
            nsAddAddrMask(line, vars, reverse ? "src" : "dst",
                          &ip->dataDstIPAddr, &ip->dataDstIPMask, NULL) < 0 ||
            nsAddItem(line, vars, "proto", &ip->dataProtocolID, false) < 0 ||
            nsAddPorts(line, vars, &rule->p.ipHdrFilter.portData, reverse) < 0 ||
            nsAddItem(line, vars, "dscp", &ip->dataDSCP, true) < 0)
            return -1;
        break;
    }

    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
    case VIR_NWFILTER_RULE_PROTOCOL_RARP: {
        arpHdrFilterDef *arp = &rule->p.arpHdrFilter;

        if (nsAddEthHdr(line, vars, &arp->ethHdr, reverse) < 0)
            return -1;
        g_string_append(line, rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ARP ?
                        " etype=0x0806" : " etype=0x8035");
        if (nsAddItem(line, vars, "arp-htype", &arp->dataHWType, false) < 0 ||
            nsAddItem(line, vars, "arp-ptype", &arp->dataProtocolType, true) < 0 ||
            nsAddItem(line, vars, "arp-op", &arp->dataOpcode, false) < 0 ||
            nsAddAddrMask(line, vars, reverse ? "arp-tpa" : "arp-spa",
                          &arp->dataARPSrcIPAddr, &arp->dataARPSrcIPMask, "32") < 0 ||
            nsAddAddrMask(line, vars, reverse ? "arp-spa" : "arp-tpa",
                          &arp->dataARPDstIPAddr, &arp->dataARPDstIPMask, "32") < 0 ||
            nsAddItem(line, vars, reverse ? "arp-tha" : "arp-sha",
                      &arp->dataARPSrcMACAddr, false) < 0 ||
            nsAddItem(line, vars, reverse ? "arp-sha" : "arp-tha",
                      &arp->dataARPDstMACAddr, false) < 0)
            return -1;
        if (HAS_ENTRY_ITEM(&arp->dataGratuitousARP) &&
            arp->dataGratuitousARP.u.boolean)
            g_string_append_printf(line, " arp-garp=%s1",
                                   ENTRY_WANT_NEG_SIGN(&arp->dataGratuitousARP) ? "!" : "");
        break;
    }

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6: {
        ipv6HdrFilterDef *ip6 = &rule->p.ipv6HdrFilter;

        if (nsAddEthHdr(line, vars, &ip6->ethHdr, reverse) < 0)
            return -1;
        g_string_append(line, " etype=0x86dd");
        if (nsAddAddrMask(line, vars, reverse ? "dst" : "src",
                          &ip6->ipHdr.dataSrcIPAddr, &ip6->ipHdr.dataSrcIPMask, NULL) < 0 ||
            nsAddAddrMask(line, vars, reverse ? "src" : "dst",
                          &ip6->ipHdr.dataDstIPAddr, &ip6->ipHdr.dataDstIPMask, NULL) < 0 ||
            nsAddItem(line, vars, "proto", &ip6->ipHdr.dataProtocolID, false) < 0 ||
            nsAddPorts(line, vars, &ip6->portData, reverse) < 0 ||
            nsAddRange(line, vars, "icmp-type", &ip6->dataICMPTypeStart,
                       &ip6->dataICMPTypeEnd, false) < 0 ||
            nsAddRange(line, vars, "icmp-code", &ip6->dataICMPCodeStart,
                       &ip6->dataICMPCodeEnd, false) < 0)
            return -1;
        break;
    }

    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:
        if (nsAddEthHdr(line, vars, &rule->p.vlanHdrFilter.ethHdr, reverse) < 0)
            return -1;
        g_string_append(line, " etype=0x8100");
        if (nsAddItem(line, vars, "vlan-id", &rule->p.vlanHdrFilter.dataVlanID, false) < 0 ||
            nsAddItem(line, vars, "vlan-type", &rule->p.vlanHdrFilter.dataVlanEncap, true) < 0)
            return -1;
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_STP: {
        stpHdrFilterDef *stp = &rule->p.stpHdrFilter;

        if (reverse && HAS_ENTRY_ITEM(&stp->ethHdr.dataSrcMACAddr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("STP filtering in %1$s direction with source MAC address set is not supported"),
                           virNWFilterRuleDirectionTypeToString(
                               VIR_NWFILTER_RULE_DIRECTION_INOUT));
            return -1;
        }
        if (nsAddEthHdr(line, vars, &stp->ethHdr, reverse) < 0)
            return -1;
        g_string_append(line, " dmac=" NWFILTER_MAC_BGA);
        if (nsAddItem(line, vars, "stp-type", &stp->dataType, true) < 0 ||
            nsAddItem(line, vars, "stp-flags", &stp->dataFlags, true) < 0 ||
            nsAddRange(line, vars, "stp-root-prio", &stp->dataRootPri,
                       &stp->dataRootPriHi, false) < 0 ||
            nsAddAddrMask(line, vars, "stp-root-addr", &stp->dataRootAddr,
                          &stp->dataRootAddrMask, NULL) < 0 ||
            nsAddRange(line, vars, "stp-root-cost", &stp->dataRootCost,
                       &stp->dataRootCostHi, false) < 0 ||
            nsAddRange(line, vars, "stp-sender-prio", &stp->dataSndrPrio,
                       &stp->dataSndrPrioHi, false) < 0 ||
            nsAddAddrMask(line, vars, "stp-sender-addr", &stp->dataSndrAddr,
                          &stp->dataSndrAddrMask, NULL) < 0 ||
            nsAddRange(line, vars, "stp-port", &stp->dataPort,
                       &stp->dataPortHi, false) < 0 ||
            nsAddRange(line, vars, "stp-age", &stp->dataAge,
                       &stp->dataAgeHi, false) < 0 ||
            nsAddRange(line, vars, "stp-max-age", &stp->dataMaxAge,
                       &stp->dataMaxAgeHi, false) < 0 ||
            nsAddRange(line, vars, "stp-hello", &stp->dataHelloTime,
                       &stp->dataHelloTimeHi, false) < 0 ||
            nsAddRange(line, vars, "stp-fwd-delay", &stp->dataFwdDelay,
                       &stp->dataFwdDelayHi, false) < 0)
            return -1;
        break;
    }

    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected rule protocol '%1$d', priority '%2$d'"),
                       rule->prtclType, rule->priority);
        return -1;
    }
    return 0;
}


static bool
nsRuleNeedsConntrack(virNWFilterRuleDef *rule)
{
    if (virNWFilterRuleIsProtocolEthernet(rule))
        return false;
    if (rule->flags & RULE_FLAG_NO_STATEMATCH)
        return false;
    if (!(rule->flags & IPTABLES_STATE_FLAGS) &&
        rule->action != VIR_NWFILTER_RULE_ACTION_ACCEPT)
        return false;
    return true;
}


static int
nsAddIPHdr(GString *line,
           virNWFilterVarCombIter *vars,
           ipHdrDataDef *ip,
           bool reverse)
{
    const char *src = reverse ? "dst" : "src";
    const char *dst = reverse ? "src" : "dst";

    if (HAS_ENTRY_ITEM(&ip->dataSrcIPAddr)) {
        if (nsAddAddrMask(line, vars, src, &ip->dataSrcIPAddr,
                          &ip->dataSrcIPMask, NULL) < 0)
            return -1;
    } else if (HAS_ENTRY_ITEM(&ip->dataSrcIPFrom)) {
        if (nsAddRange(line, vars, src, &ip->dataSrcIPFrom,
                       &ip->dataSrcIPTo, false) < 0)
            return -1;
    }
    if (HAS_ENTRY_ITEM(&ip->dataDstIPAddr)) {
        if (nsAddAddrMask(line, vars, dst, &ip->dataDstIPAddr,
                          &ip->dataDstIPMask, NULL) < 0)
            return -1;
    } else if (HAS_ENTRY_ITEM(&ip->dataDstIPFrom)) {
        if (nsAddRange(line, vars, dst, &ip->dataDstIPFrom,
                       &ip->dataDstIPTo, false) < 0)
            return -1;
    }
    if (nsAddItem(line, vars, "dscp", &ip->dataDSCP, false) < 0)
        return -1;
    return 0;
}


/* the matches of an IP rule (nftablesHandleInetRule) */
static int
nsInetRule(GString *line,
           virNWFilterVarCombIter *vars,
           virNWFilterRuleDef *rule,
           bool directionIn,
           bool reverse)
{
    ipHdrDataDef *ipHdr = NULL;
    nwItemDesc *srcmac = NULL;
    portDataDef *ports = NULL;
    const char *l4 = NULL;
    bool hasICMPType = false;

    if (virNWFilterRuleIsProtocolIPv6(rule) && !virNWFilterRuleIsProtocolIPv4(rule))
        g_string_append(line, " l3=ip6");
    else if (virNWFilterRuleIsProtocolIPv4(rule) && !virNWFilterRuleIsProtocolIPv6(rule))
        g_string_append(line, " l3=ip");

    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        l4 = "tcp";
        ipHdr = &rule->p.tcpHdrFilter.ipHdr;
        srcmac = &rule->p.tcpHdrFilter.dataSrcMACAddr;
        ports = &rule->p.tcpHdrFilter.portData;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        l4 = "udp";
        ipHdr = &rule->p.udpHdrFilter.ipHdr;
        srcmac = &rule->p.udpHdrFilter.dataSrcMACAddr;
        ports = &rule->p.udpHdrFilter.portData;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        l4 = "udplite";
        ipHdr = &rule->p.udpliteHdrFilter.ipHdr;
        srcmac = &rule->p.udpliteHdrFilter.dataSrcMACAddr;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        l4 = "esp";
        ipHdr = &rule->p.espHdrFilter.ipHdr;
        srcmac = &rule->p.espHdrFilter.dataSrcMACAddr;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        l4 = "ah";
        ipHdr = &rule->p.ahHdrFilter.ipHdr;
        srcmac = &rule->p.ahHdrFilter.dataSrcMACAddr;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        l4 = "sctp";
        ipHdr = &rule->p.sctpHdrFilter.ipHdr;
        srcmac = &rule->p.sctpHdrFilter.dataSrcMACAddr;
        ports = &rule->p.sctpHdrFilter.portData;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        l4 = rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMP ? "icmp" : "icmpv6";
        ipHdr = &rule->p.icmpHdrFilter.ipHdr;
        srcmac = &rule->p.icmpHdrFilter.dataSrcMACAddr;
        hasICMPType = true;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        l4 = "igmp";
        ipHdr = &rule->p.igmpHdrFilter.ipHdr;
        srcmac = &rule->p.igmpHdrFilter.dataSrcMACAddr;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        ipHdr = &rule->p.allHdrFilter.ipHdr;
        srcmac = &rule->p.allHdrFilter.dataSrcMACAddr;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected protocol %1$d"), rule->prtclType);
        return -1;
    }

    if (l4)
        g_string_append_printf(line, " l4=%s", l4);
    if (nsAddItem(line, vars, "smac", srcmac, false) < 0 ||
        nsAddIPHdr(line, vars, ipHdr, reverse) < 0)
        return -1;

    if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_TCP ||
        rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6) {
        nwItemDesc *flags = &rule->p.tcpHdrFilter.dataTCPFlags;

        if (HAS_ENTRY_ITEM(flags))
            g_string_append_printf(line, " tcp-flags=%s0x%x/0x%x",
                                   ENTRY_WANT_NEG_SIGN(flags) ? "!" : "",
                                   flags->u.tcpFlags.mask, flags->u.tcpFlags.flags);
        if (nsAddItem(line, vars, "tcp-option",
                      &rule->p.tcpHdrFilter.dataTCPOption, false) < 0)
            return -1;
    }
    if (ports && nsAddPorts(line, vars, ports, reverse) < 0)
        return -1;
    if (hasICMPType && HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPType)) {
        if (nsAddItem(line, vars, "icmp-type",
                      &rule->p.icmpHdrFilter.dataICMPType, false) < 0 ||
            nsAddItem(line, vars, "icmp-code",
                      &rule->p.icmpHdrFilter.dataICMPCode, false) < 0)
            return -1;
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataIPSet)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ipset is not available on Windows"));
        return -1;
    }

    /* ct count: for the connections the guest opens */
    if (HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove) && !directionIn) {
        if (nsAddItem(line, vars, "connlimit", &ipHdr->dataConnlimitAbove, false) < 0)
            return -1;
    }

    if (nsRuleNeedsConntrack(rule)) {
        bool skipDirection = (HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove) && !directionIn) ||
                             hasICMPType;

        if (!skipDirection)
            g_string_append_printf(line, " ct-dir=%s", reverse ? "reply" : "original");

        if (rule->flags & IPTABLES_STATE_FLAGS &&
            !(rule->flags & RULE_FLAG_STATE_NONE)) {
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
            g_autofree char *states = NULL;

            virNWFilterPrintStateMatchFlags(&buf, "", rule->flags, false);
            states = virBufferContentAndReset(&buf);
            if (states) {
                g_strstrip(states);
                g_ascii_strdown(states, -1);
                g_string_append_printf(line, " ct-state=%s", states);
            }
        } else {
            g_string_append_printf(line, " ct-state=%s",
                                   reverse ? "established" : "new,established");
        }
    }
    return 0;
}


static const char *
nsVerdict(virNWFilterRuleActionType action)
{
    switch (action) {
    case VIR_NWFILTER_RULE_ACTION_DROP:
        return "drop";
    case VIR_NWFILTER_RULE_ACTION_ACCEPT:
        return "accept";
    case VIR_NWFILTER_RULE_ACTION_REJECT:
        return "reject";
    case VIR_NWFILTER_RULE_ACTION_RETURN:
        return "return";
    case VIR_NWFILTER_RULE_ACTION_CONTINUE:
        return "continue";
    case VIR_NWFILTER_RULE_ACTION_LAST:
        break;
    }
    return "drop";
}


/* one rule (nftablesCreateRuleInstance) */
static int
nsRuleInstance(nsProgram *p,
               const char *chainSuffix,
               virNWFilterRuleDef *rule,
               virNWFilterVarCombIter *vars,
               bool directionIn,
               bool reverse)
{
    g_autoptr(GString) line = g_string_new(NULL);
    const char *dir = directionIn ? "in" : "out";
    bool eth = virNWFilterRuleIsProtocolEthernet(rule);
    bool root = STREQ(chainSuffix, virNWFilterChainSuffixTypeToString(
                                        VIR_NWFILTER_CHAINSUFFIX_ROOT));

    if (!eth)
        g_string_append_printf(line, "rule inet-%s", dir);
    else if (root)
        g_string_append_printf(line, "rule eth-%s", dir);
    else
        g_string_append_printf(line, "rule eth-%s-%s", dir, chainSuffix);
    g_string_append_printf(line, " %s", nsVerdict(rule->action));

    if (eth) {
        if (nsEthernetRule(line, vars, rule, reverse) < 0)
            return -1;
    } else {
        if (nsInetRule(line, vars, rule, directionIn, reverse) < 0)
            return -1;
    }
    g_string_append_c(line, '\n');
    g_string_append(p->prog, line->str);
    return 0;
}


/* every instance of a rule, one per combination of the values of its
 * variables (nftablesRuleInstCommand) */
static int
nsRuleInst(nsProgram *p, virNWFilterRuleInst *rule)
{
    virNWFilterVarCombIter *vciter;
    virNWFilterVarCombIter *tmp;
    virNWFilterRuleDirectionType direction = rule->def->tt;
    int ret = -1;

    tmp = vciter = virNWFilterVarCombIterCreate(rule->vars,
                                                rule->def->varAccess,
                                                rule->def->nVarAccess);
    if (!vciter)
        return -1;

    do {
        if (direction == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            if (nsRuleInstance(p, rule->chainSuffix, rule->def, tmp, true, false) < 0)
                goto cleanup;
            if (nsRuleInstance(p, rule->chainSuffix, rule->def, tmp, false,
                               virNWFilterRuleIsProtocolEthernet(rule->def)) < 0)
                goto cleanup;
        } else {
            bool directionIn = direction == VIR_NWFILTER_RULE_DIRECTION_IN;

            if (nsRuleInstance(p, rule->chainSuffix, rule->def, tmp,
                               directionIn, false) < 0)
                goto cleanup;
            /* the replies of the connections an accept rule lets in */
            if (nsRuleNeedsConntrack(rule->def) &&
                rule->def->action == VIR_NWFILTER_RULE_ACTION_ACCEPT) {
                if (nsRuleInstance(p, rule->chainSuffix, rule->def, tmp,
                                   !directionIn, true) < 0)
                    goto cleanup;
            }
        }
        tmp = virNWFilterVarCombIterNext(tmp);
    } while (tmp != NULL);

    ret = 0;
 cleanup:
    virNWFilterVarCombIterFree(vciter);
    return ret;
}


/* the ether type of the frames that take a sub chain, from its name */
static void
nsSubChainJump(nsProgram *p,
               const char *suffix,
               const char *dir)
{
    static const struct { const char *prefix; const char *match; } jumps[] = {
        { "ipv4", " etype=0x0800" },
        { "ipv6", " etype=0x86dd" },
        { "arp", " etype=0x0806" },
        { "rarp", " etype=0x8035" },
        { "vlan", " etype=0x8100" },
        { "stp", " dmac=" NWFILTER_MAC_BGA },
        { "mac", "" },
    };
    const char *match = "";
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(jumps); i++) {
        if (STRPREFIX(suffix, jumps[i].prefix)) {
            match = jumps[i].match;
            break;
        }
    }
    g_string_append_printf(p->prog, "rule eth-%s jump:eth-%s-%s%s\n",
                           dir, dir, suffix, match);
}


typedef struct {
    const char *suffix;
    virNWFilterChainPriority priority;
    bool in;
    bool out;
} nsSubChain;


static int
nsSubChainSort(const void *a, const void *b, void *opaque G_GNUC_UNUSED)
{
    const nsSubChain *ca = a;
    const nsSubChain *cb = b;

    return ca->priority - cb->priority;
}


/* the program of an interface (nftablesHandleCreateChains): the root rules
 * of the ethernet table interleaved with the jumps to the sub chains by
 * priority, then every other rule */
static int
nsBuildProgram(nsProgram *p,
               virNWFilterRuleInst **rules,
               size_t nrules)
{
    const char *root = virNWFilterChainSuffixTypeToString(VIR_NWFILTER_CHAINSUFFIX_ROOT);
    g_autofree nsSubChain *chains = NULL;
    size_t nchains = 0;
    size_t i;
    size_t j;
    size_t nextRoot = 0;
    g_autofree bool *done = g_new0(bool, nrules + 1);

    for (i = 0; i < nrules; i++) {
        virNWFilterRuleDef *def = rules[i]->def;
        bool eth = virNWFilterRuleIsProtocolEthernet(def);

        if (STREQ(rules[i]->chainSuffix, root))
            continue;
        for (j = 0; j < nchains; j++) {
            if (STREQ(chains[j].suffix, rules[i]->chainSuffix))
                break;
        }
        if (j == nchains) {
            VIR_EXPAND_N(chains, nchains, 1);
            chains[j].suffix = rules[i]->chainSuffix;
            chains[j].priority = rules[i]->chainPriority;
        }
        if (eth) {
            chains[j].in |= def->tt == VIR_NWFILTER_RULE_DIRECTION_IN ||
                            def->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT;
            chains[j].out |= def->tt == VIR_NWFILTER_RULE_DIRECTION_OUT ||
                             def->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT;
        }
    }
    if (nchains)
        g_qsort_with_data(chains, nchains, sizeof(chains[0]), nsSubChainSort, NULL);

    for (i = 0; i < nchains; i++) {
        /* the ethernet root rules of a lower priority than the chain */
        for (j = nextRoot; j < nrules; j++) {
            if (STRNEQ(rules[j]->chainSuffix, root))
                break;
            if (chains[i].priority <= rules[j]->priority)
                break;
            nextRoot = j + 1;
            if (!virNWFilterRuleIsProtocolEthernet(rules[j]->def))
                continue;
            if (nsRuleInst(p, rules[j]) < 0)
                return -1;
            done[j] = true;
        }
        if (chains[i].in)
            nsSubChainJump(p, chains[i].suffix, "in");
        if (chains[i].out)
            nsSubChainJump(p, chains[i].suffix, "out");
    }

    for (i = 0; i < nrules; i++) {
        if (done[i])
            continue;
        if (nsRuleInst(p, rules[i]) < 0)
            return -1;
    }
    return 0;
}


static int
nsApplyNewRules(const char *ifname,
                virNWFilterRuleInst **rules,
                size_t nrules)
{
    g_autofree char *brname = NULL;
    g_autofree char *active = nsFilterPath(ifname, NULL);
    g_autofree char *old = nsFilterPath(ifname, ".old");
    g_autoptr(GString) prog = g_string_new(NULL);
    nsProgram p = { prog, ifname };
    virMacAddr mac;
    size_t i;

    /* the filters of an interface are applied by the switch it is a port
     * of: a TAP-Windows adapter has none */
    if (virNetDevBridgeSwitchPortGet(ifname, &brname, &mac) < 0) {
        virResetLastError();
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("interface '%1$s' is not a port of the switch of a libvirt network: on Windows, network filters apply to interfaces of type 'network', or 'bridge' on the bridge of a libvirt network"),
                       ifname);
        return -1;
    }

    /* as the nftables driver: rules of a sub chain take its priority when
     * it is higher, then all are sorted */
    for (i = 0; i < nrules; i++) {
        if (rules[i]->chainPriority > rules[i]->priority &&
            !strstr("root", rules[i]->chainSuffix))
            rules[i]->priority = rules[i]->chainPriority;
    }
    if (nrules)
        g_qsort_with_data(rules, nrules, sizeof(rules[0]),
                          virNWFilterRuleInstSortPtr, NULL);

    g_string_append_printf(prog, "# network filter of %s (libvirt)\n", ifname);
    if (nsBuildProgram(&p, rules, nrules) < 0)
        return -1;

    /* the new program replaces the one in use, which is kept until
     * tearOldRules, for tearNewRules */
    unlink(old);
    if (virFileExists(active) && rename(active, old) < 0) {
        virReportSystemError(errno, _("cannot rename %1$s"), active);
        return -1;
    }
    if (nsWriteProgram(ifname, NULL, prog->str) < 0)
        return -1;
    virNetDevBridgeSwitchNotify(brname);
    return 0;
}


static int
nsTeardownNewRules(const char *ifname)
{
    g_autofree char *active = nsFilterPath(ifname, NULL);
    g_autofree char *old = nsFilterPath(ifname, ".old");

    unlink(active);
    if (virFileExists(old))
        ignore_value(rename(old, active));
    nsNotify(ifname);
    return 0;
}


static int
nsTeardownOldRules(const char *ifname)
{
    g_autofree char *old = nsFilterPath(ifname, ".old");

    unlink(old);
    return 0;
}


static int
nsAllTeardown(const char *ifname)
{
    g_autofree char *active = nsFilterPath(ifname, NULL);
    g_autofree char *old = nsFilterPath(ifname, ".old");

    unlink(active);
    unlink(old);
    nsNotify(ifname);
    return 0;
}


static bool
nsCanApplyBasicRules(void)
{
    return true;
}


static int
nsApplyProgram(const char *ifname, const char *text)
{
    g_autofree char *old = nsFilterPath(ifname, ".old");

    unlink(old);
    if (nsWriteProgram(ifname, NULL, text) < 0)
        return -1;
    nsNotify(ifname);
    return 0;
}


/* the guest may send IPv4 and ARP with its MAC address, while its IP
 * address is learned (nftablesApplyBasicRules) */
static int
nsApplyBasicRules(const char *ifname,
                  const virMacAddr *macaddr)
{
    char mac[VIR_MAC_STRING_BUFLEN];
    g_autofree char *text = NULL;

    virMacAddrFormat(macaddr, mac);
    text = g_strdup_printf("# basic rules of %s (libvirt)\n"
                           "rule eth-out drop smac=!%s\n"
                           "rule eth-out accept etype=0x0800\n"
                           "rule eth-out accept etype=0x0806\n"
                           "rule eth-out accept\n",
                           ifname, mac);
    return nsApplyProgram(ifname, text);
}


/* DHCP only (nftablesApplyDHCPOnlyRules) */
static int
nsApplyDHCPOnlyRules(const char *ifname,
                     const virMacAddr *macaddr,
                     virNWFilterVarValue *dhcpsrvrs,
                     bool leaveTemporary G_GNUC_UNUSED)
{
    char mac[VIR_MAC_STRING_BUFLEN];
    g_autoptr(GString) prog = g_string_new(NULL);
    unsigned int num = dhcpsrvrs ? virNWFilterVarValueGetCardinality(dhcpsrvrs) : 0;
    unsigned int idx = 0;

    virMacAddrFormat(macaddr, mac);
    g_string_append_printf(prog, "# DHCP only rules of %s (libvirt)\n", ifname);
    g_string_append_printf(prog,
                           "rule eth-out accept smac=%s etype=0x0800 proto=17 sport=68 dport=67\n"
                           "rule eth-out drop\n", mac);
    while (true) {
        const char *server = idx < num ? virNWFilterVarValueGetNthValue(dhcpsrvrs, idx) : NULL;
        int ctr;

        for (ctr = 0; ctr < 2; ctr++) {
            g_string_append_printf(prog, "rule eth-in accept dmac=%s etype=0x0800",
                                   ctr == 0 ? mac : "ff:ff:ff:ff:ff:ff");
            if (server)
                g_string_append_printf(prog, " src=%s", server);
            g_string_append(prog, " proto=17 sport=67 dport=68\n");
        }
        idx++;
        if (idx >= num)
            break;
    }
    g_string_append(prog, "rule eth-in drop\n");
    return nsApplyProgram(ifname, prog->str);
}


static int
nsRemoveBasicRules(const char *ifname)
{
    return nsAllTeardown(ifname);
}


static int
nsDropAllRules(const char *ifname)
{
    g_autofree char *text = g_strdup_printf("# drop all rules of %s (libvirt)\n"
                                            "rule eth-out drop\n"
                                            "rule eth-in drop\n", ifname);

    return nsApplyProgram(ifname, text);
}


static int
nsDriverInit(bool privileged G_GNUC_UNUSED,
             virNWFilterDriverConfig *config G_GNUC_UNUSED)
{
    netswitch_driver.flags = TECHDRV_FLAG_INITIALIZED;
    return 0;
}


static void
nsDriverShutdown(void)
{
    netswitch_driver.flags = 0;
}


virNWFilterTechDriver netswitch_driver = {
    .name               = NETSWITCH_DRIVER_ID,
    .flags              = 0,
    .init               = nsDriverInit,
    .shutdown           = nsDriverShutdown,
    .applyNewRules      = nsApplyNewRules,
    .tearNewRules       = nsTeardownNewRules,
    .tearOldRules       = nsTeardownOldRules,
    .allTeardown        = nsAllTeardown,
    .canApplyBasicRules = nsCanApplyBasicRules,
    .applyBasicRules    = nsApplyBasicRules,
    .applyDHCPOnlyRules = nsApplyDHCPOnlyRules,
    .applyDropAllRules  = nsDropAllRules,
    .removeBasicRules   = nsRemoveBasicRules,
};
