/*
 * interface_backend_win32.c: Windows backend for virInterface
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * What the udev backend gives on Linux, from the IP helper API and the
 * network class of SetupAPI: the network adapters Windows shows (those
 * that are not hidden), active when their link is up; a network bridge of
 * Windows is a bridge, and a team a bond, whose members are the adapters
 * below it; and, as netcf does, the addresses, DHCP and gateway of each.
 * As with netcf, virsh iface-start and iface-destroy enable and disable an
 * adapter.
 * Interface definitions (iface-define) are not kept: Windows keeps the
 * configuration of its adapters itself.
 */

#include <config.h>

/* before configmake.h, whose DATADIR the Windows headers use */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#include <iphlpapi.h>

#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "datatypes.h"
#include "interface_driver.h"
#include "interface_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "virpidfile.h"
#include "viraccessapicheck.h"
#include "virinterfaceobj.h"
#include "virnetdev.h"
#include "virmacaddr.h"
#include "vircommand.h"
#include "virsocketaddr.h"
#include "virutil.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_LOG_INIT("interface.interface_backend_win32");

/* GUID_DEVCLASS_NET of devguid.h */
static const GUID win32IfaceNetClass = {
    0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};

/* NCF_HIDDEN of the Characteristics of a network adapter */
#define WIN32_IFACE_NCF_HIDDEN 0x8

struct win32_iface_driver {
    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    char *stateDir;
    bool privileged;
};

static struct win32_iface_driver *driver;

typedef struct {
    char *name;         /* connection name (alias) */
    char *mac;          /* NULL without an Ethernet address */
    bool active;        /* link up */
    bool enabled;       /* administratively up */
    bool mux;           /* a multiplexor: a network bridge or a team */
    NET_IFINDEX index;
    NET_LUID luid;
    unsigned int mtu;
} win32Iface;

typedef struct {
    win32Iface *ifaces;
    size_t nifaces;
    PMIB_IF_TABLE2 table;   /* every interface, filters included */
} win32IfaceList;

static void
win32IfaceListClear(win32IfaceList *list)
{
    size_t i;

    for (i = 0; i < list->nifaces; i++) {
        g_free(list->ifaces[i].name);
        g_free(list->ifaces[i].mac);
    }
    g_clear_pointer(&list->ifaces, g_free);
    list->nifaces = 0;
    if (list->table)
        FreeMibTable(list->table);
    list->table = NULL;
}


static char *
win32IfaceUTF8(const wchar_t *w)
{
    return w ? g_utf16_to_utf8((const gunichar2 *)w, -1, NULL, NULL, NULL) : NULL;
}


typedef struct {
    GUID guid;
    DWORD characteristics;
    bool mux;
} win32IfaceClassInfo;

/*
 * The network class of SetupAPI: for each adapter, its Characteristics
 * (NCF_HIDDEN for those Windows does not show, as the WAN miniports and the
 * Wi-Fi Direct adapters) and whether it is a multiplexor: the adapter of a
 * network bridge (above the bridge, itself above its members), or of a
 * team of adapters (above its members).  Older Windows named the adapter
 * of a bridge ms_bridgemp.
 */
static win32IfaceClassInfo *
win32IfaceClassInfoGet(size_t *ninfo)
{
    HDEVINFO set = SetupDiGetClassDevsW(&win32IfaceNetClass, NULL, NULL, DIGCF_PRESENT);
    win32IfaceClassInfo *info = NULL;
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    DWORD i;

    *ninfo = 0;
    if (set == INVALID_HANDLE_VALUE)
        return NULL;

    for (i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        HKEY key = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0,
                                        DIREG_DRV, KEY_READ);
        wchar_t id[64] = { 0 };
        wchar_t component[128] = { 0 };
        DWORD characteristics = 0;
        DWORD size;
        GUID guid;

        if (key == INVALID_HANDLE_VALUE)
            continue;

        size = sizeof(id) - sizeof(wchar_t);
        if (RegQueryValueExW(key, L"NetCfgInstanceId", NULL, NULL,
                             (BYTE *)id, &size) != ERROR_SUCCESS ||
            CLSIDFromString(id, &guid) != NOERROR) {
            RegCloseKey(key);
            continue;
        }
        size = sizeof(characteristics);
        RegQueryValueExW(key, L"Characteristics", NULL, NULL,
                         (BYTE *)&characteristics, &size);
        size = sizeof(component) - sizeof(wchar_t);
        RegQueryValueExW(key, L"ComponentId", NULL, NULL,
                         (BYTE *)component, &size);
        RegCloseKey(key);

        VIR_REALLOC_N(info, *ninfo + 1);
        info[*ninfo].guid = guid;
        info[*ninfo].characteristics = characteristics;
        info[*ninfo].mux = _wcsicmp(component, L"ms_bridgemp") == 0 ||
            _wcsicmp(component, L"ms_implat_mp") == 0 ||
            _wcsicmp(component, L"COMPOSITEBUS\\MS_IMPLAT_MP") == 0;
        (*ninfo)++;
    }

    SetupDiDestroyDeviceInfoList(set);
    return info;
}


/*
 * The adapters of the host as "ip link" shows them on Linux: those of the
 * network class that are not hidden, with an Ethernet (or Wi-Fi) address,
 * and the virtual adapters without one, as Wintun's.  Filters (the
 * lightweight filters of the stack) and tunnels are left out.
 */
static int
win32IfaceListGet(win32IfaceList *list)
{
    PMIB_IF_TABLE2 table = NULL;
    g_autofree win32IfaceClassInfo *info = NULL;
    size_t ninfo = 0;
    ULONG i;
    DWORD err;

    list->ifaces = NULL;
    list->nifaces = 0;
    list->table = NULL;

    if ((err = GetIfTable2(&table)) != NO_ERROR) {
        virReportSystemError(err, "%s",
                             _("failed to get the network adapters of the host"));
        return -1;
    }

    info = win32IfaceClassInfoGet(&ninfo);

    for (i = 0; i < table->NumEntries; i++) {
        MIB_IF_ROW2 *row = &table->Table[i];
        win32Iface *iface;
        size_t j;

        if (row->InterfaceAndOperStatusFlags.FilterInterface)
            continue;
        if (row->Type != IF_TYPE_ETHERNET_CSMACD &&
            row->Type != IF_TYPE_IEEE80211 &&
            row->Type != IF_TYPE_PROP_VIRTUAL)
            continue;
        if (row->Type != IF_TYPE_PROP_VIRTUAL &&
            row->PhysicalAddressLength != VIR_MAC_BUFLEN)
            continue;

        for (j = 0; j < ninfo; j++) {
            if (IsEqualGUID(&info[j].guid, &row->InterfaceGuid))
                break;
        }
        /* not a network adapter of the device tree, or hidden */
        if (j == ninfo || (info[j].characteristics & WIN32_IFACE_NCF_HIDDEN))
            continue;

        VIR_REALLOC_N(list->ifaces, list->nifaces + 1);
        iface = &list->ifaces[list->nifaces];
        memset(iface, 0, sizeof(*iface));

        if (!(iface->name = win32IfaceUTF8(row->Alias)))
            continue;
        if (row->PhysicalAddressLength == VIR_MAC_BUFLEN) {
            virMacAddr mac;
            char macstr[VIR_MAC_STRING_BUFLEN];

            virMacAddrSetRaw(&mac, row->PhysicalAddress);
            iface->mac = g_strdup(virMacAddrFormat(&mac, macstr));
        }
        iface->active = row->OperStatus == IfOperStatusUp;
        iface->enabled = row->AdminStatus == NET_IF_ADMIN_STATUS_UP;
        iface->mux = info[j].mux;
        iface->index = row->InterfaceIndex;
        iface->luid = row->InterfaceLuid;
        iface->mtu = row->Mtu;
        list->nifaces++;
    }

    list->table = table;
    return 0;
}


static win32Iface *
win32IfaceListFind(win32IfaceList *list, const char *name)
{
    size_t i;

    for (i = 0; i < list->nifaces; i++) {
        if (STREQ(list->ifaces[i].name, name))
            return &list->ifaces[i];
    }
    return NULL;
}


static virInterfaceDef *
win32IfaceMinimalDef(const win32Iface *iface)
{
    virInterfaceDef *def = g_new0(virInterfaceDef, 1);

    def->name = g_strdup(iface->name);
    def->mac = g_strdup(iface->mac);
    return def;
}


static int
win32ListInterfacesByStatus(virConnectPtr conn,
                            char **const names,
                            int names_len,
                            bool active,
                            virInterfaceObjListFilter filter)
{
    win32IfaceList list;
    int count = 0;
    size_t i;

    if (win32IfaceListGet(&list) < 0)
        return -1;

    for (i = 0; i < list.nifaces; i++) {
        g_autoptr(virInterfaceDef) def = NULL;

        if (names_len >= 0 && count >= names_len)
            break;
        if (list.ifaces[i].active != active)
            continue;

        def = win32IfaceMinimalDef(&list.ifaces[i]);
        if (filter(conn, def)) {
            if (names_len >= 0)
                names[count] = g_strdup(list.ifaces[i].name);
            count++;
        }
    }

    win32IfaceListClear(&list);
    return count;
}


static int
win32ConnectNumOfInterfaces(virConnectPtr conn)
{
    if (virConnectNumOfInterfacesEnsureACL(conn) < 0)
        return -1;

    return win32ListInterfacesByStatus(conn, NULL, -1, true,
                                       virConnectNumOfInterfacesCheckACL);
}

static int
win32ConnectListInterfaces(virConnectPtr conn,
                           char **const names,
                           int names_len)
{
    if (virConnectListInterfacesEnsureACL(conn) < 0)
        return -1;

    return win32ListInterfacesByStatus(conn, names, names_len, true,
                                       virConnectListInterfacesCheckACL);
}

static int
win32ConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    if (virConnectNumOfDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    return win32ListInterfacesByStatus(conn, NULL, -1, false,
                                       virConnectNumOfDefinedInterfacesCheckACL);
}

static int
win32ConnectListDefinedInterfaces(virConnectPtr conn,
                                  char **const names,
                                  int names_len)
{
    if (virConnectListDefinedInterfacesEnsureACL(conn) < 0)
        return -1;

    return win32ListInterfacesByStatus(conn, names, names_len, false,
                                       virConnectListDefinedInterfacesCheckACL);
}

#define MATCH(FLAG) (flags & (FLAG))
static int
win32ConnectListAllInterfaces(virConnectPtr conn,
                              virInterfacePtr **ifaces,
                              unsigned int flags)
{
    win32IfaceList list;
    virInterfacePtr *ifaces_list = NULL;
    int count = 0;
    size_t i;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE, -1);

    if (virConnectListAllInterfacesEnsureACL(conn) < 0)
        return -1;

    if (win32IfaceListGet(&list) < 0)
        return -1;

    if (ifaces)
        ifaces_list = g_new0(virInterfacePtr, list.nifaces + 1);

    for (i = 0; i < list.nifaces; i++) {
        win32Iface *iface = &list.ifaces[i];
        g_autoptr(virInterfaceDef) def = win32IfaceMinimalDef(iface);

        if (!virConnectListAllInterfacesCheckACL(conn, def))
            continue;

        if (MATCH(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE) &&
            !((MATCH(VIR_CONNECT_LIST_INTERFACES_ACTIVE) && iface->active) ||
              (MATCH(VIR_CONNECT_LIST_INTERFACES_INACTIVE) && !iface->active)))
            continue;

        if (ifaces) {
            if (!(ifaces_list[count] = virGetInterface(conn, iface->name, iface->mac))) {
                size_t j;

                for (j = 0; j < count; j++)
                    virObjectUnref(ifaces_list[j]);
                g_free(ifaces_list);
                win32IfaceListClear(&list);
                return -1;
            }
        }
        count++;
    }

    win32IfaceListClear(&list);

    if (ifaces) {
        VIR_REALLOC_N(ifaces_list, count + 1);
        *ifaces = g_steal_pointer(&ifaces_list);
    }

    return count;
}
#undef MATCH


static virInterfacePtr
win32InterfaceLookupByName(virConnectPtr conn, const char *name)
{
    win32IfaceList list;
    win32Iface *iface;
    g_autoptr(virInterfaceDef) def = NULL;
    virInterfacePtr ret = NULL;

    if (win32IfaceListGet(&list) < 0)
        return NULL;

    if (!(iface = win32IfaceListFind(&list, name))) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"), name);
        goto cleanup;
    }

    def = win32IfaceMinimalDef(iface);
    if (virInterfaceLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetInterface(conn, def->name, def->mac);

 cleanup:
    win32IfaceListClear(&list);
    return ret;
}


static virInterfacePtr
win32InterfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    win32IfaceList list;
    win32Iface *match = NULL;
    g_autoptr(virInterfaceDef) def = NULL;
    virInterfacePtr ret = NULL;
    size_t i;

    if (win32IfaceListGet(&list) < 0)
        return NULL;

    for (i = 0; i < list.nifaces; i++) {
        if (!list.ifaces[i].mac || STRCASENEQ(list.ifaces[i].mac, macstr))
            continue;
        if (match) {
            virReportError(VIR_ERR_MULTIPLE_INTERFACES,
                           _("the MAC address '%1$s' matches multiple interfaces"),
                           macstr);
            goto cleanup;
        }
        match = &list.ifaces[i];
    }

    if (!match) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface with MAC address '%1$s'"),
                       macstr);
        goto cleanup;
    }

    def = win32IfaceMinimalDef(match);
    if (virInterfaceLookupByMACStringEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetInterface(conn, def->name, def->mac);

 cleanup:
    win32IfaceListClear(&list);
    return ret;
}


static void
win32IfaceProtoAddIP(virInterfaceProtocolDef *proto,
                     const char *address,
                     int prefix)
{
    virInterfaceIPDef *ip = g_new0(virInterfaceIPDef, 1);

    ip->address = g_strdup(address);
    ip->prefix = prefix;
    proto->ips = g_renew(virInterfaceIPDef *, proto->ips, proto->nips + 1);
    proto->ips[proto->nips++] = ip;
}


/*
 * The IPv4 and IPv6 configuration of an adapter, as netcf reads it from
 * the configuration files: DHCP, autoconfiguration (an address of a router
 * advertisement), the addresses and the default gateway.
 */
static void
win32IfaceGetProtocols(IP_ADAPTER_ADDRESSES *addrs,
                       const win32Iface *iface,
                       virInterfaceDef *def)
{
    IP_ADAPTER_ADDRESSES *a;

    for (a = addrs; a; a = a->Next) {
        int families[] = { AF_INET, AF_INET6 };
        size_t f;

        if (a->Luid.Value != iface->luid.Value)
            continue;

        for (f = 0; f < G_N_ELEMENTS(families); f++) {
            g_autofree virInterfaceProtocolDef *proto = g_new0(virInterfaceProtocolDef, 1);
            IP_ADAPTER_UNICAST_ADDRESS *u;
            IP_ADAPTER_GATEWAY_ADDRESS *gw;
            bool any = false;

            proto->peerdns = -1;
            if (families[f] == AF_INET) {
                if (!a->Ipv4Enabled)
                    continue;
                proto->family = g_strdup("ipv4");
                proto->dhcp = !!(a->Flags & IP_ADAPTER_DHCP_ENABLED);
            } else {
                if (!a->Ipv6Enabled)
                    continue;
                proto->family = g_strdup("ipv6");
            }
            any = proto->dhcp;

            for (u = a->FirstUnicastAddress; u; u = u->Next) {
                virSocketAddr addr = { 0 };
                g_autofree char *str = NULL;

                if (u->Address.lpSockaddr->sa_family != families[f])
                    continue;
                memcpy(&addr.data, u->Address.lpSockaddr, u->Address.iSockaddrLength);
                addr.len = u->Address.iSockaddrLength;
                if (!(str = virSocketAddrFormat(&addr)))
                    continue;

                if (families[f] == AF_INET6) {
                    if (u->PrefixOrigin == IpPrefixOriginRouterAdvertisement)
                        proto->autoconf = 1;
                    if (u->PrefixOrigin == IpPrefixOriginDhcp)
                        proto->dhcp = 1;
                }
                /* addresses that come with DHCP or autoconfiguration, and
                 * link-local ones (fe80::/64, 169.254.0.0/16), are not part
                 * of the configuration, as with netcf */
                if (u->PrefixOrigin == IpPrefixOriginDhcp ||
                    u->PrefixOrigin == IpPrefixOriginRouterAdvertisement ||
                    u->PrefixOrigin == IpPrefixOriginWellKnown)
                    continue;
                win32IfaceProtoAddIP(proto, str, u->OnLinkPrefixLength);
                any = true;
            }
            if (proto->autoconf || proto->dhcp)
                any = true;

            for (gw = a->FirstGatewayAddress; gw; gw = gw->Next) {
                virSocketAddr addr = { 0 };

                if (gw->Address.lpSockaddr->sa_family != families[f])
                    continue;
                if (proto->dhcp || proto->autoconf)
                    break;
                memcpy(&addr.data, gw->Address.lpSockaddr, gw->Address.iSockaddrLength);
                addr.len = gw->Address.iSockaddrLength;
                proto->gateway = virSocketAddrFormat(&addr);
                break;
            }

            if (!any) {
                g_free(proto->family);
                g_free(proto->gateway);
                continue;
            }
            def->protos = g_renew(virInterfaceProtocolDef *, def->protos, def->nprotos + 1);
            def->protos[def->nprotos++] = g_steal_pointer(&proto);
        }
        break;
    }
}


static IP_ADAPTER_ADDRESSES *
win32IfaceAdapterAddresses(void)
{
    ULONG size = 16384;
    ULONG err;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    int tries;

    for (tries = 0; tries < 4; tries++) {
        addrs = g_realloc(addrs, size);
        err = GetAdaptersAddresses(AF_UNSPEC,
                                   GAA_FLAG_INCLUDE_GATEWAYS |
                                   GAA_FLAG_SKIP_ANYCAST |
                                   GAA_FLAG_SKIP_MULTICAST |
                                   GAA_FLAG_SKIP_DNS_SERVER,
                                   NULL, addrs, &size);
        if (err == NO_ERROR)
            return addrs;
        if (err != ERROR_BUFFER_OVERFLOW)
            break;
    }
    g_free(addrs);
    return NULL;
}


static bool
win32IfaceIsFilter(win32IfaceList *list, NET_IFINDEX index)
{
    ULONG i;

    for (i = 0; i < list->table->NumEntries; i++) {
        if (list->table->Table[i].InterfaceIndex == index)
            return list->table->Table[i].InterfaceAndOperStatusFlags.FilterInterface;
    }
    return false;
}


/*
 * The adapters below a multiplexor in the stack of interfaces: walking up
 * from each adapter, through the filters of its stack, to the multiplexor.
 * Through a layer that is not a filter, the bridge, the multiplexor is a
 * network bridge; without one, it is a team (a bond on Linux).
 */
static win32Iface **
win32IfaceGetMembers(win32IfaceList *list,
                     win32Iface *mux,
                     PMIB_IFSTACK_TABLE stack,
                     size_t *nmembers,
                     bool *bridge)
{
    win32Iface **members = NULL;
    size_t i;
    ULONG s;

    *nmembers = 0;
    *bridge = false;
    if (!stack)
        return NULL;

    for (i = 0; i < list->nifaces; i++) {
        win32Iface *member = &list->ifaces[i];
        NET_IFINDEX lower = member->index;
        bool through = false;
        int hops;

        if (member == mux || member->mux)
            continue;

        for (hops = 0; hops < 16; hops++) {
            bool up = false;

            for (s = 0; s < stack->NumEntries; s++) {
                if (stack->Table[s].LowerLayerInterfaceIndex != lower ||
                    stack->Table[s].HigherLayerInterfaceIndex == 0)
                    continue;
                lower = stack->Table[s].HigherLayerInterfaceIndex;
                up = true;
                break;
            }
            if (!up)
                break;
            if (lower == mux->index) {
                VIR_APPEND_ELEMENT(members, *nmembers, member);
                if (through)
                    *bridge = true;
                break;
            }
            if (!win32IfaceIsFilter(list, lower))
                through = true;
        }
    }
    return members;
}


static virInterfaceDef *
win32IfaceGetDef(win32IfaceList *list,
                 win32Iface *iface,
                 IP_ADAPTER_ADDRESSES *addrs,
                 PMIB_IFSTACK_TABLE stack,
                 int depth)
{
    g_autoptr(virInterfaceDef) def = g_new0(virInterfaceDef, 1);
    g_autofree win32Iface **members = NULL;
    size_t nmembers = 0;
    bool bridge = false;
    size_t i;

    def->startmode = VIR_INTERFACE_START_UNSPECIFIED;
    def->type = VIR_INTERFACE_TYPE_ETHERNET;
    def->name = g_strdup(iface->name);
    def->mac = g_strdup(iface->mac);
    def->mtu = iface->mtu;

    if (virNetDevGetLinkInfo(def->name, &def->lnk) < 0)
        return NULL;

    /* the members of a bridge or bond have no IP configuration */
    if (depth == 0 && addrs)
        win32IfaceGetProtocols(addrs, iface, def);

    if (!iface->mux || depth > 0)
        return g_steal_pointer(&def);

    members = win32IfaceGetMembers(list, iface, stack, &nmembers, &bridge);

    if (bridge) {
        /* the bridge of Windows has no spanning tree or forward delay
         * to set: neither is written */
        def->type = VIR_INTERFACE_TYPE_BRIDGE;
        def->data.bridge.stp = -1;
    } else {
        def->type = VIR_INTERFACE_TYPE_BOND;
    }

    for (i = 0; i < nmembers; i++) {
        virInterfaceDef *mdef = win32IfaceGetDef(list, members[i], addrs,
                                                 stack, depth + 1);

        if (!mdef)
            return NULL;
        if (bridge) {
            def->data.bridge.itf = g_renew(virInterfaceDef *, def->data.bridge.itf,
                                           def->data.bridge.nbItf + 1);
            def->data.bridge.itf[def->data.bridge.nbItf++] = mdef;
        } else {
            def->data.bond.itf = g_renew(virInterfaceDef *, def->data.bond.itf,
                                         def->data.bond.nbItf + 1);
            def->data.bond.itf[def->data.bond.nbItf++] = mdef;
        }
    }

    return g_steal_pointer(&def);
}


static char *
win32InterfaceGetXMLDesc(virInterfacePtr ifinfo,
                         unsigned int flags)
{
    win32IfaceList list;
    win32Iface *iface;
    g_autoptr(virInterfaceDef) def = NULL;
    g_autofree IP_ADAPTER_ADDRESSES *addrs = NULL;
    PMIB_IFSTACK_TABLE stack = NULL;
    char *xmlstr = NULL;

    virCheckFlags(VIR_INTERFACE_XML_INACTIVE, NULL);

    if (win32IfaceListGet(&list) < 0)
        return NULL;

    if (!(iface = win32IfaceListFind(&list, ifinfo->name))) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"), ifinfo->name);
        goto cleanup;
    }

    addrs = win32IfaceAdapterAddresses();
    if (GetIfStackTable(&stack) != NO_ERROR)
        stack = NULL;

    if (!(def = win32IfaceGetDef(&list, iface, addrs, stack, 0)))
        goto cleanup;

    if (virInterfaceGetXMLDescEnsureACL(ifinfo->conn, def) < 0)
        goto cleanup;

    xmlstr = virInterfaceDefFormat(def);

 cleanup:
    if (stack)
        FreeMibTable(stack);
    win32IfaceListClear(&list);
    return xmlstr;
}


static int
win32InterfaceIsActive(virInterfacePtr ifinfo)
{
    win32IfaceList list;
    win32Iface *iface;
    g_autoptr(virInterfaceDef) def = NULL;
    int status = -1;

    if (win32IfaceListGet(&list) < 0)
        return -1;

    if (!(iface = win32IfaceListFind(&list, ifinfo->name))) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"), ifinfo->name);
        goto cleanup;
    }

    def = win32IfaceMinimalDef(iface);
    if (virInterfaceIsActiveEnsureACL(ifinfo->conn, def) < 0)
        goto cleanup;

    status = iface->active ? 1 : 0;

 cleanup:
    win32IfaceListClear(&list);
    return status;
}


/* netsh interface set interface NAME admin=enabled|disabled */
static int
win32InterfaceSetAdmin(virInterfacePtr ifinfo,
                       bool enable)
{
    win32IfaceList list;
    win32Iface *iface;
    g_autoptr(virInterfaceDef) def = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;
    int status;
    int ret = -1;

    if (win32IfaceListGet(&list) < 0)
        return -1;

    if (!(iface = win32IfaceListFind(&list, ifinfo->name))) {
        virReportError(VIR_ERR_NO_INTERFACE,
                       _("couldn't find interface named '%1$s'"), ifinfo->name);
        goto cleanup;
    }

    def = win32IfaceMinimalDef(iface);
    if (enable) {
        if (virInterfaceCreateEnsureACL(ifinfo->conn, def) < 0)
            goto cleanup;
        if (iface->active) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("interface %1$s is already active"), ifinfo->name);
            goto cleanup;
        }
    } else {
        if (virInterfaceDestroyEnsureACL(ifinfo->conn, def) < 0)
            goto cleanup;
    }

    /* as ifup and ifdown: nothing to do for an adapter already enabled
     * (whose link may be down, as a TAP adapter without its guest), or
     * already disabled */
    if (iface->enabled == enable) {
        ret = 0;
        goto cleanup;
    }

    cmd = virCommandNewArgList("netsh", "interface", "set", "interface",
                               iface->name,
                               enable ? "admin=enabled" : "admin=disabled",
                               NULL);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;
    if (status != 0) {
        /* netsh writes its errors to stdout, in UTF-8 to a pipe on recent
         * Windows, in the OEM code page on older ones */
        g_autofree char *codeset = g_strdup_printf("CP%u", GetOEMCP());
        g_autofree char *msg = NULL;

        if (!output)
            output = g_strdup("");
        if (!g_utf8_validate(output, -1, NULL))
            msg = g_convert(output, -1, "UTF-8", codeset, NULL, NULL, NULL);

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot %1$s interface %2$s: %3$s"),
                       enable ? "enable" : "disable", ifinfo->name,
                       g_strstrip(msg ? msg : output));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    win32IfaceListClear(&list);
    return ret;
}


static int
win32InterfaceCreate(virInterfacePtr ifinfo,
                     unsigned int flags)
{
    virCheckFlags(0, -1);
    return win32InterfaceSetAdmin(ifinfo, true);
}


static int
win32InterfaceDestroy(virInterfacePtr ifinfo,
                      unsigned int flags)
{
    virCheckFlags(0, -1);
    return win32InterfaceSetAdmin(ifinfo, false);
}


static int
win32StateCleanup(void);

static int
win32StateInitialize(bool privileged,
                     const char *root,
                     bool monolithic G_GNUC_UNUSED,
                     virStateInhibitCallback callback G_GNUC_UNUSED,
                     void *opaque G_GNUC_UNUSED)
{
    int ret = VIR_DRV_STATE_INIT_ERROR;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    driver = g_new0(struct win32_iface_driver, 1);
    driver->lockFD = -1;

    if (privileged) {
        driver->stateDir = g_strdup_printf("%s/libvirt/interface", VIR_INSTALL_PATH(RUNSTATEDIR));
    } else {
        g_autofree char *rundir = NULL;

        rundir = virGetUserRuntimeDirectory();
        driver->stateDir = g_strdup_printf("%s/interface/run", rundir);
    }

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto cleanup;
    }

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto cleanup;

    driver->privileged = privileged;

    ret = VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    if (ret < 0)
        win32StateCleanup();
    return ret;
}

static int
win32StateCleanup(void)
{
    if (!driver)
        return -1;

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

    VIR_FREE(driver->stateDir);
    VIR_FREE(driver);
    return 0;
}


static virDrvOpenStatus
win32ConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth G_GNUC_UNUSED,
                 virConf *conf G_GNUC_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("interface state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!virConnectValidateURIPath(conn->uri->path,
                                   "interface",
                                   driver->privileged))
        return VIR_DRV_OPEN_ERROR;

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int win32ConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}


static int win32ConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int win32ConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int win32ConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static virInterfaceDriver win32IfaceDriver = {
    .name = "win32",
    .connectNumOfInterfaces = win32ConnectNumOfInterfaces,
    .connectListInterfaces = win32ConnectListInterfaces,
    .connectNumOfDefinedInterfaces = win32ConnectNumOfDefinedInterfaces,
    .connectListDefinedInterfaces = win32ConnectListDefinedInterfaces,
    .connectListAllInterfaces = win32ConnectListAllInterfaces,
    .interfaceLookupByName = win32InterfaceLookupByName,
    .interfaceLookupByMACString = win32InterfaceLookupByMACString,
    .interfaceIsActive = win32InterfaceIsActive,
    .interfaceGetXMLDesc = win32InterfaceGetXMLDesc,
    .interfaceCreate = win32InterfaceCreate,
    .interfaceDestroy = win32InterfaceDestroy,
};


static virHypervisorDriver win32HypervisorDriver = {
    .name = "interface",
    .connectOpen = win32ConnectOpen,
    .connectClose = win32ConnectClose,
    .connectIsEncrypted = win32ConnectIsEncrypted,
    .connectIsSecure = win32ConnectIsSecure,
    .connectIsAlive = win32ConnectIsAlive,
};


static virConnectDriver win32ConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "interface", NULL },
    .hypervisorDriver = &win32HypervisorDriver,
    .interfaceDriver = &win32IfaceDriver,
};


static virStateDriver interfaceStateDriver = {
    .name = "win32",
    .stateInitialize = win32StateInitialize,
    .stateCleanup = win32StateCleanup,
};

int
win32IfaceRegister(void)
{
    if (virRegisterConnectDriver(&win32ConnectDriver, false) < 0)
        return -1;
    if (virSetSharedInterfaceDriver(&win32IfaceDriver) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to register win32 interface driver"));
        return -1;
    }
    if (virRegisterStateDriver(&interfaceStateDriver) < 0)
        return -1;
    return 0;
}
