/*
 * bridge_driver_win32.c: Windows firewall of virtual networks
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * The host has an interface on a network only in forward modes route and
 * open (a Wintun adapter; nat and isolated networks reach the host through
 * libslirp, from the switch's own sockets).  The Windows firewall puts that
 * interface in the Public profile, which blocks what the guests open to the
 * host.  As firewalld's "libvirt" zone (and "libvirt-routed" with its
 * policy "libvirt-to-host") on Linux, libvirt then allows ICMP, ICMPv6,
 * DHCP, DHCPv6, DNS, SSH and TFTP from the network's subnets to the host:
 * inbound rules of the group "libvirt", named after the network.  Mode open
 * gets them only with a zone in the configuration, as on Linux.
 */

#include <config.h>

#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>

#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("network.bridge_driver_win32");

#define NETWORK_FW_GROUP "libvirt"

/* in no MinGW import library */
static const GUID networkFwCLSID_Policy2 = {
    0xe2b3c97f, 0x6ae1, 0x41ac, { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd }
};
static const GUID networkFwIID_Policy2 = {
    0x98325047, 0xc671, 0x4174, { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 }
};
static const GUID networkFwCLSID_Rule = {
    0x2c5bc43e, 0x3369, 0x4c33, { 0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4 }
};
static const GUID networkFwIID_Rule = {
    0xaf230d27, 0xbaba, 0x4e42, { 0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2 }
};

/* the services of the zone "libvirt" */
static const struct {
    const char *name;
    LONG protocol;
    const char *ports;
} networkFwServices[] = {
    { "icmp", 1, NULL },
    { "ipv6-icmp", 58, NULL },
    { "dhcp", 17, "67" },
    { "dhcpv6", 17, "547" },
    { "dns", 17, "53" },
    { "dns-tcp", 6, "53" },
    { "ssh", 6, "22" },
    { "tftp", 17, "69" },
};


static BSTR
networkFwBSTR(const char *str)
{
    g_autofree wchar_t *w = (wchar_t *)g_utf8_to_utf16(str, -1, NULL, NULL, NULL);

    return w ? SysAllocString(w) : NULL;
}


/* The rules of the firewall, in a COM apartment the caller leaves */
static INetFwRules *
networkFwRules(HRESULT *hr)
{
    INetFwPolicy2 *policy = NULL;
    INetFwRules *rules = NULL;

    if (FAILED(*hr = CoCreateInstance(&networkFwCLSID_Policy2, NULL, CLSCTX_INPROC_SERVER,
                                      &networkFwIID_Policy2, (void **)&policy)))
        return NULL;
    *hr = policy->lpVtbl->get_Rules(policy, &rules);
    policy->lpVtbl->Release(policy);
    return SUCCEEDED(*hr) ? rules : NULL;
}


/* Removes every rule named @name (names need not be unique) */
static void
networkFwRemoveName(INetFwRules *rules, const char *name)
{
    BSTR bname = networkFwBSTR(name);
    INetFwRule *rule;
    size_t i;

    if (!bname)
        return;
    for (i = 0; i < 16; i++) {
        if (FAILED(rules->lpVtbl->Item(rules, bname, &rule)))
            break;
        rule->lpVtbl->Release(rule);
        if (FAILED(rules->lpVtbl->Remove(rules, bname)))
            break;
    }
    SysFreeString(bname);
}


static char *
networkFwRuleName(const char *network, const char *service)
{
    return g_strdup_printf("libvirt %s: %s", network, service);
}


/* The subnets of the network and of its static routes, as the firewall
 * reads remote addresses */
static char *
networkFwSubnets(virNetworkDef *def)
{
    g_autoptr(GString) out = g_string_new(NULL);
    virNetworkIPDef *ipdef;
    virNetDevIPRoute *route;
    size_t i;

    for (i = 0; (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i)); i++) {
        int prefix = virNetworkIPDefPrefix(ipdef);
        virSocketAddr net;
        g_autofree char *str = NULL;

        if (prefix < 0 ||
            virSocketAddrMaskByPrefix(&ipdef->address, prefix, &net) < 0 ||
            !(str = virSocketAddrFormat(&net)))
            continue;
        g_string_append_printf(out, "%s%s/%d", out->len ? "," : "", str, prefix);
    }
    for (i = 0; (route = virNetworkDefGetRouteByIndex(def, AF_UNSPEC, i)); i++) {
        g_autofree char *str = virSocketAddrFormat(virNetDevIPRouteGetAddress(route));

        if (str)
            g_string_append_printf(out, "%s%s/%u", out->len ? "," : "", str,
                                   virNetDevIPRouteGetPrefix(route));
    }
    if (!out->len)
        return NULL;
    return g_string_free(g_steal_pointer(&out), FALSE);
}


static int
networkFwAddRule(INetFwRules *rules, virNetworkDef *def, size_t svc,
                 const char *subnets)
{
    g_autofree char *name = networkFwRuleName(def->name, networkFwServices[svc].name);
    g_autofree char *desc = g_strdup_printf("Guests of the libvirt network %s to the host (zone libvirt)",
                                            def->name);
    BSTR bname = networkFwBSTR(name);
    BSTR bdesc = networkFwBSTR(desc);
    BSTR bgroup = networkFwBSTR(NETWORK_FW_GROUP);
    BSTR bremote = networkFwBSTR(subnets);
    BSTR bports = networkFwServices[svc].ports ? networkFwBSTR(networkFwServices[svc].ports) : NULL;
    INetFwRule *rule = NULL;
    HRESULT hr;

    networkFwRemoveName(rules, name);

    if (!bname || !bdesc || !bgroup || !bremote ||
        (networkFwServices[svc].ports && !bports)) {
        hr = E_OUTOFMEMORY;
    } else if (SUCCEEDED(hr = CoCreateInstance(&networkFwCLSID_Rule, NULL, CLSCTX_INPROC_SERVER,
                                               &networkFwIID_Rule, (void **)&rule)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Name(rule, bname)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Description(rule, bdesc)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Grouping(rule, bgroup)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Protocol(rule, networkFwServices[svc].protocol)) &&
               (!bports || SUCCEEDED(hr = rule->lpVtbl->put_LocalPorts(rule, bports))) &&
               SUCCEEDED(hr = rule->lpVtbl->put_RemoteAddresses(rule, bremote)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Direction(rule, NET_FW_RULE_DIR_IN)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Action(rule, NET_FW_ACTION_ALLOW)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Profiles(rule, NET_FW_PROFILE2_ALL)) &&
               SUCCEEDED(hr = rule->lpVtbl->put_Enabled(rule, VARIANT_TRUE))) {
        hr = rules->lpVtbl->Add(rules, rule);
    }

    if (rule)
        rule->lpVtbl->Release(rule);
    SysFreeString(bname);
    SysFreeString(bdesc);
    SysFreeString(bgroup);
    SysFreeString(bremote);
    SysFreeString(bports);

    if (FAILED(hr)) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to add the Windows firewall rule '%1$s': error 0x%2$lx%3$s"),
                       name, (unsigned long)hr,
                       hr == E_ACCESSDENIED ? _(" (it takes administrator rights)") : "");
        return -1;
    }
    return 0;
}


static void
networkFwRemoveNetwork(INetFwRules *rules, const char *network)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(networkFwServices); i++) {
        g_autofree char *name = networkFwRuleName(network, networkFwServices[i].name);

        networkFwRemoveName(rules, name);
    }
}


/* Removes the rules of the group "libvirt": those of networks that were
 * active when the host stopped stay in the firewall's store */
static void
networkFwRemoveAll(INetFwRules *rules)
{
    g_autoptr(GPtrArray) names = g_ptr_array_new_with_free_func(g_free);
    IUnknown *unk = NULL;
    IEnumVARIANT *it = NULL;
    VARIANT var;
    ULONG fetched;
    size_t i;

    if (FAILED(rules->lpVtbl->get__NewEnum(rules, &unk)))
        return;
    if (FAILED(unk->lpVtbl->QueryInterface(unk, &IID_IEnumVARIANT, (void **)&it))) {
        unk->lpVtbl->Release(unk);
        return;
    }
    unk->lpVtbl->Release(unk);

    VariantInit(&var);
    while (it->lpVtbl->Next(it, 1, &var, &fetched) == S_OK && fetched == 1) {
        INetFwRule *rule = NULL;
        BSTR group = NULL;
        BSTR name = NULL;

        if (V_VT(&var) == VT_DISPATCH && V_DISPATCH(&var) &&
            SUCCEEDED(V_DISPATCH(&var)->lpVtbl->QueryInterface(V_DISPATCH(&var),
                                                               &networkFwIID_Rule,
                                                               (void **)&rule))) {
            if (SUCCEEDED(rule->lpVtbl->get_Grouping(rule, &group)) && group &&
                wcscmp(group, L"" NETWORK_FW_GROUP) == 0 &&
                SUCCEEDED(rule->lpVtbl->get_Name(rule, &name)) && name &&
                wcsncmp(name, L"libvirt ", 8) == 0)
                g_ptr_array_add(names, g_utf16_to_utf8((gunichar2 *)name, -1, NULL, NULL, NULL));
            SysFreeString(group);
            SysFreeString(name);
            rule->lpVtbl->Release(rule);
        }
        VariantClear(&var);
    }
    it->lpVtbl->Release(it);

    for (i = 0; i < names->len; i++) {
        if (g_ptr_array_index(names, i))
            networkFwRemoveName(rules, g_ptr_array_index(names, i));
    }
}


void networkPreReloadFirewallRules(virNetworkDriverState *driver G_GNUC_UNUSED,
                                   bool startup,
                                   bool force G_GNUC_UNUSED)
{
    HRESULT init;
    HRESULT hr;
    INetFwRules *rules;

    /* the rules of the active networks are added again after this */
    if (!startup)
        return;
    init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if ((rules = networkFwRules(&hr))) {
        networkFwRemoveAll(rules);
        rules->lpVtbl->Release(rules);
    }
    if (SUCCEEDED(init))
        CoUninitialize();
}


void networkPostReloadFirewallRules(bool startup G_GNUC_UNUSED)
{
}


int networkCheckRouteCollision(virNetworkDef *def G_GNUC_UNUSED)
{
    return 0;
}


int networkAddFirewallRules(virNetworkDef *def,
                            virFirewallBackend firewallBackend,
                            virFirewall **fwRemoval G_GNUC_UNUSED)
{
    g_autofree char *subnets = NULL;
    INetFwRules *rules;
    HRESULT init;
    HRESULT hr;
    size_t i;
    int ret = 0;

    if (firewallBackend != VIR_FIREWALL_BACKEND_NONE) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Firewall backend '%1$s' not available on this platform"),
                       virFirewallBackendTypeToString(firewallBackend));
        return -1;
    }

    /* the zones of libvirt are those Windows has rules for */
    if (def->bridgeZone &&
        STRNEQ(def->bridgeZone, "libvirt") && STRNEQ(def->bridgeZone, "libvirt-routed")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("zone %1$s requested for network %2$s but Windows has only the zones 'libvirt' and 'libvirt-routed'"),
                       def->bridgeZone, def->name);
        return -1;
    }

    if (def->forward.type != VIR_NETWORK_FORWARD_ROUTE &&
        !(def->forward.type == VIR_NETWORK_FORWARD_OPEN && def->bridgeZone))
        return 0;
    if (!(subnets = networkFwSubnets(def)))
        return 0;

    VIR_DEBUG("Adding Windows firewall rules for network '%s' from %s", def->name, subnets);

    init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!(rules = networkFwRules(&hr))) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to open the Windows firewall: error 0x%1$lx"),
                       (unsigned long)hr);
        ret = -1;
    } else {
        for (i = 0; i < G_N_ELEMENTS(networkFwServices) && ret == 0; i++)
            ret = networkFwAddRule(rules, def, i, subnets);
        if (ret < 0)
            networkFwRemoveNetwork(rules, def->name);
        rules->lpVtbl->Release(rules);
    }
    if (SUCCEEDED(init))
        CoUninitialize();
    return ret;
}


void
networkRemoveFirewallRules(virNetworkObj *obj,
                           bool unsetZone G_GNUC_UNUSED)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    INetFwRules *rules;
    HRESULT init;
    HRESULT hr;

    init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if ((rules = networkFwRules(&hr))) {
        networkFwRemoveNetwork(rules, def->name);
        rules->lpVtbl->Release(rules);
    }
    if (SUCCEEDED(init))
        CoUninitialize();
}
