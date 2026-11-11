/*
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

#include <config.h>

/* before configmake.h: objidl.h (setupapi.h) has a type DATADIR */
#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <winsock2.h>
# include <ws2tcpip.h>
# include <windows.h>
# include <setupapi.h>
# include <objbase.h>
# include <netcon.h>
# include <iphlpapi.h>
#endif

#include "virmacaddr.h"
#include "virnetdevtap.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevmidonet.h"
#include "virnetdevopenvswitch.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "configmake.h"

#include <unistd.h>
#include <sys/types.h>
#ifndef WIN32
# include <sys/ioctl.h>
#endif
#ifdef WITH_NET_IF_H
# include <net/if.h>
#endif
#include <fcntl.h>
#ifdef __linux__
# include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */
#elif defined(__FreeBSD__)
# include <net/if_mib.h>
# include <sys/sysctl.h>
#endif
#if defined(WITH_GETIFADDRS) && defined(AF_LINK)
# include <ifaddrs.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevtap");

/**
 * virNetDevTapGetName:
 * @tapfd: a tun/tap file descriptor
 * @ifname: a pointer that will receive the interface name
 *
 * Retrieve the interface name given a file descriptor for a tun/tap
 * interface.
 *
 * Returns 0 if the interface name is successfully queried, -1 otherwise
 */
int
virNetDevTapGetName(int tapfd G_GNUC_UNUSED, char **ifname G_GNUC_UNUSED)
{
#ifdef TUNGETIFF
    struct ifreq ifr;

    if (ioctl(tapfd, TUNGETIFF, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query tap interface name"));
        return -1;
    }

    *ifname = g_strdup(ifr.ifr_name);
    return 0;
#else
    return -1;
#endif
}

/**
 * virNetDevTapGetRealDeviceName:
 * @ifname: the interface name
 *
 * Lookup real interface name (i.e. name of the device entry in /dev),
 * because e.g. on FreeBSD if we rename tap device to vnetN its device
 * entry still remains unchanged (/dev/tapX), but bhyve needs a name
 * that matches /dev entry.
 *
 * Returns the proper interface name or NULL if no corresponding interface
 * found.
 */
char*
virNetDevTapGetRealDeviceName(char *ifname G_GNUC_UNUSED)
{
#ifdef IFDATA_DRIVERNAME
    int ifindex = 0;
    int name[6];
    size_t len = 0;
    char *ret = NULL;

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        virReportSystemError(errno,
                             _("Unable to get interface index for '%1$s'"),
                             ifname);
        return NULL;
    }

    name[0] = CTL_NET;
    name[1] = PF_LINK;
    name[2] = NETLINK_GENERIC;
    name[3] = IFMIB_IFDATA;
    name[4] = ifindex;
    name[5] = IFDATA_DRIVERNAME;

    if (sysctl(name, 6, NULL, &len, 0, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to get driver name for '%1$s'"),
                             ifname);
        return NULL;
    }

    ret = g_new0(char, len);

    if (sysctl(name, 6, ret, &len, 0, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to get driver name for '%1$s'"),
                             ifname);
        VIR_FREE(ret);
        return NULL;
    }

    return ret;
#else
    return NULL;
#endif
}


#ifdef TUNSETIFF
/**
 * virNetDevTapCreate:
 * @ifname: the interface name
 * @tunpath: path to the tun device (if NULL, /dev/net/tun is used)
 * @tapfds: array of file descriptors return value for the new tap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @flags: OR of virNetDevTapCreateFlags. Only the following flags are
 *         recognized:
 *
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *   VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING
 *     - The device creation does not fail if @ifname already exists
 *
 * Creates a tap interface. The caller must use virNetDevTapDelete to
 * remove a persistent TAP device when it is no longer needed. In case
 * @tapfdSize is greater than one, multiqueue extension is requested
 * from kernel.
 *
 * Returns 0 in case of success or -1 on failure.
 */
int virNetDevTapCreate(char **ifname,
                       const char *tunpath,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags)
{
    size_t i = 0;
    int rc;
    int ret = -1;
    int fd = -1;

    /* if ifname is empty, then auto-generate a name for the new
     * device (the kernel could do this for us, but has a bad habit of
     * immediately re-using names that have just been released, which
     * can lead to race conditions).  if ifname is just a
     * user-provided name, virNetDevGenerateName leaves it
     * unchanged. */
    rc = virNetDevGenerateName(ifname, VIR_NET_DEV_GEN_NAME_VNET);
    if (rc < 0)
        return -1;

    if (rc > 0 &&
        !(flags & VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING)) {
        rc = virNetDevExists(*ifname);

        if (rc < 0) {
            return -1;
        } else if (rc > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("The %1$s interface already exists"),
                           *ifname);
            return -1;
        }
    }

    if (!tunpath)
        tunpath = "/dev/net/tun";

    for (i = 0; i < tapfdSize; i++) {
        struct ifreq ifr = { 0 };

        if ((fd = open(tunpath, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %1$s, is tun module loaded?"),
                                 tunpath);
            goto cleanup;
        }

        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        /* If tapfdSize is greater than one, request multiqueue */
        if (tapfdSize > 1)
            ifr.ifr_flags |= IFF_MULTI_QUEUE;

        if (flags &  VIR_NETDEV_TAP_CREATE_VNET_HDR)
            ifr.ifr_flags |= IFF_VNET_HDR;

        if (virStrcpyStatic(ifr.ifr_name, *ifname) < 0) {
            virReportSystemError(ERANGE,
                                 _("Network interface name '%1$s' is too long"),
                                 *ifname);
            goto cleanup;

        }

        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            if (flags & VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING) {
                if (tapfdSize > 1) {
                    virReportSystemError(errno,
                                         _("Unable to create multiple fds for tap device %1$s (maybe existing device was created without multi_queue flag)"),
                                         *ifname);
                } else {
                    virReportSystemError(errno,
                                         _("Unable to set tap device %1$s (maybe existing device was created with multi_queue flag but device XML lacks 'queues' greater than one)"),
                                         *ifname);
                }
            } else {
                virReportSystemError(errno,
                                     _("Unable to create tap device %1$s"),
                                     *ifname);
            }
            goto cleanup;
        }

        if (i == 0) {
            /* In case we are looping more than once, set other
             * TAPs to have the same name */
            VIR_FREE(*ifname);
            *ifname = g_strdup(ifr.ifr_name);
        }

        if ((flags & VIR_NETDEV_TAP_CREATE_PERSIST) &&
            ioctl(fd, TUNSETPERSIST, 1) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set tap device %1$s to persistent"),
                                 *ifname);
            goto cleanup;
        }
        tapfd[i] = fd;
    }

    VIR_INFO("created device: '%s'", *ifname);
    ret = 0;

 cleanup:
    if (ret < 0) {
        VIR_FORCE_CLOSE(fd);
        while (i--)
            VIR_FORCE_CLOSE(tapfd[i]);
    }

    return ret;
}


int virNetDevTapDelete(const char *ifname,
                       const char *tunpath)
{
    struct ifreq try = { 0 };
    int fd;
    int ret = -1;

    if (!tunpath)
        tunpath = "/dev/net/tun";

    if ((fd = open(tunpath, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %1$s, is tun module loaded?"),
                             tunpath);
        return -1;
    }

    try.ifr_flags = IFF_TAP|IFF_NO_PI;

    if (virStrcpyStatic(try.ifr_name, ifname) < 0) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%1$s' is too long"),
                             ifname);
        goto cleanup;
    }

    if (ioctl(fd, TUNSETIFF, &try) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to associate TAP device"));
        goto cleanup;
    }

    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to make TAP device non-persistent"));
        goto cleanup;
    }

    VIR_INFO("delete device: '%s'", ifname);
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(SIOCIFCREATE2) && defined(SIOCIFDESTROY) && defined(IF_MAXUNIT)
int virNetDevTapCreate(char **ifname,
                       const char *tunpath G_GNUC_UNUSED,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags G_GNUC_UNUSED)
{
    int s;
    struct ifreq ifr;
    int ret = -1;
    bool created = false;

    if (tapfdSize > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Multiqueue devices are not supported on this system"));
        return -1;
    }

    /* auto-generate an unused name for the new device (this
     * is NOP if a name has been provided)
     */
    if (virNetDevGenerateName(ifname, VIR_NET_DEV_GEN_NAME_VNET) < 0)
        return -1;

    /* As FreeBSD determines interface type by name,
     * we have to create 'tap' interface first and
     * then rename it to 'vnet'
     */
    if ((s = virNetDevSetupControl("tap", &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create tap device"));
        VIR_FORCE_CLOSE(s);
        return -1;
    }

    created = true;

    if (tapfd) {
        g_autofree char *dev_path = NULL;
        dev_path = g_strdup_printf("/dev/%s", ifr.ifr_name);

        if ((*tapfd = open(dev_path, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %1$s"),
                                 dev_path);
            goto cleanup;
        }
    }

    if (virNetDevSetName(ifr.ifr_name, *ifname) == -1)
        goto cleanup;


    ret = 0;
 cleanup:
    if (ret < 0 && created) {
        virErrorPtr err;

        virErrorPreserveLast(&err);

        if (tapfd)
            VIR_FORCE_CLOSE(*tapfd);

        ignore_value(virNetDevTapDelete(ifr.ifr_name, NULL));
        virErrorRestore(&err);
    }

    VIR_FORCE_CLOSE(s);

    return ret;
}

int virNetDevTapDelete(const char *ifname,
                       const char *tunpath G_GNUC_UNUSED)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    if ((s = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove tap device %1$s"),
                             ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(s);
    return ret;
}

#elif defined(WIN32)
/*
 * Windows: a TAP device is an adapter of the TAP-Windows6 driver of OpenVPN
 * (hardware id root\tap0901), named by its connection name, which QEMU opens
 * by that name (-netdev tap,ifname=NAME) rather than by a file descriptor.
 * As a TAP device on Linux, a managed one is created for the interface and
 * named vnetN, then deleted: a root enumerated device of the driver, made
 * as devcon does, which needs the driver in the driver store
 * (pnputil /add-driver OemVista.inf /install) and administrator rights.
 */

# define VIR_TAP_WIN32_CLASS L"SYSTEM\\CurrentControlSet\\Control\\Class\\" \
                             L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
# define VIR_TAP_WIN32_NETWORK L"SYSTEM\\CurrentControlSet\\Control\\Network\\" \
                               L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
# define VIR_TAP_WIN32_HWID L"root\\tap0901"

static const GUID virNetDevTapWin32NetClass = {
    0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};


static char *
virNetDevTapWin32RegString(HKEY key, const wchar_t *subkey, const wchar_t *value)
{
    wchar_t buf[512];
    DWORD size = sizeof(buf) - sizeof(wchar_t);
    DWORD type;
    HKEY k;
    LONG rc;

    if (RegOpenKeyExW(key, subkey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return NULL;
    rc = RegQueryValueExW(k, value, NULL, &type, (BYTE *)buf, &size);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS || type != REG_SZ)
        return NULL;
    buf[size / sizeof(wchar_t)] = 0;
    return g_utf16_to_utf8((gunichar2 *)buf, -1, NULL, NULL, NULL);
}


/* The connection name of the network adapter @guid */
static char *
virNetDevTapWin32ConnectionName(const char *guid)
{
    g_autofree char *path = g_strdup_printf("%ls\\%s\\Connection",
                                            VIR_TAP_WIN32_NETWORK, guid);
    g_autofree wchar_t *wpath = (wchar_t *)g_utf8_to_utf16(path, -1, NULL, NULL, NULL);

    return wpath ? virNetDevTapWin32RegString(HKEY_LOCAL_MACHINE, wpath, L"Name") : NULL;
}


/*
 * The TAP-Windows adapter named @name: returns 1 with its NetCfgInstanceId
 * in @guid (if not NULL), 0 when no TAP adapter has that name
 */
static int
virNetDevTapWin32Find(const char *name, char **guid)
{
    HKEY cls;
    DWORD i;
    int ret = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, VIR_TAP_WIN32_CLASS, 0,
                      KEY_ENUMERATE_SUB_KEYS, &cls) != ERROR_SUCCESS)
        return 0;

    for (i = 0; ret == 0; i++) {
        wchar_t sub[64];
        DWORD len = G_N_ELEMENTS(sub);
        g_autofree char *component = NULL;
        g_autofree char *id = NULL;
        g_autofree char *conn = NULL;

        if (RegEnumKeyExW(cls, i, sub, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (!(component = virNetDevTapWin32RegString(cls, sub, L"ComponentId")) ||
            (g_ascii_strcasecmp(component, "tap0901") != 0 &&
             g_ascii_strcasecmp(component, "root\\tap0901") != 0) ||
            !(id = virNetDevTapWin32RegString(cls, sub, L"NetCfgInstanceId")) ||
            !(conn = virNetDevTapWin32ConnectionName(id)))
            continue;
        if (STREQ(conn, name)) {
            if (guid)
                *guid = g_steal_pointer(&id);
            ret = 1;
        }
    }
    RegCloseKey(cls);
    return ret;
}


/*
 * The connection name of an adapter is renamed as Explorer does, by the
 * network connections manager (writing the registry value is not enough:
 * Windows keeps its own name).  These GUIDs are in no MinGW library.
 */
static const GUID virNetDevTapWin32CLSID_ConnectionManager = {
    0xba126ad1, 0x2166, 0x11d1, { 0xb1, 0xd0, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e }
};
static const GUID virNetDevTapWin32IID_INetConnectionManager = {
    0xc08956a2, 0x1cd3, 0x11d1, { 0xb1, 0xc5, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e }
};


/* 1 renamed, 0 the connection is not there (yet), -1 error in @hr */
static int
virNetDevTapWin32RenameConnection(const GUID *id, const wchar_t *wname, HRESULT *hr)
{
    INetConnectionManager *mgr = NULL;
    IEnumNetConnection *conns = NULL;
    INetConnection *conn = NULL;
    ULONG fetched;
    int ret = 0;

    if (FAILED(*hr = CoCreateInstance(&virNetDevTapWin32CLSID_ConnectionManager, NULL,
                                      CLSCTX_ALL, &virNetDevTapWin32IID_INetConnectionManager,
                                      (void **)&mgr)))
        return -1;
    if (FAILED(*hr = mgr->lpVtbl->EnumConnections(mgr, NCME_DEFAULT, &conns))) {
        mgr->lpVtbl->Release(mgr);
        return -1;
    }
    while (ret == 0 && conns->lpVtbl->Next(conns, 1, &conn, &fetched) == S_OK && fetched == 1) {
        NETCON_PROPERTIES *props = NULL;

        if (SUCCEEDED(conn->lpVtbl->GetProperties(conn, &props)) && props) {
            if (IsEqualGUID(&props->guidId, id))
                ret = SUCCEEDED(*hr = conn->lpVtbl->Rename(conn, wname)) ? 1 : -1;
            CoTaskMemFree(props->pszwName);
            CoTaskMemFree(props->pszwDeviceName);
            CoTaskMemFree(props);
        }
        conn->lpVtbl->Release(conn);
    }
    conns->lpVtbl->Release(conns);
    mgr->lpVtbl->Release(mgr);
    return ret;
}


typedef DWORD (WINAPI *virNetDevTapWin32NciSetConnectionNameFunc)(const GUID *, const wchar_t *);

/*
 * Name the adapter @guid, once Windows has made its connection: by
 * NciSetConnectionName of nci.dll as Wintun does, else by the network
 * connections manager as Explorer does
 */
static int
virNetDevTapWin32SetConnectionName(const char *guid, const char *name)
{
    g_autofree wchar_t *wguid = (wchar_t *)g_utf8_to_utf16(guid, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wname = (wchar_t *)g_utf8_to_utf16(name, -1, NULL, NULL, NULL);
    HMODULE nci = LoadLibraryExW(L"nci.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    virNetDevTapWin32NciSetConnectionNameFunc setName = NULL;
    HRESULT init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    DWORD nciErr = ERROR_PROC_NOT_FOUND;
    HRESULT hr = S_OK;
    GUID id;
    size_t i;
    int rc = 0;

    if (nci)
        setName = (virNetDevTapWin32NciSetConnectionNameFunc)(void (*)(void))
            GetProcAddress(nci, "NciSetConnectionName");

    if (!wguid || !wname || FAILED(CLSIDFromString(wguid, &id))) {
        rc = -1;
    } else {
        for (i = 0; i < 100 && rc != 1; i++) {
            if (setName && (nciErr = setName(&id, wname)) == ERROR_SUCCESS) {
                rc = 1;
                break;
            }
            if ((rc = virNetDevTapWin32RenameConnection(&id, wname, &hr)) != 1)
                g_usleep(100 * 1000);
        }
    }
    if (SUCCEEDED(init))
        CoUninitialize();
    if (nci)
        FreeLibrary(nci);

    if (rc != 1) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to name the TAP adapter %1$s (nci 0x%2$lx, connection manager 0x%3$lx%4$s)"),
                       name, nciErr, (unsigned long)hr,
                       rc == 0 ? _(", no connection") : "");
        return -1;
    }
    return 0;
}


static void
virNetDevTapWin32ReportLastError(const char *what)
{
    DWORD err = GetLastError();

    virReportError(VIR_ERR_SYSTEM_ERROR,
                   _("%1$s: Windows error 0x%2$lx%3$s"), what, err,
                   err == ERROR_ACCESS_DENIED ?
                   _(" (TAP devices take administrator rights)") : "");
}


/* A new TAP-Windows device, its NetCfgInstanceId in @guid */
static int
virNetDevTapWin32CreateDevice(char **guid)
{
    static const wchar_t hwid[] = VIR_TAP_WIN32_HWID L"\0";
    HDEVINFO set;
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    SP_DRVINFO_DATA_W drv = { .cbSize = sizeof(drv) };
    SP_DRVINFO_DATA_W best = { .cbSize = sizeof(best) };
    bool found = false;
    bool registered = false;
    DWORD i;
    int ret = -1;

    if ((set = SetupDiCreateDeviceInfoList(&virNetDevTapWin32NetClass, NULL)) ==
        INVALID_HANDLE_VALUE) {
        virNetDevTapWin32ReportLastError(_("Unable to create a TAP device"));
        return -1;
    }

    if (!SetupDiCreateDeviceInfoW(set, L"Net", &virNetDevTapWin32NetClass, NULL, NULL,
                                  DICD_GENERATE_ID, &dev) ||
        !SetupDiSetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID,
                                           (const BYTE *)hwid, sizeof(hwid))) {
        virNetDevTapWin32ReportLastError(_("Unable to create a TAP device"));
        goto cleanup;
    }

    /* the newest TAP-Windows driver of the driver store */
    if (SetupDiBuildDriverInfoList(set, &dev, SPDIT_COMPATDRIVER)) {
        for (i = 0; SetupDiEnumDriverInfoW(set, &dev, SPDIT_COMPATDRIVER, i, &drv); i++) {
            if (!found || drv.DriverVersion > best.DriverVersion) {
                best = drv;
                found = true;
            }
        }
    }
    if (!found) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TAP devices need the TAP-Windows6 driver of OpenVPN in the driver store (pnputil /add-driver OemVista.inf /install)"));
        goto cleanup;
    }

    if (!SetupDiSetSelectedDriverW(set, &dev, &best) ||
        !SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, &dev)) {
        virNetDevTapWin32ReportLastError(_("Unable to create a TAP device"));
        goto cleanup;
    }
    registered = true;
    SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, set, &dev);
    SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, set, &dev);
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, set, &dev)) {
        virNetDevTapWin32ReportLastError(_("Unable to install the TAP device"));
        goto cleanup;
    }

    /* its adapter: the class installer writes NetCfgInstanceId */
    for (i = 0; i < 50 && !*guid; i++) {
        HKEY k = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0, DIREG_DRV,
                                      KEY_QUERY_VALUE);

        if (k != INVALID_HANDLE_VALUE) {
            *guid = virNetDevTapWin32RegString(k, NULL, L"NetCfgInstanceId");
            RegCloseKey(k);
        }
        if (!*guid)
            g_usleep(100 * 1000);
    }
    if (!*guid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The TAP device got no network adapter"));
        goto cleanup;
    }
    ret = 0;

 cleanup:
    if (ret < 0 && registered)
        SetupDiCallClassInstaller(DIF_REMOVE, set, &dev);
    SetupDiDestroyDeviceInfoList(set);
    return ret;
}


/* Remove the TAP-Windows device of the adapter @guid */
static int
virNetDevTapWin32RemoveDevice(const char *guid)
{
    HDEVINFO set = SetupDiGetClassDevsW(&virNetDevTapWin32NetClass, NULL, NULL, 0);
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    DWORD i;
    int ret = -1;

    if (set == INVALID_HANDLE_VALUE) {
        virNetDevTapWin32ReportLastError(_("Unable to delete the TAP device"));
        return -1;
    }
    for (i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        HKEY k = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0, DIREG_DRV,
                                      KEY_QUERY_VALUE);
        g_autofree char *id = NULL;
        g_autofree char *component = NULL;

        if (k == INVALID_HANDLE_VALUE)
            continue;
        id = virNetDevTapWin32RegString(k, NULL, L"NetCfgInstanceId");
        component = virNetDevTapWin32RegString(k, NULL, L"ComponentId");
        RegCloseKey(k);
        /* only ever a TAP-Windows device */
        if (!id || g_ascii_strcasecmp(id, guid) != 0 || !component ||
            (g_ascii_strcasecmp(component, "tap0901") != 0 &&
             g_ascii_strcasecmp(component, "root\\tap0901") != 0))
            continue;
        if (!SetupDiCallClassInstaller(DIF_REMOVE, set, &dev))
            virNetDevTapWin32ReportLastError(_("Unable to delete the TAP device"));
        else
            ret = 0;
        break;
    }
    if (ret < 0 && !virGetLastError())
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No TAP device for the adapter %1$s"), guid);
    SetupDiDestroyDeviceInfoList(set);
    return ret;
}


int virNetDevTapCreate(char **ifname,
                       const char *tunpath G_GNUC_UNUSED,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags)
{
    g_autofree char *guid = NULL;
    size_t i;

    /* QEMU opens the adapter itself, by its name */
    for (i = 0; i < tapfdSize; i++)
        tapfd[i] = -1;

    if (*ifname && !strchr(*ifname, '%')) {
        if (virNetDevTapWin32Find(*ifname, NULL) == 1)
            return 0;
        if (flags & VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("No TAP-Windows adapter named '%1$s'"), *ifname);
            return -1;
        }
    } else {
        g_clear_pointer(ifname, g_free);
        if (virNetDevGenerateName(ifname, VIR_NET_DEV_GEN_NAME_VNET) < 0)
            return -1;
    }

    if (virNetDevTapWin32CreateDevice(&guid) < 0)
        return -1;

    if (virNetDevTapWin32SetConnectionName(guid, *ifname) < 0) {
        ignore_value(virNetDevTapWin32RemoveDevice(guid));
        return -1;
    }
    VIR_DEBUG("created TAP adapter %s (%s)", *ifname, guid);
    return 0;
}


int virNetDevTapDelete(const char *ifname,
                       const char *tunpath G_GNUC_UNUSED)
{
    g_autofree char *guid = NULL;

    if (virNetDevTapWin32Find(ifname, &guid) != 1) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No TAP-Windows adapter named '%1$s'"), ifname);
        return -1;
    }
    return virNetDevTapWin32RemoveDevice(guid);
}
#else
int virNetDevTapCreate(char **ifname G_GNUC_UNUSED,
                       const char *tunpath G_GNUC_UNUSED,
                       int *tapfd G_GNUC_UNUSED,
                       size_t tapfdSize G_GNUC_UNUSED,
                       unsigned int flags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to create TAP devices on this platform"));
    return -1;
}
int virNetDevTapDelete(const char *ifname G_GNUC_UNUSED,
                       const char *tunpath G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to delete TAP devices on this platform"));
    return -1;
}
#endif


/**
 * virNetDevTapAttachBridge:
 * @tapname: the tap interface name (or name template)
 * @brname: the bridge name
 * @macaddr: desired MAC address
 * @virtPortProfile: bridge/port specific configuration
 * @virtVlan: vlan tag info
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 *
 * This attaches an existing tap device (@tapname) to a bridge
 * (@brname).
 *
 * Returns 0 in case of success or -1 on failure
 */
int
virNetDevTapAttachBridge(const char *tapname,
                         const char *brname,
                         const virMacAddr *macaddr,
                         const unsigned char *vmuuid,
                         const virNetDevVPortProfile *virtPortProfile,
                         const virNetDevVlan *virtVlan,
                         virTristateBool isolatedPort,
                         unsigned int mtu,
                         unsigned int *actualMTU)
{
    /* If an MTU is specified for the new device, set it before
     * attaching the device to the bridge, as it may affect the MTU of
     * the bridge (in particular if it is the first device attached to
     * the bridge, or if it is smaller than the current MTU of the
     * bridge). If MTU isn't specified for the new device (i.e. 0),
     * we need to set the interface MTU to the current MTU of the
     * bridge (to avoid inadvertently changing the bridge's MTU).
     */
    if (mtu > 0) {
        if (virNetDevSetMTU(tapname, mtu) < 0)
            return -1;
    } else {
        if (virNetDevSetMTUFromDevice(tapname, brname) < 0)
            return -1;
    }
    if (actualMTU) {
        int retMTU = virNetDevGetMTU(tapname);

        if (retMTU < 0)
            return -1;

        *actualMTU = retMTU;
    }


    if (virtPortProfile) {
        if (virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
            if (virNetDevMidonetBindPort(tapname, virtPortProfile) < 0)
                return -1;
        } else if (virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            if (virNetDevOpenvswitchAddPort(brname, tapname, macaddr, vmuuid,
                                            virtPortProfile, virtVlan) < 0)
                return -1;
        }
    } else {
        if (virNetDevBridgeAddPort(brname, tapname, virtVlan) < 0)
            return -1;

        if (isolatedPort == VIR_TRISTATE_BOOL_YES &&
            virNetDevBridgePortSetIsolated(brname, tapname, true) < 0) {
            virErrorPtr err;

            virErrorPreserveLast(&err);
            ignore_value(virNetDevBridgeRemovePort(brname, tapname));
            virErrorRestore(&err);
            return -1;
        }
    }

    return 0;
}


/**
 * virNetDevTapReattachBridge:
 * @tapname: the tap interface name (or name template)
 * @brname: the bridge name
 * @macaddr: desired MAC address
 * @virtPortProfile: bridge/port specific configuration
 * @virtVlan: vlan tag info
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 * @force: set true to force detach/reattach even if the bridge name is unchanged
 *         (this can be useful if, for example, the profileid of the
 *         <virtualport> changes)
 *
 * Ensures that the tap device (@tapname) is connected to the bridge
 * (@brname), potentially removing it from any existing bridge that
 * does not match.
 *
 * Returns 0 in case of success or -1 on failure
 */
int
virNetDevTapReattachBridge(const char *tapname,
                           const char *brname,
                           const virMacAddr *macaddr,
                           const unsigned char *vmuuid,
                           const virNetDevVPortProfile *virtPortProfile,
                           const virNetDevVlan *virtVlan,
                           virTristateBool isolatedPort,
                           unsigned int mtu,
                           unsigned int *actualMTU,
                           bool force)
{
    bool useOVS = false;
    g_autofree char *master = NULL;

    if (virNetDevGetMaster(tapname, &master) < 0)
        return -1;

    /* IFLA_MASTER for a tap on an OVS switch is always "ovs-system" */
    if (STREQ_NULLABLE(master, "ovs-system")) {
        useOVS = true;

        /* master needs to be released here because it will be reassigned */
        g_clear_pointer(&master, g_free);
        if (virNetDevOpenvswitchInterfaceGetMaster(tapname, &master) < 0)
            return -1;
    }

    /* Nothing more todo if we're on the right bridge already */
    if (STREQ_NULLABLE(brname, master) && !force)
        return 0;

    /* disconnect from current (incorrect) bridge, if any  */
    if (master) {
        int ret;
        VIR_INFO("Removing %s from %s", tapname, master);
        if (useOVS)
            ret = virNetDevOpenvswitchRemovePort(tapname);
        else
            ret = virNetDevBridgeRemovePort(master, tapname);
        if (ret < 0)
            return -1;
    }

    VIR_INFO("Attaching %s to %s", tapname, brname);
    if (virNetDevTapAttachBridge(tapname, brname,
                                 macaddr, vmuuid,
                                 virtPortProfile,
                                 virtVlan,
                                 isolatedPort,
                                 mtu, actualMTU) < 0)
        return -1;

    return 0;
}


/**
 * virNetDevTapCreateInBridgePort:
 * @brname: the bridge name
 * @ifname: the interface name (or name template)
 * @macaddr: desired MAC address
 * @tunpath: path to the tun device (if NULL, /dev/net/tun is used)
 * @tapfd: array of file descriptor return value for the new tap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @virtPortProfile: bridge/port specific configuration
 * @coalesce: optional coalesce parameters
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_IFUP
 *     - Bring the interface up
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE
 *     - Set this interface's MAC as the bridge's MAC address
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *
 * This function creates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname.
 * If the @tapfd parameter is supplied, the open tap device file descriptor
 * will be returned, otherwise the TAP device will be closed. The caller must
 * use virNetDevTapDelete to remove a persistent TAP device when it is no
 * longer needed.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const virMacAddr *macaddr,
                                   const unsigned char *vmuuid,
                                   const char *tunpath,
                                   int *tapfd,
                                   size_t tapfdSize,
                                   const virNetDevVPortProfile *virtPortProfile,
                                   const virNetDevVlan *virtVlan,
                                   virTristateBool isolatedPort,
                                   virNetDevCoalesce *coalesce,
                                   unsigned int mtu,
                                   unsigned int *actualMTU,
                                   unsigned int flags)
{
    virMacAddr tapmac;
    size_t i;

    if (virNetDevTapCreate(ifname, tunpath, tapfd, tapfdSize, flags) < 0)
        return -1;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    virMacAddrSet(&tapmac, macaddr);
    if (!(flags & VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE)) {
        /* The tap device's MAC address cannot match the MAC address
         * used by the guest. This results in "received packet on
         * vnetX with own address as source address" error logs from
         * the kernel. Making the tap address as high as possible
         * discourages the bridge from using this tap's MAC as its own
         * (a Linux host bridge will take on the lowest numbered MAC
         * of all devices attached to it).
         */
        if (tapmac.addr[0] == 0xFE)
            tapmac.addr[0] = 0xFA;
        else
            tapmac.addr[0] = 0xFE;
    }

    if (virNetDevSetMAC(*ifname, &tapmac) < 0)
        goto error;

    if (virNetDevTapAttachBridge(*ifname, brname, macaddr, vmuuid,
                                 virtPortProfile, virtVlan,
                                 isolatedPort, mtu, actualMTU) < 0) {
        goto error;
    }

    if (virNetDevSetOnline(*ifname, !!(flags & VIR_NETDEV_TAP_CREATE_IFUP)) < 0)
        goto error;

    if (virNetDevSetCoalesce(*ifname, coalesce, false) < 0)
        goto error;

    return 0;

 error:
    for (i = 0; i < tapfdSize && tapfd[i] >= 0; i++)
        VIR_FORCE_CLOSE(tapfd[i]);

#if defined(VIR_NETDEV_TAP_REQUIRE_MANUAL_CLEANUP) || defined(WIN32)
    /* (Windows: a TAP-Windows adapter outlives its handles) */
    if (!(flags & VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING)) {
        virErrorPtr err;

        virErrorPreserveLast(&err);
        ignore_value(virNetDevTapDelete(*ifname, tunpath));
        virErrorRestore(&err);
    }
#endif /* VIR_NETDEV_TAP_REQUIRE_MANUAL_CLEANUP || WIN32 */

    return -1;
}

/*-------------------- interface stats --------------------*/

/**
 * virNetDevTapInterfaceStats:
 * @ifname: interface
 * @stats: where to store statistics
 * @swapped: whether to swap RX/TX fields
 *
 * Fetch RX/TX statistics for given named interface (@ifname) and
 * store them at @stats. The returned statistics are always from
 * domain POV. Because in some cases this means swapping RX/TX in
 * the stats and in others this means no swapping (consider TAP
 * vs macvtap) caller might choose if the returned stats should
 * be @swapped or not.
 *
 * Returns 0 on success, -1 otherwise (with error reported).
 */
#ifdef __linux__
int
virNetDevTapInterfaceStats(const char *ifname,
                           virDomainInterfaceStatsPtr stats,
                           bool swapped)
{
    int ifname_len;
    FILE *fp;
    char line[256], *colon;

    if (!ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface name not provided"));
        return -1;
    }

    fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        virReportSystemError(errno, "%s",
                             _("Could not open /proc/net/dev"));
        return -1;
    }

    ifname_len = strlen(ifname);

    while (fgets(line, sizeof(line), fp)) {
        long long dummy;
        long long rx_bytes;
        long long rx_packets;
        long long rx_errs;
        long long rx_drop;
        long long tx_bytes;
        long long tx_packets;
        long long tx_errs;
        long long tx_drop;

        /* The line looks like:
         *   "   eth0:..."
         * Split it at the colon.
         */
        colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        if (colon-ifname_len >= line &&
            STREQ(colon-ifname_len, ifname)) {
            if (sscanf(colon+1,
                       "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                       &rx_bytes, &rx_packets, &rx_errs, &rx_drop,
                       &dummy, &dummy, &dummy, &dummy,
                       &tx_bytes, &tx_packets, &tx_errs, &tx_drop,
                       &dummy, &dummy, &dummy, &dummy) != 16)
                continue;

            if (swapped) {
                stats->rx_bytes = tx_bytes;
                stats->rx_packets = tx_packets;
                stats->rx_errs = tx_errs;
                stats->rx_drop = tx_drop;
                stats->tx_bytes = rx_bytes;
                stats->tx_packets = rx_packets;
                stats->tx_errs = rx_errs;
                stats->tx_drop = rx_drop;
            } else {
                stats->rx_bytes = rx_bytes;
                stats->rx_packets = rx_packets;
                stats->rx_errs = rx_errs;
                stats->rx_drop = rx_drop;
                stats->tx_bytes = tx_bytes;
                stats->tx_packets = tx_packets;
                stats->tx_errs = tx_errs;
                stats->tx_drop = tx_drop;
            }

            VIR_FORCE_FCLOSE(fp);
            return 0;
        }
    }
    VIR_FORCE_FCLOSE(fp);

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("/proc/net/dev: Interface not found"));
    return -1;
}
#elif defined(WITH_GETIFADDRS) && defined(AF_LINK)
int
virNetDevTapInterfaceStats(const char *ifname,
                           virDomainInterfaceStatsPtr stats,
                           bool swapped)
{
    struct ifaddrs *ifap, *ifa;
    struct if_data *ifd;
    int ret = -1;

    if (!ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface name not provided"));
        return -1;
    }

    if (getifaddrs(&ifap) < 0) {
        virReportSystemError(errno, "%s",
                             _("Could not get interface list"));
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_LINK)
            continue;

        if (STREQ(ifa->ifa_name, ifname)) {
            ifd = (struct if_data *)ifa->ifa_data;
            if (swapped) {
                stats->tx_bytes = ifd->ifi_ibytes;
                stats->tx_packets = ifd->ifi_ipackets;
                stats->tx_errs = ifd->ifi_ierrors;
                stats->tx_drop = ifd->ifi_iqdrops;
                stats->rx_bytes = ifd->ifi_obytes;
                stats->rx_packets = ifd->ifi_opackets;
                stats->rx_errs = ifd->ifi_oerrors;
# ifndef __APPLE__
                stats->rx_drop = ifd->ifi_oqdrops;
# else
                stats->rx_drop = 0;
# endif
            } else {
                stats->tx_bytes = ifd->ifi_obytes;
                stats->tx_packets = ifd->ifi_opackets;
                stats->tx_errs = ifd->ifi_oerrors;
# ifndef __APPLE__
                stats->tx_drop = ifd->ifi_oqdrops;
# else
                stats->tx_drop = 0;
# endif
                stats->rx_bytes = ifd->ifi_ibytes;
                stats->rx_packets = ifd->ifi_ipackets;
                stats->rx_errs = ifd->ifi_ierrors;
                stats->rx_drop = ifd->ifi_iqdrops;
            }

            ret = 0;
            break;
        }
    }

    if (ret < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface not found"));

    freeifaddrs(ifap);
    return ret;
}
#elif defined(WIN32)
/* The counters the switch of the port keeps, in the domain's view (rx is
 * what the guest received), in run/libvirt/network/BRIDGE.stats */
int
virNetDevTapInterfaceStats(const char *ifname,
                           virDomainInterfaceStatsPtr stats,
                           bool swapped)
{
    g_autofree char *brname = NULL;
    g_autofree char *path = NULL;
    g_autoptr(GKeyFile) kf = g_key_file_new();
    char macstr[VIR_MAC_STRING_BUFLEN];
    virMacAddr mac;
    long long rx[4], tx[4];
    static const char *const keys[] = { "bytes", "packets", "errs", "drop" };
    size_t i;
    g_autofree char *port = virNetDevBridgeSwitchPortPath(ifname);

    if (!virFileExists(port)) {
        /* a TAP adapter: its counters, in the host's view */
        g_autofree wchar_t *alias = (wchar_t *)g_utf8_to_utf16(ifname, -1, NULL, NULL, NULL);
        MIB_IF_ROW2 row = { 0 };

        if (!alias || ConvertInterfaceAliasToLuid(alias, &row.InterfaceLuid) != NO_ERROR ||
            GetIfEntry2(&row) != NO_ERROR) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Interface not found: %1$s"), ifname);
            return -1;
        }
        rx[0] = row.InOctets;
        rx[1] = row.InUcastPkts + row.InNUcastPkts;
        rx[2] = row.InErrors;
        rx[3] = row.InDiscards;
        tx[0] = row.OutOctets;
        tx[1] = row.OutUcastPkts + row.OutNUcastPkts;
        tx[2] = row.OutErrors;
        tx[3] = row.OutDiscards;
        /* what the host receives is what the guest sends */
        if (swapped) {
            for (i = 0; i < G_N_ELEMENTS(keys); i++) {
                long long t = rx[i];

                rx[i] = tx[i];
                tx[i] = t;
            }
        }
        stats->rx_bytes = rx[0];
        stats->rx_packets = rx[1];
        stats->rx_errs = rx[2];
        stats->rx_drop = rx[3];
        stats->tx_bytes = tx[0];
        stats->tx_packets = tx[1];
        stats->tx_errs = tx[2];
        stats->tx_drop = tx[3];
        return 0;
    }

    if (virNetDevBridgeSwitchPortGet(ifname, &brname, &mac) < 0)
        return -1;
    path = g_strdup_printf("%s/%s.stats",
                           VIR_INSTALL_PATH(RUNSTATEDIR "/libvirt/network"), brname);
    virMacAddrFormat(&mac, macstr);
    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL) ||
        !g_key_file_has_group(kf, macstr)) {
        /* nothing went through the port yet */
        memset(stats, 0, sizeof(*stats));
        return 0;
    }
    for (i = 0; i < G_N_ELEMENTS(keys); i++) {
        g_autofree char *rxkey = g_strdup_printf("rx_%s", keys[i]);
        g_autofree char *txkey = g_strdup_printf("tx_%s", keys[i]);

        rx[i] = g_key_file_get_int64(kf, macstr, rxkey, NULL);
        tx[i] = g_key_file_get_int64(kf, macstr, txkey, NULL);
    }
    /* @swapped asks for the domain's view of a host side device: the
     * switch's counters are that view already */
    if (!swapped) {
        for (i = 0; i < G_N_ELEMENTS(keys); i++) {
            long long t = rx[i];

            rx[i] = tx[i];
            tx[i] = t;
        }
    }
    stats->rx_bytes = rx[0];
    stats->rx_packets = rx[1];
    stats->rx_errs = rx[2];
    stats->rx_drop = rx[3];
    stats->tx_bytes = tx[0];
    stats->tx_packets = tx[1];
    stats->tx_errs = tx[2];
    stats->tx_drop = tx[3];
    return 0;
}
#else
int
virNetDevTapInterfaceStats(const char *ifname G_GNUC_UNUSED,
                           virDomainInterfaceStatsPtr stats G_GNUC_UNUSED,
                           bool swapped G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("interface stats not implemented on this platform"));
    return -1;
}

#endif /* __linux__ */
