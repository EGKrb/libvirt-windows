/*
 * node_device_win32.c: node device enumeration on Windows
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
 * What udev gives on Linux, from the device tree of Windows (SetupAPI and
 * the configuration manager), the IP helper API and the storage IOCTLs:
 * the computer (SMBIOS), PCI and USB devices, network interfaces and disks,
 * each under its parent in the device tree.  The devices are enumerated
 * when the driver starts, and again by nodeStateReload.
 */

#include <config.h>

/* before configmake.h, whose DATADIR the Windows headers use */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <iphlpapi.h>
#include <winioctl.h>

#include "node_device_conf.h"
#include "node_device_driver.h"
#include "node_device_event.h"
#include "node_device_win32.h"
#include "virnodedeviceobj.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virstring.h"
#include "virsysinfo.h"
#include "virutil.h"
#include "viruuid.h"
#include "virmacaddr.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("node_device.node_device_win32");

/* GUID_DEVINTERFACE_DISK of ntddstor.h */
static const GUID win32NodeDiskInterface = {
    0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b }
};


static char *
win32NodeUTF8(const wchar_t *w)
{
    return w ? g_utf16_to_utf8((const gunichar2 *)w, -1, NULL, NULL, NULL) : NULL;
}


/* A string (or the first string of a list) of the registry of a device */
static char *
win32NodeDevString(HDEVINFO set, SP_DEVINFO_DATA *dev, DWORD prop)
{
    wchar_t buf[1024];
    DWORD type;

    if (!SetupDiGetDeviceRegistryPropertyW(set, dev, prop, &type, (BYTE *)buf,
                                           sizeof(buf) - sizeof(wchar_t), NULL))
        return NULL;
    buf[G_N_ELEMENTS(buf) - 1] = 0;
    return win32NodeUTF8(buf);
}


/* The list strings of a device property, joined by '|' for searching */
static char *
win32NodeDevMultiString(HDEVINFO set, SP_DEVINFO_DATA *dev, DWORD prop)
{
    wchar_t buf[4096] = { 0 };
    g_auto(virBuffer) out = VIR_BUFFER_INITIALIZER;
    const wchar_t *s;

    if (!SetupDiGetDeviceRegistryPropertyW(set, dev, prop, NULL, (BYTE *)buf,
                                           sizeof(buf) - 2 * sizeof(wchar_t), NULL))
        return NULL;
    for (s = buf; *s; s += wcslen(s) + 1) {
        g_autofree char *u = win32NodeUTF8(s);

        virBufferAsprintf(&out, "%s|", NULLSTR_EMPTY(u));
    }
    return virBufferContentAndReset(&out);
}


static bool
win32NodeDevDWORD(HDEVINFO set, SP_DEVINFO_DATA *dev, DWORD prop, DWORD *val)
{
    return SetupDiGetDeviceRegistryPropertyW(set, dev, prop, NULL, (BYTE *)val,
                                             sizeof(*val), NULL);
}


static char *
win32NodeInstanceId(DEVINST inst)
{
    wchar_t id[MAX_DEVICE_ID_LEN];

    if (CM_Get_Device_IDW(inst, id, G_N_ELEMENTS(id), 0) != CR_SUCCESS)
        return NULL;
    return win32NodeUTF8(id);
}


/* the hexadecimal number after @key in @ids ("VEN_8086", "VID_046D") */
static bool
win32NodeHexAfter(const char *ids, const char *key, unsigned int *val)
{
    const char *p;
    char *end;
    g_autofree char *upper = NULL;

    if (!ids)
        return false;
    upper = g_ascii_strup(ids, -1);
    if (!(p = strstr(upper, key)))
        return false;
    /* followed by "&DEV_..." */
    return virStrToLong_uip(p + strlen(key), &end, 16, val) == 0;
}


/* The device names, by instance id, for the parents of the next ones */
typedef struct {
    GHashTable *names;          /* node name by instance id */
    GHashTable *seen;           /* node names of this enumeration */
} win32NodeEnum;


/* the node name of the nearest enumerated ancestor of @inst */
static char *
win32NodeParent(win32NodeEnum *en, DEVINST inst)
{
    DEVINST parent;

    while (CM_Get_Parent(&parent, inst, 0) == CR_SUCCESS) {
        g_autofree char *id = win32NodeInstanceId(parent);
        const char *name = id ? g_hash_table_lookup(en->names, id) : NULL;

        if (name)
            return g_strdup(name);
        inst = parent;
    }
    return g_strdup("computer");
}


static int
win32NodeAdd(win32NodeEnum *en, virNodeDeviceDef *def, const char *instanceId)
{
    virNodeDeviceObj *obj;
    size_t n;

    /* two devices of the same name in this enumeration (the same port of
     * two USB hubs): numbered */
    if (g_hash_table_contains(en->seen, def->name)) {
        for (n = 2; ; n++) {
            g_autofree char *name = g_strdup_printf("%s_%zu", def->name, n);

            if (!g_hash_table_contains(en->seen, name)) {
                g_free(def->name);
                def->name = g_steal_pointer(&name);
                break;
            }
        }
    }
    g_hash_table_add(en->seen, g_strdup(def->name));

    if (instanceId)
        g_hash_table_insert(en->names, g_ascii_strup(instanceId, -1), g_strdup(def->name));

    if (!(obj = virNodeDeviceObjListAssignDef(driver->devs, def))) {
        virNodeDeviceDefFree(def);
        return -1;
    }
    virNodeDeviceObjSetActive(obj, true);
    virNodeDeviceObjEndAPI(&obj);
    return 0;
}


static int
win32NodeSystem(win32NodeEnum *en)
{
    virNodeDeviceDef *def = g_new0(virNodeDeviceDef, 1);
    virNodeDevCapSystem *sys;
    g_autoptr(virSysinfoDef) sysinfo = virSysinfoRead();
    virNodeDeviceObj *obj;

    def->name = g_strdup("computer");
    def->caps = g_new0(virNodeDevCapsDef, 1);
    def->caps->data.type = VIR_NODE_DEV_CAP_SYSTEM;
    sys = &def->caps->data.system;

    if (sysinfo) {
        if (sysinfo->system) {
            sys->product_name = g_strdup(sysinfo->system->product);
            sys->hardware.vendor_name = g_strdup(sysinfo->system->manufacturer);
            sys->hardware.version = g_strdup(sysinfo->system->version);
            sys->hardware.serial = g_strdup(sysinfo->system->serial);
        }
        if (sysinfo->bios) {
            sys->firmware.vendor_name = g_strdup(sysinfo->bios->vendor);
            sys->firmware.version = g_strdup(sysinfo->bios->version);
            sys->firmware.release_date = g_strdup(sysinfo->bios->date);
        }
    } else {
        virResetLastError();
    }
    ignore_value(virGetHostUUID(sys->hardware.uuid));

    g_hash_table_add(en->seen, g_strdup(def->name));
    if (!(obj = virNodeDeviceObjListAssignDef(driver->devs, def))) {
        virNodeDeviceDefFree(def);
        return -1;
    }
    virNodeDeviceObjSetActive(obj, true);
    virNodeDeviceObjSetAutostart(obj, true);
    virNodeDeviceObjSetPersistent(obj, true);
    virNodeDeviceObjEndAPI(&obj);
    return 0;
}


/* PCI devices, buses first so that their children find them */
static int
win32NodePCI(win32NodeEnum *en)
{
    HDEVINFO set = SetupDiGetClassDevsW(NULL, L"PCI", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    DWORD i;

    if (set == INVALID_HANDLE_VALUE) {
        VIR_DEBUG("no PCI device list (error %lu)", GetLastError());
        return 0;
    }

    for (i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        virNodeDeviceDef *def;
        virNodeDevCapPCIDev *pci;
        g_autofree char *id = win32NodeInstanceId(dev.DevInst);
        g_autofree char *hwids = win32NodeDevMultiString(set, &dev, SPDRP_HARDWAREID);
        g_autofree char *compat = win32NodeDevMultiString(set, &dev, SPDRP_COMPATIBLEIDS);
        DWORD bus = 0, addr = 0;
        unsigned int klass = 0;

        if (!win32NodeDevDWORD(set, &dev, SPDRP_BUSNUMBER, &bus) ||
            !win32NodeDevDWORD(set, &dev, SPDRP_ADDRESS, &addr)) {
            VIR_DEBUG("PCI device %s without bus or address (error %lu)",
                      NULLSTR(id), GetLastError());
            continue;
        }

        def = g_new0(virNodeDeviceDef, 1);
        def->caps = g_new0(virNodeDevCapsDef, 1);
        def->caps->data.type = VIR_NODE_DEV_CAP_PCI_DEV;
        pci = &def->caps->data.pci_dev;
        pci->domain = 0;
        pci->bus = bus;
        pci->slot = (addr >> 16) & 0xffff;
        pci->function = addr & 0xffff;
        pci->numa_node = -1;
        ignore_value(win32NodeHexAfter(hwids, "VEN_", &pci->vendor));
        ignore_value(win32NodeHexAfter(hwids, "DEV_", &pci->product));
        if (win32NodeHexAfter(compat, "CC_", &klass)) {
            /* "CC_060400": class, subclass and interface */
            pci->klass = klass;
            if ((klass >> 8) == 0x0604)
                pci->hdrType = VIR_PCI_HEADER_PCI_BRIDGE;
            else if ((klass >> 8) == 0x0607)
                pci->hdrType = VIR_PCI_HEADER_CARDBUS_BRIDGE;
        }
        pci->vendor_name = win32NodeDevString(set, &dev, SPDRP_MFG);
        pci->product_name = win32NodeDevString(set, &dev, SPDRP_DEVICEDESC);
        def->driver = win32NodeDevString(set, &dev, SPDRP_SERVICE);
        def->sysfs_path = g_strdup(id);
        def->name = g_strdup_printf("pci_%04x_%02x_%02x_%x",
                                    pci->domain, pci->bus, pci->slot, pci->function);
        def->parent = win32NodeParent(en, dev.DevInst);
        if (win32NodeAdd(en, def, id) < 0) {
            SetupDiDestroyDeviceInfoList(set);
            return -1;
        }
    }
    VIR_DEBUG("%lu PCI devices (end: error %lu)", i, GetLastError());
    SetupDiDestroyDeviceInfoList(set);
    return 0;
}


/* USB devices (not their interfaces); hub number and port as bus and
 * device numbers, which Windows does not have */
static int
win32NodeUSB(win32NodeEnum *en)
{
    HDEVINFO set = SetupDiGetClassDevsW(NULL, L"USB", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    DWORD i;

    if (set == INVALID_HANDLE_VALUE)
        return 0;

    for (i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        virNodeDeviceDef *def;
        virNodeDevCapUSBDev *usb;
        g_autofree char *id = win32NodeInstanceId(dev.DevInst);
        g_autofree char *upper = id ? g_ascii_strup(id, -1) : NULL;
        g_autofree char *loc = NULL;
        unsigned int port = 0, hub = 0;
        DWORD addr = 0;

        if (!upper || !g_str_has_prefix(upper, "USB\\VID_") || strstr(upper, "&MI_"))
            continue;

        def = g_new0(virNodeDeviceDef, 1);
        def->caps = g_new0(virNodeDevCapsDef, 1);
        def->caps->data.type = VIR_NODE_DEV_CAP_USB_DEV;
        usb = &def->caps->data.usb_dev;
        ignore_value(win32NodeHexAfter(upper, "VID_", &usb->vendor));
        ignore_value(win32NodeHexAfter(upper, "PID_", &usb->product));
        usb->vendor_name = win32NodeDevString(set, &dev, SPDRP_MFG);
        usb->product_name = win32NodeDevString(set, &dev, SPDRP_DEVICEDESC);

        /* "Port_#0002.Hub_#0001" */
        loc = win32NodeDevString(set, &dev, SPDRP_LOCATION_INFORMATION);
        if (loc) {
            const char *p;

            char *end;

            if ((p = strstr(loc, "Port_#")))
                ignore_value(virStrToLong_uip(p + 6, &end, 10, &port));
            if ((p = strstr(loc, "Hub_#")))
                ignore_value(virStrToLong_uip(p + 5, &end, 10, &hub));
        }
        if (!port && win32NodeDevDWORD(set, &dev, SPDRP_ADDRESS, &addr))
            port = addr;
        usb->bus = hub;
        usb->device = port;
        usb->port = g_strdup_printf("%u", port);

        def->driver = win32NodeDevString(set, &dev, SPDRP_SERVICE);
        def->sysfs_path = g_strdup(id);
        def->name = g_strdup_printf("usb_%u_%u", usb->bus, usb->device);
        def->parent = win32NodeParent(en, dev.DevInst);
        if (win32NodeAdd(en, def, id) < 0) {
            SetupDiDestroyDeviceInfoList(set);
            return -1;
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    return 0;
}


/* The device of a network adapter: its PnP instance in the registry */
static char *
win32NodeNetInstance(const GUID *guid)
{
    g_autofree char *key = g_strdup_printf(
        "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
        "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\\Connection",
        (unsigned long)guid->Data1, guid->Data2, guid->Data3,
        guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
        guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    g_autofree wchar_t *wkey = (wchar_t *)g_utf8_to_utf16(key, -1, NULL, NULL, NULL);
    wchar_t buf[MAX_DEVICE_ID_LEN];
    DWORD size = sizeof(buf) - sizeof(wchar_t);

    if (!wkey ||
        RegGetValueW(HKEY_LOCAL_MACHINE, wkey, L"PnPInstanceId", RRF_RT_REG_SZ,
                     NULL, buf, &size) != ERROR_SUCCESS)
        return NULL;
    return win32NodeUTF8(buf);
}


static int
win32NodeNet(win32NodeEnum *en)
{
    MIB_IF_TABLE2 *table = NULL;
    ULONG i;

    if (GetIfTable2(&table) != NO_ERROR)
        return 0;

    for (i = 0; i < table->NumEntries; i++) {
        MIB_IF_ROW2 *row = &table->Table[i];
        virNodeDeviceDef *def;
        virNodeDevCapNet *net;
        g_autofree char *inst = NULL;
        virMacAddr mac;
        char macstr[VIR_MAC_STRING_BUFLEN];
        DEVINST devinst;
        g_autofree wchar_t *winst = NULL;

        /* the adapters of the hardware (and their virtual peers, such as
         * TAP or Wintun), as udev's "net" devices */
        if (!row->InterfaceAndOperStatusFlags.ConnectorPresent ||
            row->PhysicalAddressLength != VIR_MAC_BUFLEN ||
            row->InterfaceAndOperStatusFlags.FilterInterface)
            continue;

        def = g_new0(virNodeDeviceDef, 1);
        def->caps = g_new0(virNodeDevCapsDef, 1);
        def->caps->data.type = VIR_NODE_DEV_CAP_NET;
        net = &def->caps->data.net;
        net->ifname = win32NodeUTF8(row->Alias);
        virMacAddrSetRaw(&mac, row->PhysicalAddress);
        net->address = g_strdup(virMacAddrFormat(&mac, macstr));
        net->address_len = VIR_MAC_BUFLEN;
        net->subtype = VIR_NODE_DEV_CAP_NET_LAST;
        net->lnk.state = row->OperStatus == IfOperStatusUp ?
            VIR_NETDEV_IF_STATE_UP : VIR_NETDEV_IF_STATE_DOWN;
        if (row->OperStatus == IfOperStatusUp)
            net->lnk.speed = row->TransmitLinkSpeed / 1000000;

        def->name = g_strdup_printf("net_%s_%s", NULLSTR_EMPTY(net->ifname), net->address);
        for (char *p = def->name; *p; p++) {
            if (!g_ascii_isalnum(*p))
                *p = '_';
        }

        inst = win32NodeNetInstance(&row->InterfaceGuid);
        if (inst && (winst = (wchar_t *)g_utf8_to_utf16(inst, -1, NULL, NULL, NULL)) &&
            CM_Locate_DevNodeW(&devinst, winst, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) {
            g_autofree char *upper = g_ascii_strup(inst, -1);
            const char *self = g_hash_table_lookup(en->names, upper);

            /* the PCI or USB device of the adapter, else its parent */
            def->parent = self ? g_strdup(self) : win32NodeParent(en, devinst);
        } else {
            def->parent = g_strdup("computer");
        }
        def->sysfs_path = g_steal_pointer(&inst);
        if (win32NodeAdd(en, def, NULL) < 0) {
            FreeMibTable(table);
            return -1;
        }
    }
    FreeMibTable(table);
    return 0;
}


static const char *
win32NodeStorageBus(STORAGE_BUS_TYPE bus)
{
    switch ((int)bus) {
    case BusTypeScsi: return "scsi";
    case BusTypeAtapi:
    case BusTypeAta:
    case BusTypeSata: return "ata";
    case BusTypeUsb: return "usb";
    case BusTypeSd:
    case BusTypeMmc: return "mmc";
    /* BusTypeVirtual, BusTypeFileBackedVirtual and BusTypeNvme, which
     * MinGW's winioctl.h may lack */
    case 14:
    case 15: return "virtual";
    case 17: return "nvme";
    default: return NULL;
    }
}


/* a string of a STORAGE_DEVICE_DESCRIPTOR, at @offset */
static char *
win32NodeStorageString(const BYTE *buf, DWORD size, DWORD offset)
{
    g_autofree char *s = NULL;

    if (!offset || offset >= size)
        return NULL;
    s = g_strndup((const char *)buf + offset, size - offset);
    g_strstrip(s);
    return *s ? g_steal_pointer(&s) : NULL;
}


/* disks, from their device interfaces: a handle with no access right
 * answers the queries, without administrator rights */
static int
win32NodeStorage(win32NodeEnum *en)
{
    HDEVINFO set = SetupDiGetClassDevsW(&win32NodeDiskInterface, NULL, NULL,
                                        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    SP_DEVICE_INTERFACE_DATA iface = { .cbSize = sizeof(iface) };
    DWORD i;

    if (set == INVALID_HANDLE_VALUE)
        return 0;

    for (i = 0; SetupDiEnumDeviceInterfaces(set, NULL, &win32NodeDiskInterface, i, &iface); i++) {
        BYTE detailBuf[1024] = { 0 };
        SP_DEVICE_INTERFACE_DETAIL_DATA_W *detail = (SP_DEVICE_INTERFACE_DETAIL_DATA_W *)detailBuf;
        SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
        STORAGE_DEVICE_NUMBER number;
        STORAGE_PROPERTY_QUERY query = { .PropertyId = StorageDeviceProperty,
                                         .QueryType = PropertyStandardQuery };
        BYTE descBuf[4096] = { 0 };
        STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)descBuf;
        DISK_GEOMETRY_EX geom;
        virNodeDeviceDef *def;
        virNodeDevCapStorage *stor;
        g_autofree char *id = NULL;
        DWORD got;
        HANDLE h;

        detail->cbSize = sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(set, &iface, detail, sizeof(detailBuf),
                                              NULL, &dev))
            continue;
        h = CreateFileW(detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        if (!DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                             &number, sizeof(number), &got, NULL)) {
            CloseHandle(h);
            continue;
        }

        def = g_new0(virNodeDeviceDef, 1);
        def->caps = g_new0(virNodeDevCapsDef, 1);
        def->caps->data.type = VIR_NODE_DEV_CAP_STORAGE;
        stor = &def->caps->data.storage;
        stor->block = g_strdup_printf("\\\\.\\PhysicalDrive%lu", number.DeviceNumber);
        stor->drive_type = g_strdup("disk");

        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                            descBuf, sizeof(descBuf), &got, NULL) && got >= sizeof(*desc)) {
            const char *bus = win32NodeStorageBus(desc->BusType);

            stor->vendor = win32NodeStorageString(descBuf, got, desc->VendorIdOffset);
            stor->model = win32NodeStorageString(descBuf, got, desc->ProductIdOffset);
            stor->serial = win32NodeStorageString(descBuf, got, desc->SerialNumberOffset);
            stor->bus = g_strdup(bus);
            if (desc->RemovableMedia)
                stor->flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;
        }
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
                            &geom, sizeof(geom), &got, NULL)) {
            stor->size = geom.DiskSize.QuadPart;
            stor->logical_block_size = geom.Geometry.BytesPerSector;
            if (stor->logical_block_size)
                stor->num_blocks = stor->size / stor->logical_block_size;
        }
        CloseHandle(h);

        id = win32NodeInstanceId(dev.DevInst);
        def->sysfs_path = g_strdup(id);
        def->driver = win32NodeDevString(set, &dev, SPDRP_SERVICE);
        def->name = g_strdup_printf("block_PhysicalDrive%lu%s%s", number.DeviceNumber,
                                    stor->serial ? "_" : "", NULLSTR_EMPTY(stor->serial));
        for (char *p = def->name; *p; p++) {
            if (!g_ascii_isalnum(*p))
                *p = '_';
        }
        def->parent = win32NodeParent(en, dev.DevInst);
        if (win32NodeAdd(en, def, id) < 0) {
            SetupDiDestroyDeviceInfoList(set);
            return -1;
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    return 0;
}


/* a device of a previous enumeration that is gone */
static bool
win32NodeGone(virNodeDeviceObj *obj, const void *opaque)
{
    GHashTable *seen = (GHashTable *)opaque;

    return !g_hash_table_contains(seen, virNodeDeviceObjGetDef(obj)->name);
}


/* the devices as they are now: updated, added, and those gone removed */
static int
win32NodeEnumerate(void)
{
    win32NodeEnum en = {
        .names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free),
        .seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL),
    };
    int ret = -1;

    /* PCI before what hangs off it, USB before network adapters and disks */
    if (win32NodeSystem(&en) < 0 ||
        win32NodePCI(&en) < 0 ||
        win32NodeUSB(&en) < 0 ||
        win32NodeNet(&en) < 0 ||
        win32NodeStorage(&en) < 0)
        goto cleanup;
    virNodeDeviceObjListForEachRemove(driver->devs, win32NodeGone, en.seen);
    ret = 0;

 cleanup:
    g_hash_table_unref(en.names);
    g_hash_table_unref(en.seen);
    return ret;
}


static int
nodeStateCleanup(void)
{
    if (!driver)
        return -1;

    virObjectUnref(driver->nodeDeviceEventState);
    virNodeDeviceObjListFree(driver->devs);

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

    VIR_FREE(driver->stateDir);
    virCondDestroy(&driver->initCond);
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);
    return 0;
}


static virDrvStateInitResult
nodeStateInitialize(bool privileged,
                    const char *root,
                    bool monolithic G_GNUC_UNUSED,
                    virStateInhibitCallback callback G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return VIR_DRV_STATE_INIT_ERROR;
    }

    driver = g_new0(virNodeDeviceDriverState, 1);
    driver->lockFD = -1;
    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }
    if (virCondInit(&driver->initCond) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize condition variable"));
        virMutexDestroy(&driver->lock);
        VIR_FREE(driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    driver->privileged = privileged;
    if (privileged) {
        driver->stateDir = g_strdup_printf("%s/libvirt/nodedev", VIR_INSTALL_PATH(RUNSTATEDIR));
    } else {
        g_autofree char *rundir = virGetUserRuntimeDirectory();

        driver->stateDir = g_strdup_printf("%s/nodedev/run", rundir);
    }

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto error;
    }
    if ((driver->lockFD = virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto error;
    if (!(driver->devs = virNodeDeviceObjListNew()))
        goto error;

    driver->nodeDeviceEventState = virObjectEventStateNew();
    driver->parserCallbacks.postParse = nodeDeviceDefPostParse;
    driver->parserCallbacks.validate = nodeDeviceDefValidate;

    if (win32NodeEnumerate() < 0)
        goto error;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        driver->initialized = true;
        virCondBroadcast(&driver->initCond);
    }
    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    nodeStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}


/* Windows sends no device event to this driver: a reload (SIGHUP)
 * enumerates the devices again */
static int
nodeStateReload(void)
{
    if (!driver)
        return -1;
    return win32NodeEnumerate();
}


static virNodeDeviceDriver win32NodeDeviceDriver = {
    .name = "win32",
    .nodeNumOfDevices = nodeNumOfDevices,
    .nodeListDevices = nodeListDevices,
    .connectListAllNodeDevices = nodeConnectListAllNodeDevices,
    .connectNodeDeviceEventRegisterAny = nodeConnectNodeDeviceEventRegisterAny,
    .connectNodeDeviceEventDeregisterAny = nodeConnectNodeDeviceEventDeregisterAny,
    .nodeDeviceLookupByName = nodeDeviceLookupByName,
    .nodeDeviceLookupSCSIHostByWWN = nodeDeviceLookupSCSIHostByWWN,
    .nodeDeviceGetXMLDesc = nodeDeviceGetXMLDesc,
    .nodeDeviceGetParent = nodeDeviceGetParent,
    .nodeDeviceNumOfCaps = nodeDeviceNumOfCaps,
    .nodeDeviceListCaps = nodeDeviceListCaps,
    .nodeDeviceIsPersistent = nodeDeviceIsPersistent,
    .nodeDeviceIsActive = nodeDeviceIsActive,
};


static virHypervisorDriver win32NodeHypervisorDriver = {
    .name = "nodedev",
    .connectOpen = nodeConnectOpen,
    .connectClose = nodeConnectClose,
    .connectIsEncrypted = nodeConnectIsEncrypted,
    .connectIsSecure = nodeConnectIsSecure,
    .connectIsAlive = nodeConnectIsAlive,
};


static virConnectDriver win32NodeConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "nodedev", NULL },
    .hypervisorDriver = &win32NodeHypervisorDriver,
    .nodeDeviceDriver = &win32NodeDeviceDriver,
};


static virStateDriver win32NodeStateDriver = {
    .name = "win32-nodedev",
    .stateInitialize = nodeStateInitialize,
    .stateCleanup = nodeStateCleanup,
    .stateReload = nodeStateReload,
};


int
win32NodeRegister(void)
{
    VIR_DEBUG("Registering the Windows node device backend");

    if (virRegisterConnectDriver(&win32NodeConnectDriver, false) < 0)
        return -1;
    if (virSetSharedNodeDeviceDriver(&win32NodeDeviceDriver) < 0)
        return -1;

    return virRegisterStateDriver(&win32NodeStateDriver);
}
