/*
 * storage_backend_fs_win32.c: mounts of the fs and netfs pools on Windows
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * What mount(8) does for these pools on Linux:
 *
 *  - netfs: the share \\HOST\DIR (SMB, or NFS with the Client for NFS of
 *    Windows, which takes the same paths) is "mounted" on the target
 *    directory by putting there a directory symbolic link to it; unmounting
 *    puts the empty directory back.
 *  - fs: the volume of the source device (a drive letter, X:, or a volume
 *    name, \\?\Volume{GUID}\) is mounted on the target directory as a
 *    volume mount point, as mountvol does.
 *
 * Making the file system of a fs pool (pool-build --overwrite) formats the
 * volume: vfat as FAT32, udf as UDF, and auto as NTFS, the file system of
 * Windows, which the formats of libvirt do not name.
 */

#include <config.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <lm.h>

#include "storage_backend_fs_win32.h"
#include "virerror.h"
#include "vircommand.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_fs_win32");

/* the symbolic link part of REPARSE_DATA_BUFFER (ntifs.h) */
typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    ULONG Flags;
    WCHAR PathBuffer[1];
} virStorageWin32SymlinkReparse;

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
# define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif


/* the message of Windows for the error of the last call */
static char *
virStorageWin32LastError(void)
{
    return g_win32_error_message(GetLastError());
}


static wchar_t *
virStorageWin32Wide(const char *s)
{
    return (wchar_t *)g_utf8_to_utf16(s, -1, NULL, NULL, NULL);
}


static char *
virStorageWin32UTF8(const wchar_t *w, int len)
{
    return g_utf16_to_utf8((const gunichar2 *)w, len, NULL, NULL, NULL);
}


/* @path with backslashes and without a trailing one */
static char *
virStorageWin32Path(const char *path)
{
    char *p = g_strdup(path);
    size_t len;

    g_strdelimit(p, "/", '\\');
    len = strlen(p);
    while (len > 3 && p[len - 1] == '\\')
        p[--len] = '\0';
    return p;
}


/* \\HOST\DIR of a netfs pool, @dir as /share/sub or share/sub */
static char *
virStorageWin32ShareUNC(virStoragePoolDef *def)
{
    const char *dir = def->source.dir;
    g_autofree char *path = NULL;

    while (*dir == '/' || *dir == '\\')
        dir++;
    path = g_strdup_printf("\\\\%s\\%s", def->source.hosts[0].name, dir);
    return virStorageWin32Path(path);
}


/* the volume name (\\?\Volume{GUID}\) of a fs pool's source device */
static int
virStorageWin32VolumeName(const char *device,
                          wchar_t *volume,
                          size_t volumelen)
{
    g_autofree char *root = NULL;
    g_autofree wchar_t *wroot = NULL;
    size_t len = strlen(device);

    if (len > 0 && device[len - 1] != '\\' && device[len - 1] != '/')
        root = g_strdup_printf("%s\\", device);
    else
        root = g_strdup(device);
    g_strdelimit(root, "/", '\\');
    wroot = virStorageWin32Wide(root);

    if (!wroot ||
        !GetVolumeNameForVolumeMountPointW(wroot, volume, volumelen)) {
        g_autofree char *msg = virStorageWin32LastError();

        virReportError(VIR_ERR_INVALID_ARG,
                       _("'%1$s' is not a volume (a drive letter such as E: or a volume name \\\\?\\Volume{GUID}\\): %2$s"),
                       device, msg);
        return -1;
    }
    return 0;
}


/* the target of the directory symbolic link @path, as \\HOST\SHARE... */
static char *
virStorageWin32ReadLink(const char *path)
{
    g_autofree wchar_t *wpath = virStorageWin32Wide(path);
    /* ULONGs for the alignment of the structure */
    g_autofree ULONG *buf = g_new0(ULONG, MAXIMUM_REPARSE_DATA_BUFFER_SIZE / sizeof(ULONG));
    virStorageWin32SymlinkReparse *rp = (virStorageWin32SymlinkReparse *)buf;
    g_autofree char *target = NULL;
    HANDLE h;
    DWORD got = 0;
    BOOL ok;

    h = CreateFileW(wpath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, buf,
                         MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &got, NULL);
    CloseHandle(h);
    if (!ok || rp->ReparseTag != IO_REPARSE_TAG_SYMLINK)
        return NULL;

    target = virStorageWin32UTF8(rp->PathBuffer + rp->SubstituteNameOffset / sizeof(WCHAR),
                                 rp->SubstituteNameLength / sizeof(WCHAR));
    if (!target)
        return NULL;

    /* \??\UNC\HOST\SHARE is \\HOST\SHARE, \??\C:\DIR is C:\DIR */
    if (STRPREFIX(target, "\\??\\UNC\\"))
        return g_strdup_printf("\\\\%s", target + strlen("\\??\\UNC\\"));
    if (STRPREFIX(target, "\\??\\"))
        return g_strdup(target + strlen("\\??\\"));
    return g_steal_pointer(&target);
}


/*
 * NFS without the Client for NFS of Windows (Windows Home has none):
 * libvirt_nfsmount, libnfs shown on the target directory by WinFsp.  Its
 * process is the mount: its state (pid, source) is in
 * RUNSTATEDIR/libvirt/storage/POOL.nfsmount, its output in
 * LOCALSTATEDIR/log/libvirt/storage/POOL-nfs.log.
 */
static bool virStorageWin32DirIsEmpty(const char *path);


static bool
virStorageWin32HasWinFsp(void)
{
    WCHAR dir[MAX_PATH];
    DWORD size = sizeof(dir);

    return RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\WinFsp", L"InstallDir",
                        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY, NULL, dir,
                        &size) == ERROR_SUCCESS;
}


static bool
virStorageWin32UseNfsHelper(virStoragePoolDef *def)
{
    return def->type == VIR_STORAGE_POOL_NETFS &&
        def->source.format == VIR_STORAGE_POOL_NETFS_NFS &&
        virStorageWin32HasWinFsp();
}


static char *
virStorageWin32NfsState(virStoragePoolDef *def)
{
    return g_strdup_printf("%s/libvirt/storage/%s.nfsmount",
                           VIR_INSTALL_PATH(RUNSTATEDIR), def->name);
}


/* the pid of the helper mounting the pool, 0 when none runs */
static DWORD
virStorageWin32NfsPid(virStoragePoolDef *def)
{
    g_autofree char *state = virStorageWin32NfsState(def);
    g_autoptr(GKeyFile) kf = g_key_file_new();
    g_autofree char *mountpoint = NULL;
    DWORD pid;
    HANDLE h;
    bool alive;

    if (!g_key_file_load_from_file(kf, state, G_KEY_FILE_NONE, NULL))
        return 0;
    pid = g_key_file_get_uint64(kf, "mount", "pid", NULL);
    mountpoint = g_key_file_get_string(kf, "mount", "target", NULL);
    if (!pid || !(h = OpenProcess(SYNCHRONIZE, FALSE, pid)))
        return 0;
    alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    if (!alive || !mountpoint || !virFileExists(mountpoint))
        return 0;
    return pid;
}


static int
virStorageWin32NfsMount(virStoragePoolDef *def, const char *target)
{
    g_autofree char *helper = g_strdup_printf("%s/libvirt_nfsmount.exe",
                                              VIR_INSTALL_PATH(LIBEXECDIR));
    g_autofree char *logdir = g_strdup_printf("%s/log/libvirt/storage",
                                              VIR_INSTALL_PATH(LOCALSTATEDIR));
    g_autofree char *logpath = g_strdup_printf("%s/%s-nfs.log", logdir, def->name);
    g_autofree char *state = virStorageWin32NfsState(def);
    g_autofree char *statedir = g_path_get_dirname(state);
    g_autofree char *export = g_strdup_printf("/%s", def->source.dir +
                                              strspn(def->source.dir, "/\\"));
    g_autofree char *cmdline = NULL;
    g_autofree wchar_t *wcmd = NULL;
    g_autofree wchar_t *wlog = NULL;
    g_autofree wchar_t *wtarget = virStorageWin32Wide(target);
    g_autoptr(GKeyFile) kf = g_key_file_new();
    g_autofree char *data = NULL;
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };
    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    const char *version = def->source.protocolVer ? def->source.protocolVer : "3";
    bool hadDir = false;
    size_t logStart = 0;
    HANDLE log;
    int i;

    if (!virFileExists(helper)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("'%1$s' is missing: it mounts NFS without the Client for NFS of Windows"),
                       helper);
        return -1;
    }

    /* WinFsp makes the directory it mounts on */
    if (virFileIsDir(target)) {
        if (!virStorageWin32DirIsEmpty(target)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("the target '%1$s' of the pool is not empty"),
                           target);
            return -1;
        }
        if (!RemoveDirectoryW(wtarget)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot replace '%1$s': %2$s"), target, msg);
            return -1;
        }
        hadDir = true;
    }

    g_mkdir_with_parents(logdir, 0777);
    g_mkdir_with_parents(statedir, 0777);
    wlog = virStorageWin32Wide(logpath);
    {
        struct stat sb;

        if (stat(logpath, &sb) == 0)
            logStart = sb.st_size;
    }
    log = CreateFileW(wlog, FILE_APPEND_DATA | SYNCHRONIZE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    cmdline = g_strdup_printf("\"%s\" \"%s\" \"%s\" \"%s\" --version %s",
                              helper, def->source.hosts[0].name, export,
                              target, version);
    wcmd = virStorageWin32Wide(cmdline);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = log;
    si.hStdError = log;
    if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                        NULL, NULL, &si, &pi)) {
        g_autofree char *msg = virStorageWin32LastError();

        if (log != INVALID_HANDLE_VALUE)
            CloseHandle(log);
        if (hadDir)
            CreateDirectoryW(wtarget, NULL);
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot run '%1$s': %2$s"), helper, msg);
        return -1;
    }
    CloseHandle(pi.hThread);
    if (log != INVALID_HANDLE_VALUE)
        CloseHandle(log);

    /* mounted when the directory is there */
    for (i = 0; i < 300; i++) {
        if (virFileExists(target))
            break;
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            g_autofree char *out = NULL;
            char *msg = (char *)"";

            CloseHandle(pi.hProcess);
            if (hadDir)
                CreateDirectoryW(wtarget, NULL);

            /* what the helper wrote this time, on one line */
            if (virFileReadAll(logpath, 1024 * 1024, &out) >= 0) {
                msg = strlen(out) > logStart ? out + logStart : out;
                g_strdelimit(msg, "\r\n", ' ');
                g_strstrip(msg);
            }
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot mount %1$s:%2$s on '%3$s': %4$s"),
                           def->source.hosts[0].name, export, target, msg);
            return -1;
        }
    }
    if (i == 300) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        if (hadDir)
            CreateDirectoryW(wtarget, NULL);
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("mounting %1$s:%2$s on '%3$s' took more than 30 seconds (see %4$s)"),
                       def->source.hosts[0].name, export, target, logpath);
        return -1;
    }
    CloseHandle(pi.hProcess);

    g_key_file_set_uint64(kf, "mount", "pid", pi.dwProcessId);
    g_key_file_set_string(kf, "mount", "source", def->source.hosts[0].name);
    g_key_file_set_string(kf, "mount", "export", export);
    g_key_file_set_string(kf, "mount", "target", target);
    data = g_key_file_to_data(kf, NULL, NULL);
    if (virFileWriteStr(state, data, 0644) < 0)
        VIR_WARN("cannot write %s", state);
    VIR_INFO("Mounted %s:%s on '%s' (libvirt_nfsmount, pid %lu)",
             def->source.hosts[0].name, export, target, pi.dwProcessId);
    return 0;
}


static int
virStorageWin32NfsUnmount(virStoragePoolDef *def, const char *target)
{
    g_autofree char *state = virStorageWin32NfsState(def);
    g_autofree wchar_t *wtarget = virStorageWin32Wide(target);
    DWORD pid = virStorageWin32NfsPid(def);

    if (pid) {
        g_autofree char *evname = g_strdup_printf("Local\\libvirt-signal-%lu-15", pid);
        HANDLE ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, evname);
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);

        if (ev) {
            SetEvent(ev);
            CloseHandle(ev);
        }
        if (h) {
            if (WaitForSingleObject(h, ev ? 15000 : 0) != WAIT_OBJECT_0) {
                TerminateProcess(h, 1);
                WaitForSingleObject(h, 5000);
            }
            CloseHandle(h);
        }
    }
    unlink(state);

    /* as after umount(8), the directory is left */
    if (!virFileIsDir(target) && !CreateDirectoryW(wtarget, NULL)) {
        g_autofree char *msg = virStorageWin32LastError();

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot create '%1$s': %2$s"), target, msg);
        return -1;
    }
    return 0;
}


int
virStorageBackendFsWin32IsMounted(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *target = virStorageWin32Path(def->target.path);

    if (virStorageWin32UseNfsHelper(def))
        return virStorageWin32NfsPid(def) != 0;

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        g_autofree char *unc = virStorageWin32ShareUNC(def);
        g_autofree char *link = virStorageWin32ReadLink(target);

        return link && g_ascii_strcasecmp(link, unc) == 0;
    } else {
        wchar_t volume[MAX_PATH];
        wchar_t mounted[MAX_PATH];
        g_autofree char *root = g_strdup_printf("%s\\", target);
        g_autofree wchar_t *wroot = virStorageWin32Wide(root);

        if (virStorageWin32VolumeName(def->source.devices[0].path,
                                      volume, G_N_ELEMENTS(volume)) < 0)
            return -1;
        /* only a mount point (or the root of a drive) has a volume name */
        if (!GetVolumeNameForVolumeMountPointW(wroot, mounted, G_N_ELEMENTS(mounted)))
            return 0;
        return _wcsicmp(volume, mounted) == 0;
    }
}


static bool
virStorageWin32DirIsEmpty(const char *path)
{
    g_autoptr(GDir) dir = g_dir_open(path, 0, NULL);

    return dir && g_dir_read_name(dir) == NULL;
}


int
virStorageBackendFsWin32Mount(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *target = virStorageWin32Path(def->target.path);
    g_autofree wchar_t *wtarget = virStorageWin32Wide(target);

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        g_autofree char *unc = NULL;
        g_autofree wchar_t *wunc = NULL;
        DWORD attr;
        bool hadDir = false;

        if (def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("glusterfs is not available on Windows"));
            return -1;
        }
        if (virStorageWin32UseNfsHelper(def))
            return virStorageWin32NfsMount(def, target);

        unc = virStorageWin32ShareUNC(def);
        wunc = virStorageWin32Wide(unc);

        /* as mount(8), fail when the share cannot be reached */
        attr = GetFileAttributesW(wunc);
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot reach the share '%1$s': %2$s"),
                           unc, msg);
            return -1;
        }

        if (virFileIsDir(target)) {
            if (!virStorageWin32DirIsEmpty(target)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("the target '%1$s' of the pool is not empty"),
                               target);
                return -1;
            }
            if (!RemoveDirectoryW(wtarget)) {
                g_autofree char *msg = virStorageWin32LastError();

                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("cannot replace '%1$s': %2$s"),
                               target, msg);
                return -1;
            }
            hadDir = true;
        }

        if (!CreateSymbolicLinkW(wtarget, wunc,
                                 SYMBOLIC_LINK_FLAG_DIRECTORY |
                                 SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
            g_autofree char *msg = virStorageWin32LastError();

            if (hadDir)
                CreateDirectoryW(wtarget, NULL);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot link '%1$s' to '%2$s': %3$s (making symbolic links takes administrator rights or the developer mode of Windows)"),
                           target, unc, msg);
            return -1;
        }
        VIR_INFO("Linked '%s' to '%s'", target, unc);
        return 0;
    } else {
        wchar_t volume[MAX_PATH];
        g_autofree char *root = g_strdup_printf("%s\\", target);
        g_autofree wchar_t *wroot = virStorageWin32Wide(root);

        if (virStorageWin32VolumeName(def->source.devices[0].path,
                                      volume, G_N_ELEMENTS(volume)) < 0)
            return -1;
        if (!virFileIsDir(target) && g_mkdir_with_parents(target, 0777) < 0) {
            virReportSystemError(errno, _("cannot create '%1$s'"), target);
            return -1;
        }
        if (!SetVolumeMountPointW(wroot, volume)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot mount '%1$s' on '%2$s': %3$s"),
                           def->source.devices[0].path, target, msg);
            return -1;
        }
        return 0;
    }
}


int
virStorageBackendFsWin32Unmount(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *target = virStorageWin32Path(def->target.path);
    g_autofree wchar_t *wtarget = virStorageWin32Wide(target);

    if (virStorageWin32UseNfsHelper(def))
        return virStorageWin32NfsUnmount(def, target);

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        /* removes the link, not what it points to */
        if (!RemoveDirectoryW(wtarget)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot unlink '%1$s': %2$s"),
                           target, msg);
            return -1;
        }
        /* as after umount(8), the directory is left */
        if (!CreateDirectoryW(wtarget, NULL)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot create '%1$s': %2$s"),
                           target, msg);
            return -1;
        }
        return 0;
    } else {
        g_autofree char *root = g_strdup_printf("%s\\", target);
        g_autofree wchar_t *wroot = virStorageWin32Wide(root);

        if (!DeleteVolumeMountPointW(wroot)) {
            g_autofree char *msg = virStorageWin32LastError();

            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot unmount '%1$s': %2$s"),
                           target, msg);
            return -1;
        }
        return 0;
    }
}


int
virStorageBackendFsWin32MakeFileSystem(virStoragePoolObj *pool,
                                       unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    const char *device;
    const char *fs;
    wchar_t volume[MAX_PATH];
    wchar_t fsname[MAX_PATH + 1] = { 0 };
    g_autofree char *volstr = NULL;
    g_autofree char *script = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (def->type != VIR_STORAGE_POOL_FS || !def->source.devices) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No source device specified when formatting pool '%1$s'"),
                       def->name);
        return -1;
    }
    device = def->source.devices[0].path;

    if (def->source.format == VIR_STORAGE_POOL_FS_AUTO) {
        fs = "NTFS";
    } else if (def->source.format == VIR_STORAGE_POOL_FS_VFAT) {
        fs = "FAT32";
    } else if (def->source.format == VIR_STORAGE_POOL_FS_UDF) {
        fs = "UDF";
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Windows cannot make a file system of format '%1$s' (auto for NTFS, vfat or udf)"),
                       virStoragePoolFormatFileSystemTypeToString(def->source.format));
        return -1;
    }

    if (virStorageWin32VolumeName(device, volume, G_N_ELEMENTS(volume)) < 0)
        return -1;

    if (flags & VIR_STORAGE_POOL_BUILD_NO_OVERWRITE &&
        GetVolumeInformationW(volume, NULL, 0, NULL, NULL, NULL,
                              fsname, G_N_ELEMENTS(fsname)) &&
        fsname[0] && _wcsicmp(fsname, L"RAW") != 0) {
        g_autofree char *name = virStorageWin32UTF8(fsname, -1);

        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Device '%1$s' already formatted using '%2$s'"),
                       device, NULLSTR(name));
        return -1;
    }

    volstr = virStorageWin32UTF8(volume, -1);
    script = g_strdup_printf("Format-Volume -Path '%s' -FileSystem %s -Force -Confirm:$false | Out-Null",
                             volstr, fs);
    cmd = virCommandNewArgList("powershell", "-NoProfile", "-NonInteractive",
                               "-Command", script, NULL);
    return virCommandRun(cmd, NULL);
}


/*
 * The disk shares of @host (NetShareEnum), as showmount lists the exports
 * of an NFS server.
 */
int
virStorageBackendFsWin32FindShares(const char *host,
                                   virStoragePoolSourceList *list)
{
    g_autofree wchar_t *whost = NULL;
    g_autofree char *server = g_strdup_printf("\\\\%s", host);
    SHARE_INFO_1 *shares = NULL;
    DWORD read = 0;
    DWORD total = 0;
    DWORD resume = 0;
    NET_API_STATUS st;
    DWORD i;
    int found = 0;

    whost = virStorageWin32Wide(server);
    do {
        st = NetShareEnum(whost, 1, (BYTE **)&shares, MAX_PREFERRED_LENGTH,
                          &read, &total, &resume);
        if (st != NERR_Success && st != ERROR_MORE_DATA)
            return -1;

        for (i = 0; i < read; i++) {
            virStoragePoolSource *src;
            g_autofree char *name = NULL;

            if ((shares[i].shi1_type & 0xff) != STYPE_DISKTREE ||
                shares[i].shi1_type & STYPE_SPECIAL)
                continue;
            if (!(name = virStorageWin32UTF8(shares[i].shi1_netname, -1)))
                continue;
            if (!(src = virStoragePoolSourceListNewSource(list)))
                break;
            src->hosts = g_new0(virStoragePoolSourceHost, 1);
            src->nhost = 1;
            src->hosts[0].name = g_strdup(host);
            src->dir = g_strdup_printf("/%s", name);
            src->format = VIR_STORAGE_POOL_NETFS_CIFS;
            found++;
        }
        NetApiBufferFree(shares);
        shares = NULL;
    } while (st == ERROR_MORE_DATA);

    return found;
}
