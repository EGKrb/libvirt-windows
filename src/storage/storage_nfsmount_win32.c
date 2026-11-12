/*
 * storage_nfsmount_win32.c: libvirt_nfsmount, mount(8) of NFS for the netfs
 * pools on Windows
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Windows Home has no NFS client.  This helper is one: libnfs speaks NFS
 * (version 3 or 4) to the server, and WinFsp, the file system of user mode
 * programs of Windows (what FUSE is on Linux), shows the export on a
 * directory, the target of the pool:
 *
 *   libvirt_nfsmount SERVER EXPORT MOUNTPOINT [--version 3|4] [--uid N] [--gid N]
 *
 * It runs until the SIGTERM of libvirt (its named event, see virProcessKill)
 * and unmounts then.  WinFsp is loaded when the helper starts, from where
 * its installer put it, so that the helper says it is missing instead of
 * failing to start.
 */

#include <config.h>

#include <winsock2.h>
#include <windows.h>

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <nfsc/libnfs.h>

/* the FUSE API of WinFsp, whose functions this file takes from its DLL */
#define FSP_FUSE_API
#include <fuse.h>

#define NM_SIGTERM 15

#ifndef O_ACCMODE
# define O_ACCMODE (O_RDONLY | O_WRONLY | O_RDWR)
#endif

/* an open file: its NFS handle, and whether it was written since its last
 * COMMIT (close-to-open consistency, as the NFS client of Linux) */
typedef struct _nmFile nmFile;
struct _nmFile {
    struct nfsfh *fh;
    bool written;
    int flags;
};

static struct nfs_context *nfs;
static CRITICAL_SECTION nfsLock;
static struct fuse *nmFuse;
static HANDLE nmTerm;

#define NFS_LOCKED(expr) \
    ({ __typeof__(expr) _r; EnterCriticalSection(&nfsLock); _r = (expr); \
       LeaveCriticalSection(&nfsLock); _r; })

/* the server asks to wait (the grace period of NFS 4 after it starts, or
 * a busy server): the client of Linux waits and retries */
static bool
nmShouldRetry(void)
{
    const char *err = nfs_get_error(nfs);

    return err && (strstr(err, "NFS4ERR_GRACE") || strstr(err, "NFS4ERR_DELAY") ||
                   strstr(err, "NFS3ERR_JUKEBOX"));
}

/* an operation, retried every second for 2 minutes while the server says
 * to wait */
#define NFS_CALL(expr) \
    ({ int _rc; int _tries = 0; bool _again; \
       for (;;) { \
           EnterCriticalSection(&nfsLock); \
           _rc = (expr); \
           _again = _rc < 0 && nmShouldRetry() && _tries++ < 120; \
           LeaveCriticalSection(&nfsLock); \
           if (!_again) \
               break; \
           Sleep(1000); \
       } \
       _rc; })


/* ---------------------------------------------------------------------
 * WinFsp, loaded at run time
 */

static int (*pMainReal)(struct fsp_fuse_env *, int, char *[],
                        const struct fuse_operations *, size_t, void *);
static void (*pExit)(struct fsp_fuse_env *, struct fuse *);
static struct fuse_context *(*pGetContext)(struct fsp_fuse_env *);

int
fsp_fuse_main_real(struct fsp_fuse_env *env, int argc, char *argv[],
                   const struct fuse_operations *ops, size_t opsize, void *data)
{
    return pMainReal(env, argc, argv, ops, opsize, data);
}

void
fsp_fuse_exit(struct fsp_fuse_env *env, struct fuse *f)
{
    pExit(env, f);
}

struct fuse_context *
fsp_fuse_get_context(struct fsp_fuse_env *env)
{
    return pGetContext(env);
}


/* as FspLoad() of WinFsp: its installation directory in the registry */
static bool
nmLoadWinFsp(void)
{
    WCHAR dir[MAX_PATH];
    WCHAR path[MAX_PATH + 32];
    DWORD size = sizeof(dir);
    HMODULE mod;

    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\WinFsp", L"InstallDir",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY, NULL, dir, &size) != ERROR_SUCCESS)
        return false;
    _snwprintf(path, G_N_ELEMENTS(path), L"%sbin\\winfsp-x64.dll", dir);
    path[G_N_ELEMENTS(path) - 1] = 0;
    if (!(mod = LoadLibraryW(path)))
        return false;
    pMainReal = (void *)GetProcAddress(mod, "fsp_fuse_main_real");
    pExit = (void *)GetProcAddress(mod, "fsp_fuse_exit");
    pGetContext = (void *)GetProcAddress(mod, "fsp_fuse_get_context");
    return pMainReal && pExit && pGetContext;
}


/* ---------------------------------------------------------------------
 * The file system
 */

static void
nmStat(const struct nfs_stat_64 *st, struct fuse_stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_dev = st->nfs_dev;
    stbuf->st_ino = st->nfs_ino;
    stbuf->st_mode = st->nfs_mode;
    stbuf->st_nlink = st->nfs_nlink;
    stbuf->st_uid = st->nfs_uid;
    stbuf->st_gid = st->nfs_gid;
    stbuf->st_size = st->nfs_size;
    stbuf->st_blksize = st->nfs_blksize ? st->nfs_blksize : 4096;
    stbuf->st_blocks = st->nfs_blocks;
    stbuf->st_atim.tv_sec = st->nfs_atime;
    stbuf->st_atim.tv_nsec = st->nfs_atime_nsec;
    stbuf->st_mtim.tv_sec = st->nfs_mtime;
    stbuf->st_mtim.tv_nsec = st->nfs_mtime_nsec;
    stbuf->st_ctim.tv_sec = st->nfs_ctime;
    stbuf->st_ctim.tv_nsec = st->nfs_ctime_nsec;
    stbuf->st_birthtim = stbuf->st_ctim;
}


static int
nmGetattr(const char *path, struct fuse_stat *stbuf)
{
    struct nfs_stat_64 st;
    int rc = NFS_CALL(nfs_stat64(nfs, path, &st));

    if (rc < 0)
        return rc;
    nmStat(&st, stbuf);
    return 0;
}


static int
nmFgetattr(const char *path, struct fuse_stat *stbuf, struct fuse_file_info *fi)
{
    struct nfs_stat_64 st;
    int rc;

    if (!fi || !fi->fh)
        return nmGetattr(path, stbuf);
    rc = NFS_CALL(nfs_fstat64(nfs, ((nmFile *)(uintptr_t)fi->fh)->fh, &st));
    if (rc < 0)
        return rc;
    nmStat(&st, stbuf);
    return 0;
}


static int
nmReaddir(const char *path, void *buf, fuse_fill_dir_t filler,
          fuse_off_t off G_GNUC_UNUSED, struct fuse_file_info *fi G_GNUC_UNUSED)
{
    struct nfsdir *dir;
    struct nfsdirent *ent;
    int rc;

    EnterCriticalSection(&nfsLock);
    if ((rc = nfs_opendir(nfs, path, &dir)) < 0) {
        LeaveCriticalSection(&nfsLock);
        return rc;
    }
    while ((ent = nfs_readdir(nfs, dir))) {
        struct fuse_stat st = { 0 };

        st.st_ino = ent->inode;
        st.st_mode = ent->mode;
        st.st_nlink = ent->nlink;
        st.st_uid = ent->uid;
        st.st_gid = ent->gid;
        st.st_size = ent->size;
        st.st_atim.tv_sec = ent->atime.tv_sec;
        st.st_mtim.tv_sec = ent->mtime.tv_sec;
        st.st_ctim.tv_sec = ent->ctime.tv_sec;
        if (filler(buf, ent->name, &st, 0))
            break;
    }
    nfs_closedir(nfs, dir);
    LeaveCriticalSection(&nfsLock);
    return 0;
}


/* the errors of operations, in the log of the mount */
static int
nmFail(const char *op, const char *path, int rc)
{
    const char *err = nfs_get_error(nfs);

    fprintf(stderr, "libvirt_nfsmount: %s %s: %s%s%s\n", op, path,
            g_strerror(rc < 0 ? -rc : rc), err && *err ? " - " : "",
            err && *err ? err : "");
    return rc < 0 ? rc : -EIO;
}


static nmFile *
nmFileOf(struct fuse_file_info *fi)
{
    return fi && fi->fh ? (nmFile *)(uintptr_t)fi->fh : NULL;
}


static int
nmOpen(const char *path, struct fuse_file_info *fi)
{
    struct nfsfh *fh;
    nmFile *f;
    int rc = NFS_CALL(nfs_open(nfs, path, fi->flags & O_ACCMODE, &fh));

    if (rc < 0) {
        fprintf(stderr, "libvirt_nfsmount: open flags 0x%x\n", fi->flags);
        return nmFail("open", path, rc);
    }
    f = g_new0(nmFile, 1);
    f->fh = fh;
    f->flags = fi->flags;
    fi->fh = (uintptr_t)f;
    return 0;
}


static int
nmCreate(const char *path, fuse_mode_t mode, struct fuse_file_info *fi)
{
    struct nfsfh *fh;
    nmFile *f;
    int rc = NFS_CALL(nfs_creat(nfs, path, mode & 07777, &fh));

    if (rc < 0)
        return nmFail("create", path, rc);
    /* libnfs leaves NFS 4 files created with the mode 0000, which WinFsp
     * makes an ACL nobody may open: the mode is set again */
    if ((rc = NFS_CALL(nfs_chmod(nfs, path, mode & 07777))) < 0)
        nmFail("chmod", path, rc);
    f = g_new0(nmFile, 1);
    f->fh = fh;
    f->flags = fi->flags;
    fi->fh = (uintptr_t)f;
    return 0;
}


static int
nmCommit(const char *path, nmFile *f)
{
    int rc;

    if (!f || !f->written)
        return 0;
    if ((rc = NFS_CALL(nfs_fsync(nfs, f->fh))) < 0)
        return nmFail("commit", path, rc);
    f->written = false;
    return 0;
}


static int
nmFlush(const char *path, struct fuse_file_info *fi)
{
    return nmCommit(path, nmFileOf(fi));
}


static int
nmRelease(const char *path, struct fuse_file_info *fi)
{
    nmFile *f = nmFileOf(fi);

    if (!f)
        return 0;
    nmCommit(path, f);
    NFS_LOCKED(nfs_close(nfs, f->fh));
    g_free(f);
    fi->fh = 0;
    return 0;
}


static int
nmRead(const char *path, char *buf, size_t size, fuse_off_t off,
       struct fuse_file_info *fi)
{
    nmFile *f = nmFileOf(fi);
    size_t max = NFS_LOCKED(nfs_get_readmax(nfs));
    size_t done = 0;

    if (!f)
        return -EBADF;
    while (done < size) {
        size_t n = MIN(size - done, max);
        int rc = NFS_CALL(nfs_pread(nfs, f->fh, buf + done, n, off + done));

        if (rc < 0)
            return done ? (int)done : nmFail("read", path, rc);
        if (rc == 0)
            break;
        done += rc;
    }
    return done;
}


static int
nmWrite(const char *path, const char *buf, size_t size,
        fuse_off_t off, struct fuse_file_info *fi)
{
    nmFile *f = nmFileOf(fi);
    /* libnfs on Windows never gets an answer to an NFS 4 WRITE of more
     * than 128 KiB (as measured against the nfsd of Linux): requests of
     * 128 KiB at most, the size the server gives NFS 3 */
    size_t max = MIN(NFS_LOCKED(nfs_get_writemax(nfs)), 128 * 1024);
    size_t done = 0;

    if (!f)
        return -EBADF;
    while (done < size) {
        size_t n = MIN(size - done, max);
        int rc = NFS_CALL(nfs_pwrite(nfs, f->fh, buf + done, n, off + done));

        if (rc < 0) {
            fprintf(stderr, "libvirt_nfsmount: write flags 0x%x offset %lld\n",
                    f->flags, (long long)(off + done));
            return done ? (int)done : nmFail("write", path, rc);
        }
        if (rc == 0)
            return -EIO;
        done += rc;
        f->written = true;
    }
    return done;
}


static int
nmFsync(const char *path, int datasync G_GNUC_UNUSED,
        struct fuse_file_info *fi)
{
    nmFile *f = nmFileOf(fi);
    int rc;

    if (!f)
        return 0;
    if ((rc = NFS_CALL(nfs_fsync(nfs, f->fh))) < 0)
        return nmFail("fsync", path, rc);
    f->written = false;
    return 0;
}


static int
nmTruncate(const char *path, fuse_off_t size)
{
    int rc = NFS_CALL(nfs_truncate(nfs, path, size));

    return rc < 0 ? nmFail("truncate", path, rc) : 0;
}


static int
nmFtruncate(const char *path, fuse_off_t size, struct fuse_file_info *fi)
{
    nmFile *f = nmFileOf(fi);
    int rc;

    /* a SETATTR of the size: by path, as the server sees no difference,
     * and a handle opened for reading only can truncate too */
    if (!f)
        return nmTruncate(path, size);
    rc = NFS_CALL(nfs_truncate(nfs, path, size));
    return rc < 0 ? nmFail("ftruncate", path, rc) : 0;
}


static int
nmUnlink(const char *path)
{
    return NFS_CALL(nfs_unlink(nfs, path));
}


static int
nmMkdir(const char *path, fuse_mode_t mode)
{
    int rc = NFS_CALL(nfs_mkdir2(nfs, path, mode & 07777));

    if (rc < 0)
        return nmFail("mkdir", path, rc);
    /* as for files (nmCreate) */
    if ((rc = NFS_CALL(nfs_chmod(nfs, path, mode & 07777))) < 0)
        nmFail("chmod", path, rc);
    return 0;
}


static int
nmRmdir(const char *path)
{
    return NFS_CALL(nfs_rmdir(nfs, path));
}


static int
nmRename(const char *from, const char *to)
{
    return NFS_CALL(nfs_rename(nfs, from, to));
}


static int
nmChmod(const char *path, fuse_mode_t mode)
{
    return NFS_CALL(nfs_chmod(nfs, path, mode & 07777));
}


static int
nmUtimens(const char *path, const struct fuse_timespec tv[2])
{
    struct timeval times[2];

    times[0].tv_sec = tv[0].tv_sec;
    times[0].tv_usec = tv[0].tv_nsec / 1000;
    times[1].tv_sec = tv[1].tv_sec;
    times[1].tv_usec = tv[1].tv_nsec / 1000;
    return NFS_CALL(nfs_utimes(nfs, path, times));
}


static int
nmStatfs(const char *path G_GNUC_UNUSED, struct fuse_statvfs *stbuf)
{
    struct nfs_statvfs_64 sv;
    int rc = NFS_CALL(nfs_statvfs64(nfs, "/", &sv));

    if (rc < 0)
        return rc;
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_bsize = sv.f_bsize;
    stbuf->f_frsize = sv.f_frsize ? sv.f_frsize : sv.f_bsize;
    stbuf->f_blocks = sv.f_blocks;
    stbuf->f_bfree = sv.f_bfree;
    stbuf->f_bavail = sv.f_bavail;
    stbuf->f_files = sv.f_files;
    stbuf->f_ffree = sv.f_ffree;
    stbuf->f_favail = sv.f_favail;
    stbuf->f_fsid = sv.f_fsid;
    stbuf->f_namemax = sv.f_namemax ? sv.f_namemax : 255;
    return 0;
}


/* the FUSE loop ends on the SIGTERM of libvirt */
static DWORD WINAPI
nmWaitTerm(void *opaque G_GNUC_UNUSED)
{
    WaitForSingleObject(nmTerm, INFINITE);
    fprintf(stderr, "libvirt_nfsmount: SIGTERM: unmounting\n");
    if (nmFuse)
        fuse_exit(nmFuse);
    return 0;
}


static void *
nmInit(struct fuse_conn_info *conn G_GNUC_UNUSED)
{
    nmFuse = fuse_get_context()->fuse;
    CloseHandle(CreateThread(NULL, 0, nmWaitTerm, NULL, 0, NULL));
    fprintf(stderr, "libvirt_nfsmount: mounted\n");
    return NULL;
}


static const struct fuse_operations nmOps = {
    .getattr = nmGetattr,
    .fgetattr = nmFgetattr,
    .readdir = nmReaddir,
    .open = nmOpen,
    .create = nmCreate,
    .flush = nmFlush,
    .release = nmRelease,
    .read = nmRead,
    .write = nmWrite,
    .fsync = nmFsync,
    .truncate = nmTruncate,
    .ftruncate = nmFtruncate,
    .unlink = nmUnlink,
    .mkdir = nmMkdir,
    .rmdir = nmRmdir,
    .rename = nmRename,
    .chmod = nmChmod,
    .utimens = nmUtimens,
    .statfs = nmStatfs,
    .init = nmInit,
};


static void
nmUsage(void)
{
    fprintf(stderr,
            "Usage: libvirt_nfsmount SERVER EXPORT MOUNTPOINT [--version 3|4] [--uid N] [--gid N]\n"
            "Mounts the NFS export SERVER:EXPORT on the directory MOUNTPOINT (WinFsp),\n"
            "until the SIGTERM of libvirt.\n");
}


int
main(int argc, char **argv)
{
    const char *server;
    const char *export;
    const char *mountpoint;
    int version = 3;
    int uid = 0;
    int gid = 0;
    char evname[64];
    g_autofree char *volname = NULL;
    char *fargv[10];
    int fargc = 0;
    WSADATA wsa;
    int i;
    int rc;

    if (argc < 4) {
        nmUsage();
        return 2;
    }
    server = argv[1];
    export = argv[2];
    mountpoint = argv[3];
    for (i = 4; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--version") == 0)
            version = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--uid") == 0)
            uid = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "--gid") == 0)
            gid = atoi(argv[i + 1]);
        else
            break;
    }
    if (i != argc || (version != 3 && version != 4)) {
        nmUsage();
        return 2;
    }

    if (!nmLoadWinFsp()) {
        fprintf(stderr, "libvirt_nfsmount: WinFsp is not installed (https://winfsp.dev)\n");
        return 3;
    }

    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&nfsLock);
    if (!(nfs = nfs_init_context())) {
        fprintf(stderr, "libvirt_nfsmount: cannot make an NFS context\n");
        return 1;
    }
    nfs_set_uid(nfs, uid);
    nfs_set_gid(nfs, gid);
    nfs_set_timeout(nfs, 60000);
    if ((rc = nfs_set_version(nfs, version)) < 0 ||
        (rc = nfs_mount(nfs, server, export)) < 0) {
        const char *err = nfs_get_error(nfs);

        fprintf(stderr, "libvirt_nfsmount: cannot mount %s:%s (NFS version %d): %s%s%s\n",
                server, export, version, err && *err ? err : "",
                err && *err ? ": " : "", g_strerror(-rc));
        return 1;
    }

    g_snprintf(evname, sizeof(evname), "Local\\libvirt-signal-%lu-%d",
               GetCurrentProcessId(), NM_SIGTERM);
    nmTerm = CreateEventA(NULL, TRUE, FALSE, evname);

    /* the files are the mounting user's, as uid= of a mount of Linux */
    volname = g_strdup("-ouid=-1,gid=-1,FileSystemName=NFS,volname=NFS");
    fargv[fargc++] = argv[0];
    fargv[fargc++] = (char *)"-f";
    fargv[fargc++] = (char *)"-s";
    /* every request of WinFsp and its answer, in the log of the pool */
    if (getenv("LIBVIRT_NFSMOUNT_DEBUG"))
        fargv[fargc++] = (char *)"-d";
    fargv[fargc++] = volname;
    fargv[fargc++] = (char *)mountpoint;
    fargv[fargc] = NULL;

    rc = fuse_main(fargc, fargv, &nmOps, NULL);

    NFS_LOCKED(nfs_umount(nfs));
    nfs_destroy_context(nfs);
    fprintf(stderr, "libvirt_nfsmount: unmounted (%d)\n", rc);
    return rc == 0 ? 0 : 1;
}
