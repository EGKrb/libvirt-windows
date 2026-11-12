/*
 * lxc_win32_vm.c: virtlxcd on Windows, the LXC driver in a Linux VM
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Linux containers need a Linux kernel, which Windows has not.  virtlxcd
 * runs one: a small Alpine Linux VM (QEMU, accelerated by the Windows
 * Hypervisor Platform) whose libvirt has the LXC driver of Linux, and
 * takes the place of that driver for the clients of this machine, on the
 * sockets of virtlxcd (lxc:///system).  A client connection is relayed to
 * the libvirt of the VM through SSH, with the key only this daemon has:
 * the API, the XML of containers and virsh are the ones of LXC on Linux;
 * the containers, their file systems and their networks are in the VM.
 *
 * The VM is made once by share/libvirt/lxc/lxc-vm-setup.ps1 (virtlxcd
 * --setup), in LOCALSTATEDIR/lib/libvirt/lxc: its disk (lxcvm.qcow2), the
 * key (id_ed25519), the host key of the VM (known_hosts) and lxcvm.conf
 * (the QEMU to run, memory, processors).
 */

#include <config.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <windows.h>

#include <stdio.h>

#include "internal.h"
#include "virerror.h"
#include "virfile.h"
#include "virgettext.h"
#include "virprocess.h"
#include "virstring.h"
#include "configmake.h"

/* the Winsock API itself, not the file descriptors of virsocket.h */
#undef socket
#undef bind
#undef listen
#undef accept
#undef connect
#undef recv
#undef send
#undef closesocket
#undef shutdown
#undef getsockname
#undef ioctlsocket

#define VIR_FROM_THIS VIR_FROM_LXC

typedef struct {
    char *stateDir;
    char *qemu;
    char *disk;
    char *key;
    char *knownHosts;
    char *ssh;
    int memory;                 /* MiB */
    int cpus;
    int port;                   /* the SSH port of the VM on 127.0.0.1 */
    HANDLE vm;                  /* QEMU */
    HANDLE evTerm;
    volatile LONG quit;
} lvState;

typedef struct {
    lvState *st;
    SOCKET client;
    bool readonly;
} lvClient;


static void G_GNUC_PRINTF(1, 2)
lvLog(const char *fmt, ...)
{
    va_list ap;
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *stamp = g_date_time_format(now, "%Y-%m-%d %H:%M:%S");

    va_start(ap, fmt);
    fprintf(stderr, "%s: ", stamp);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(ap);
}


/* one argument of a Windows command line (CommandLineToArgvW rules:
 * backslashes are doubled before a quote and at the end only) */
static void
lvAppendArg(GString *cmd, const char *arg)
{
    const char *p;

    if (cmd->len)
        g_string_append_c(cmd, ' ');
    if (*arg && !strpbrk(arg, " \t\""))  {
        g_string_append(cmd, arg);
        return;
    }
    g_string_append_c(cmd, '"');
    for (p = arg; *p; p++) {
        size_t bs = 0;

        while (*p == '\\') {
            bs++;
            p++;
        }
        if (!*p) {
            for (; bs; bs--)
                g_string_append(cmd, "\\\\");
            break;
        }
        if (*p == '"') {
            for (; bs; bs--)
                g_string_append(cmd, "\\\\");
            g_string_append(cmd, "\\\"");
        } else {
            for (; bs; bs--)
                g_string_append_c(cmd, '\\');
            g_string_append_c(cmd, *p);
        }
    }
    g_string_append_c(cmd, '"');
}


static HANDLE
lvSpawn(const char *const *argv, HANDLE in, HANDLE out, HANDLE err)
{
    g_autoptr(GString) cmd = g_string_new(NULL);
    g_autofree wchar_t *wcmd = NULL;
    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    size_t i;

    for (i = 0; argv[i]; i++)
        lvAppendArg(cmd, argv[i]);
    if (!(wcmd = (wchar_t *)g_utf8_to_utf16(cmd->str, -1, NULL, NULL, NULL)))
        return NULL;

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in ? in : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out ? out : GetStdHandle(STD_ERROR_HANDLE);
    si.hStdError = err ? err : GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        lvLog("cannot run %s: error %lu", argv[0], GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}


typedef struct {
    char port[16];
    char known[MAX_PATH * 3];
} lvSshBuf;

/* ssh to the VM, running @command */
static void
lvSshArgv(lvState *st, const char **argv, const char *command, lvSshBuf *b)
{
    size_t i = 0;
    char *port = b->port;
    char *known = b->known;

    g_snprintf(b->port, sizeof(b->port), "%d", st->port);
    g_snprintf(b->known, sizeof(b->known), "UserKnownHostsFile=%s", st->knownHosts);
    argv[i++] = st->ssh;
    argv[i++] = "-q";
    argv[i++] = "-T";
    argv[i++] = "-i";
    argv[i++] = st->key;
    argv[i++] = "-p";
    argv[i++] = port;
    argv[i++] = "-o";
    argv[i++] = "BatchMode=yes";
    argv[i++] = "-o";
    argv[i++] = "IdentitiesOnly=yes";
    argv[i++] = "-o";
    argv[i++] = "HostKeyAlias=libvirt-lxcvm";
    argv[i++] = "-o";
    argv[i++] = "StrictHostKeyChecking=yes";
    argv[i++] = "-o";
    argv[i++] = known;
    argv[i++] = "-o";
    argv[i++] = "ConnectTimeout=5";
    argv[i++] = "root@127.0.0.1";
    argv[i++] = command;
    argv[i] = NULL;
}


static int
lvSshRun(lvState *st, const char *command, DWORD timeoutMs)
{
    const char *argv[32];
    lvSshBuf b;
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, 0, NULL);
    HANDLE proc;
    DWORD code = 1;

    SetHandleInformation(nul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    lvSshArgv(st, argv, command, &b);
    proc = lvSpawn(argv, nul, nul, nul);
    CloseHandle(nul);
    if (!proc)
        return -1;
    if (WaitForSingleObject(proc, timeoutMs) != WAIT_OBJECT_0)
        TerminateProcess(proc, 1);
    GetExitCodeProcess(proc, &code);
    CloseHandle(proc);
    return code == 0 ? 0 : -1;
}


static int
lvFreePort(void)
{
    struct sockaddr_in sin = { .sin_family = AF_INET };
    int len = sizeof(sin);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int port = -1;

    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s != INVALID_SOCKET &&
        bind(s, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
        getsockname(s, (struct sockaddr *)&sin, &len) == 0)
        port = ntohs(sin.sin_port);
    if (s != INVALID_SOCKET)
        closesocket(s);
    return port;
}


static int
lvStartVM(lvState *st)
{
    g_autofree char *mem = g_strdup_printf("%d", st->memory);
    g_autofree char *cpus = g_strdup_printf("%d", st->cpus);
    g_autofree char *drive = NULL;
    g_autofree char *netdev = NULL;
    g_autofree char *logdir = g_strdup(VIR_INSTALL_PATH(LOCALSTATEDIR "/log/libvirt/lxc"));
    g_autofree char *console = NULL;
    const char *argv[40];
    size_t i = 0;
    gint64 deadline;

    if ((st->port = lvFreePort()) < 0) {
        lvLog("no free port for the SSH of the VM");
        return -1;
    }
    g_mkdir_with_parents(logdir, 0777);
    console = g_strdup_printf("file:%s/lxcvm-console.log", logdir);
    drive = g_strdup_printf("file=%s,if=virtio,format=qcow2,cache=writeback", st->disk);
    netdev = g_strdup_printf("user,id=n0,hostname=lxcvm,hostfwd=tcp:127.0.0.1:%d-:22",
                             st->port);

    argv[i++] = st->qemu;
    argv[i++] = "-nodefaults";
    argv[i++] = "-machine";
    argv[i++] = "q35";
    argv[i++] = "-accel";
    argv[i++] = "whpx";
    argv[i++] = "-accel";
    argv[i++] = "tcg";
    argv[i++] = "-m";
    argv[i++] = mem;
    argv[i++] = "-smp";
    argv[i++] = cpus;
    argv[i++] = "-drive";
    argv[i++] = drive;
    argv[i++] = "-netdev";
    argv[i++] = netdev;
    argv[i++] = "-device";
    argv[i++] = "virtio-net-pci,netdev=n0";
    argv[i++] = "-device";
    argv[i++] = "virtio-rng-pci";
    argv[i++] = "-serial";
    argv[i++] = console;
    argv[i++] = "-display";
    argv[i++] = "none";
    argv[i] = NULL;

    lvLog("starting the VM: %s, %d MiB, %d processors, SSH on 127.0.0.1:%d",
          st->disk, st->memory, st->cpus, st->port);
    if (!(st->vm = lvSpawn(argv, NULL, NULL, NULL)))
        return -1;

    /* its libvirt answers through SSH */
    deadline = g_get_monotonic_time() + 300 * G_USEC_PER_SEC;
    while (g_get_monotonic_time() < deadline) {
        if (WaitForSingleObject(st->vm, 0) == WAIT_OBJECT_0) {
            lvLog("the VM stopped while starting; see %s/lxcvm-console.log", logdir);
            return -1;
        }
        if (WaitForSingleObject(st->evTerm, 0) == WAIT_OBJECT_0)
            return -1;
        if (lvSshRun(st, "test -S /run/libvirt/libvirt-sock", 15000) == 0) {
            lvLog("the VM is up");
            return 0;
        }
        Sleep(2000);
    }
    lvLog("the VM did not answer in 5 minutes; see %s/lxcvm-console.log", logdir);
    return -1;
}


static void
lvStopVM(lvState *st)
{
    if (!st->vm)
        return;
    if (WaitForSingleObject(st->vm, 0) != WAIT_OBJECT_0) {
        lvLog("stopping the VM");
        lvSshRun(st, "poweroff", 15000);
        if (WaitForSingleObject(st->vm, 60000) != WAIT_OBJECT_0) {
            lvLog("the VM did not stop: terminating it");
            TerminateProcess(st->vm, 1);
            WaitForSingleObject(st->vm, 10000);
        }
    }
    CloseHandle(st->vm);
    st->vm = NULL;
}


typedef struct {
    SOCKET sock;
    HANDLE pipe;
} lvPump;


/* the client to the stdin of ssh */
static gpointer
lvPumpIn(gpointer data)
{
    lvPump *p = data;
    g_autofree char *buf = g_malloc(65536);
    int n;

    while ((n = recv(p->sock, buf, 65536, 0)) > 0) {
        DWORD done = 0;
        int off = 0;

        while (off < n) {
            if (!WriteFile(p->pipe, buf + off, n - off, &done, NULL))
                goto out;
            off += done;
        }
    }
 out:
    CloseHandle(p->pipe);
    return NULL;
}


static gpointer
lvClientThread(gpointer data)
{
    g_autofree lvClient *c = data;
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };
    HANDLE inRead = NULL, inWrite = NULL, outRead = NULL, outWrite = NULL;
    HANDLE proc = NULL;
    const char *argv[32];
    lvSshBuf b;
    lvPump pump;
    GThread *t = NULL;
    g_autofree char *buf = g_malloc(65536);
    DWORD n;

    if (!CreatePipe(&inRead, &inWrite, &sa, 0) ||
        !CreatePipe(&outRead, &outWrite, &sa, 0))
        goto cleanup;
    SetHandleInformation(inWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);

    lvSshArgv(c->st, argv, c->readonly ?
              "exec socat - UNIX-CONNECT:/run/libvirt/libvirt-sock-ro" :
              "exec socat - UNIX-CONNECT:/run/libvirt/libvirt-sock", &b);
    proc = lvSpawn(argv, inRead, outWrite, NULL);
    CloseHandle(inRead);
    inRead = NULL;
    CloseHandle(outWrite);
    outWrite = NULL;
    if (!proc)
        goto cleanup;

    pump.sock = c->client;
    pump.pipe = inWrite;
    inWrite = NULL;
    t = g_thread_new("lxc-in", lvPumpIn, &pump);

    /* the stdout of ssh to the client */
    while (ReadFile(outRead, buf, 65536, &n, NULL) && n > 0) {
        DWORD off = 0;

        while (off < n) {
            int sent = send(c->client, buf + off, n - off, 0);

            if (sent <= 0)
                goto done;
            off += sent;
        }
    }
 done:
    shutdown(c->client, SD_BOTH);
    TerminateProcess(proc, 0);
    g_thread_join(t);

 cleanup:
    if (proc)
        CloseHandle(proc);
    if (inRead)
        CloseHandle(inRead);
    if (inWrite)
        CloseHandle(inWrite);
    if (outRead)
        CloseHandle(outRead);
    if (outWrite)
        CloseHandle(outWrite);
    closesocket(c->client);
    return NULL;
}


static SOCKET
lvListen(const char *path)
{
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    SOCKET s;

    if (strlen(path) >= sizeof(un.sun_path)) {
        lvLog("socket path too long: %s", path);
        return INVALID_SOCKET;
    }
    g_strlcpy(un.sun_path, path, sizeof(un.sun_path));
    DeleteFileA(path);
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET ||
        bind(s, (struct sockaddr *)&un, sizeof(un)) == SOCKET_ERROR ||
        listen(s, 16) == SOCKET_ERROR) {
        lvLog("cannot listen on %s: error %d", path, WSAGetLastError());
        return INVALID_SOCKET;
    }
    return s;
}


static int
lvLoadConfig(lvState *st)
{
    g_autofree char *conf = NULL;
    g_autoptr(GKeyFile) kf = g_key_file_new();
    g_autoptr(GError) err = NULL;
    g_autofree char *sysdir = NULL;

    st->stateDir = g_strdup(VIR_INSTALL_PATH(LOCALSTATEDIR "/lib/libvirt/lxc"));
    conf = g_strdup_printf("%s/lxcvm.conf", st->stateDir);
    st->disk = g_strdup_printf("%s/lxcvm.qcow2", st->stateDir);
    st->key = g_strdup_printf("%s/id_ed25519", st->stateDir);
    st->knownHosts = g_strdup_printf("%s/known_hosts", st->stateDir);

    if (!virFileExists(st->disk) || !g_key_file_load_from_file(kf, conf, G_KEY_FILE_NONE, &err)) {
        lvLog("the Linux VM of LXC is not made: run '%s --setup' once (it downloads Alpine Linux)",
              "virtlxcd");
        return -1;
    }
    st->qemu = g_key_file_get_string(kf, "vm", "qemu", NULL);
    st->memory = g_key_file_get_integer(kf, "vm", "memory", NULL);
    st->cpus = g_key_file_get_integer(kf, "vm", "cpus", NULL);
    if (st->memory <= 0)
        st->memory = 2048;
    if (st->cpus <= 0)
        st->cpus = 2;
    if (!st->qemu && !(st->qemu = virFindFileInPath("qemu-system-x86_64.exe"))) {
        lvLog("qemu-system-x86_64.exe is neither in %s nor on PATH", conf);
        return -1;
    }

    sysdir = g_strdup_printf("%s\\System32\\OpenSSH\\ssh.exe", g_getenv("SystemRoot"));
    if (virFileExists(sysdir))
        st->ssh = g_steal_pointer(&sysdir);
    else if (!(st->ssh = virFindFileInPath("ssh.exe"))) {
        lvLog("ssh.exe (the OpenSSH client of Windows) is not there");
        return -1;
    }
    return 0;
}


/* --daemon: the same program in the background, logging to its file;
 * this one waits for it to listen */
static int
lvDaemonize(int argc, char **argv, const char *sockPath)
{
    g_autofree char *logdir = g_strdup(VIR_INSTALL_PATH(LOCALSTATEDIR "/log/libvirt"));
    g_autofree char *logpath = g_strdup_printf("%s/virtlxcd.log", logdir);
    g_autofree wchar_t *wlog = NULL;
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = TRUE };
    const char **args = g_new0(const char *, argc + 1);
    HANDLE logh;
    HANDLE child;
    int i, j = 0;
    gint64 deadline = g_get_monotonic_time() + 330 * G_USEC_PER_SEC;

    g_mkdir_with_parents(logdir, 0777);
    wlog = (wchar_t *)g_utf8_to_utf16(logpath, -1, NULL, NULL, NULL);
    logh = CreateFileW(wlog, FILE_APPEND_DATA | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    for (i = 0; i < argc; i++) {
        if (STRNEQ(argv[i], "--daemon") && STRNEQ(argv[i], "-d"))
            args[j++] = argv[i];
    }
    child = lvSpawn(args, NULL, logh, logh);
    g_free(args);
    if (logh != INVALID_HANDLE_VALUE)
        CloseHandle(logh);
    if (!child)
        return EXIT_FAILURE;

    while (g_get_monotonic_time() < deadline) {
        if (virFileExists(sockPath))
            return EXIT_SUCCESS;
        if (WaitForSingleObject(child, 1000) == WAIT_OBJECT_0) {
            fprintf(stderr, "virtlxcd: failed to start, see %s\n", logpath);
            return EXIT_FAILURE;
        }
    }
    fprintf(stderr, "virtlxcd: still starting, see %s\n", logpath);
    return EXIT_SUCCESS;
}


static int
lvSetup(int argc, char **argv)
{
    g_autofree char *script = g_strdup_printf("%s/lxc/lxc-vm-setup.ps1",
                                              VIR_INSTALL_PATH(PKGDATADIR));
    const char **args = g_new0(const char *, argc + 8);
    HANDLE proc;
    DWORD code = 1;
    size_t j = 0;
    int i;

    args[j++] = "powershell.exe";
    args[j++] = "-NoProfile";
    args[j++] = "-ExecutionPolicy";
    args[j++] = "Bypass";
    args[j++] = "-File";
    args[j++] = script;
    for (i = 2; i < argc; i++)
        args[j++] = argv[i];
    proc = lvSpawn(args, NULL, GetStdHandle(STD_OUTPUT_HANDLE), NULL);
    g_free(args);
    if (!proc)
        return EXIT_FAILURE;
    WaitForSingleObject(proc, INFINITE);
    GetExitCodeProcess(proc, &code);
    CloseHandle(proc);
    return code;
}


int
main(int argc, char **argv)
{
    lvState st = { 0 };
    g_autofree char *rundir = g_strdup(VIR_INSTALL_PATH(RUNSTATEDIR "/libvirt"));
    g_autofree char *sockPath = g_strdup_printf("%s/virtlxcd-sock", rundir);
    g_autofree char *roPath = g_strdup_printf("%s/virtlxcd-sock-ro", rundir);
    g_autofree char *pidPath = g_strdup_printf("%s/virtlxcd.pid",
                                               VIR_INSTALL_PATH(RUNSTATEDIR));
    g_autofree char *evname = NULL;
    g_autofree char *pidstr = NULL;
    SOCKET rw, ro;
    WSADATA wsa;
    int i;

    if (virGettextInitialize() < 0 || virErrorInitialize() < 0)
        return EXIT_FAILURE;

    for (i = 1; i < argc; i++) {
        if (STREQ(argv[i], "--setup"))
            return lvSetup(argc, argv);
        if (STREQ(argv[i], "--help") || STREQ(argv[i], "-h")) {
            printf("Usage: virtlxcd [--daemon] | --setup [setup options]\n"
                   "The LXC driver of libvirt, in a Linux VM (see --setup).\n");
            return EXIT_SUCCESS;
        }
    }
    for (i = 1; i < argc; i++) {
        if (STREQ(argv[i], "--daemon") || STREQ(argv[i], "-d"))
            return lvDaemonize(argc, argv, sockPath);
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return EXIT_FAILURE;
    if (lvLoadConfig(&st) < 0)
        return EXIT_FAILURE;

    if (virFileExists(sockPath)) {
        g_autofree char *old = NULL;
        long long oldpid;

        if (virFileReadAll(pidPath, 64, &old) > 0 &&
            virStrToLong_ll(old, NULL, 10, &oldpid) == 0) {
            HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, oldpid);

            if (h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT) {
                lvLog("virtlxcd is already running (pid %lld)", oldpid);
                CloseHandle(h);
                return EXIT_FAILURE;
            }
            if (h)
                CloseHandle(h);
        }
    }

    evname = VIR_PROCESS_WIN32_SIGNAL_EVENT((long long)GetCurrentProcessId(), SIGTERM);
    st.evTerm = CreateEventA(NULL, TRUE, FALSE, evname);
    pidstr = g_strdup_printf("%lu\n", GetCurrentProcessId());
    g_mkdir_with_parents(rundir, 0777);
    if (virFileWriteStr(pidPath, pidstr, 0644) < 0)
        lvLog("cannot write %s", pidPath);

    if (lvStartVM(&st) < 0) {
        lvStopVM(&st);
        DeleteFileA(pidPath);
        return EXIT_FAILURE;
    }

    if ((rw = lvListen(sockPath)) == INVALID_SOCKET ||
        (ro = lvListen(roPath)) == INVALID_SOCKET) {
        lvStopVM(&st);
        DeleteFileA(pidPath);
        return EXIT_FAILURE;
    }
    lvLog("listening on %s, pid %lu", sockPath, GetCurrentProcessId());

    while (WaitForSingleObject(st.evTerm, 0) != WAIT_OBJECT_0) {
        WSAPOLLFD fds[2] = {
            { .fd = rw, .events = POLLRDNORM },
            { .fd = ro, .events = POLLRDNORM },
        };

        if (WaitForSingleObject(st.vm, 0) == WAIT_OBJECT_0) {
            lvLog("the VM stopped; see the console log");
            break;
        }
        if (WSAPoll(fds, 2, 500) <= 0)
            continue;
        for (i = 0; i < 2; i++) {
            SOCKET s;
            lvClient *c;

            if (!fds[i].revents || (s = accept(fds[i].fd, NULL, NULL)) == INVALID_SOCKET)
                continue;
            c = g_new0(lvClient, 1);
            c->st = &st;
            c->client = s;
            c->readonly = i == 1;
            g_thread_unref(g_thread_new("lxc-client", lvClientThread, c));
        }
    }

    lvLog("SIGTERM: stopping");
    closesocket(rw);
    closesocket(ro);
    DeleteFileA(sockPath);
    DeleteFileA(roPath);
    lvStopVM(&st);
    DeleteFileA(pidPath);
    return EXIT_SUCCESS;
}
