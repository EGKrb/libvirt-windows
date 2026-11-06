/*
 * virdaemon.c: shared daemon setup code
 *
 * Copyright (C) 2020 Red Hat, Inc.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
# include <sys/wait.h>
#else
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <io.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "virdaemon.h"
#include "virutil.h"
#include "virfile.h"
#include "virlog.h"
#include "viralloc.h"

#include "configmake.h"

#ifndef WIN32

int
virDaemonForkIntoBackground(const char *argv0)
{
    int statuspipe[2];
    pid_t pid;

    if (virPipeQuiet(statuspipe) < 0)
        return -1;

    pid = fork();
    switch (pid) {
    case 0:
        {
            /* intermediate child */
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;

            VIR_FORCE_CLOSE(statuspipe[0]);

            if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) < 0)
                goto cleanup;
            if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
                goto cleanup;
            if (VIR_CLOSE(stdinfd) < 0)
                goto cleanup;
            if (VIR_CLOSE(stdoutfd) < 0)
                goto cleanup;

            if (setsid() < 0)
                goto cleanup;

            nextpid = fork();
            switch (nextpid) {
            case 0: /* grandchild */
                return statuspipe[1];
            case -1: /* error */
                goto cleanup;
            default: /* intermediate child succeeded */
                _exit(EXIT_SUCCESS);
            }

         cleanup:
            VIR_FORCE_CLOSE(stdoutfd);
            VIR_FORCE_CLOSE(stdinfd);
            VIR_FORCE_CLOSE(statuspipe[1]);
            _exit(EXIT_FAILURE);

        }

    case -1: /* error in parent */
        goto error;

    default:
        {
            /* parent */
            int got, exitstatus = 0;
            int ret;
            char status;

            VIR_FORCE_CLOSE(statuspipe[1]);

            /* We wait to make sure the first child forked successfully */
            if ((got = waitpid(pid, &exitstatus, 0)) < 0 ||
                got != pid ||
                exitstatus != 0) {
                goto error;
            }

            /* If we got here, then the grandchild was spawned, so we
             * must exit. Block until the second child initializes
             * successfully */
            ret = saferead(statuspipe[0], &status, 1);

            VIR_FORCE_CLOSE(statuspipe[0]);

            if (ret != 1) {
                fprintf(stderr,
                        _("%1$s: error: unable to determine if daemon is running: %2$s\n"),
                        argv0,
                        g_strerror(errno));
                exit(EXIT_FAILURE);
            } else if (status != 0) {
                fprintf(stderr,
                        _("%1$s: error: %2$s. Check /var/log/messages or run without --daemon for more info.\n"),
                        argv0,
                        virDaemonErrTypeToString(status));
                exit(EXIT_FAILURE);
            }
            _exit(EXIT_SUCCESS);
        }
    }

 error:
    VIR_FORCE_CLOSE(statuspipe[0]);
    VIR_FORCE_CLOSE(statuspipe[1]);
    return -1;
}

#else /* WIN32 */

/* Inherited handle of the status pipe, in the daemon relaunched in background */
# define VIR_DAEMON_STATUS_HANDLE_ENV "LIBVIRT_DAEMON_STATUS_HANDLE"

/*
 * There is no fork(): the daemon relaunches itself with the same command
 * line, detached from the console, and the new process returns the write
 * end of the status pipe from here, as the POSIX grandchild does.
 */
int
virDaemonForkIntoBackground(const char *argv0)
{
    const char *inherited = g_getenv(VIR_DAEMON_STATUS_HANDLE_ENV);
    g_autofree char *attrbuf = NULL;
    g_autofree char *handlestr = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SIZE_T attrsize = 0;
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    WCHAR exe[MAX_PATH];
    HANDLE devnull = INVALID_HANDLE_VALUE;
    HANDLE statusread = NULL;
    HANDLE statuswrite = NULL;
    SECURITY_ATTRIBUTES inherit = { sizeof(inherit), NULL, TRUE };
    HANDLE handles[2];
    DWORD got = 0;
    char status;

    if (inherited) {
        /* the relaunched daemon */
        intptr_t handle = (intptr_t) g_ascii_strtoll(inherited, NULL, 10);

        g_unsetenv(VIR_DAEMON_STATUS_HANDLE_ENV);
        return _open_osfhandle(handle, _O_WRONLY | _O_BINARY);
    }

    if (!CreatePipe(&statusread, &statuswrite, &inherit, 0) ||
        !SetHandleInformation(statusread, HANDLE_FLAG_INHERIT, 0))
        goto error;
    devnull = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                          OPEN_EXISTING, 0, NULL);
    if (devnull == INVALID_HANDLE_VALUE)
        goto error;

    handlestr = g_strdup_printf("%lld", (long long) (intptr_t) statuswrite);
    g_setenv(VIR_DAEMON_STATUS_HANDLE_ENV, handlestr, TRUE);

    /* stdio on NUL, and only the status pipe inherited */
    handles[0] = devnull;
    handles[1] = statuswrite;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrsize);
    attrbuf = g_new0(char, attrsize);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST) attrbuf;
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrsize) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   handles, sizeof(handles), NULL, NULL))
        goto error;
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = devnull;
    si.StartupInfo.hStdOutput = devnull;
    si.StartupInfo.hStdError = devnull;
    si.lpAttributeList = attrs;

    if (!GetModuleFileNameW(NULL, exe, G_N_ELEMENTS(exe)) ||
        !CreateProcessW(exe, GetCommandLineW(), NULL, NULL, TRUE,
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
                        EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &si.StartupInfo, &pi))
        goto error;
    g_unsetenv(VIR_DAEMON_STATUS_HANDLE_ENV);
    DeleteProcThreadAttributeList(attrs);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(devnull);
    CloseHandle(statuswrite);

    /* Block until the daemon initializes successfully */
    if (!ReadFile(statusread, &status, 1, &got, NULL) || got != 1) {
        fprintf(stderr,
                _("%1$s: error: unable to determine if daemon is running: %2$s\n"),
                argv0, g_strerror(EPIPE));
        exit(EXIT_FAILURE);
    } else if (status != 0) {
        fprintf(stderr,
                _("%1$s: error: %2$s. Check the log file or run without --daemon for more info.\n"),
                argv0, virDaemonErrTypeToString(status));
        exit(EXIT_FAILURE);
    }
    _exit(EXIT_SUCCESS);

 error:
    g_unsetenv(VIR_DAEMON_STATUS_HANDLE_ENV);
    if (attrs)
        DeleteProcThreadAttributeList(attrs);
    if (devnull != INVALID_HANDLE_VALUE)
        CloseHandle(devnull);
    if (statusread)
        CloseHandle(statusread);
    if (statuswrite)
        CloseHandle(statuswrite);
    errno = ECHILD;
    return -1;
}

#endif /* WIN32 */


/*
 * Set up the logging environment
 * By default if daemonized all errors go to the logfile libvirtd.log,
 * but if verbose or error debugging is asked for then also output
 * informational and debug messages. Default size if 64 kB.
 */
int
virDaemonSetupLogging(const char *daemon_name,
                      unsigned int log_level,
                      char *log_filters,
                      char *log_outputs,
                      bool privileged,
                      bool verbose,
                      bool godaemon)
{
    if (virLogReset() < 0)
        return -1;

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * Given the precedence, we must process the variables in the opposite
     * order, each one overriding the previous.
     */
    if (log_level != 0 &&
        virLogSetDefaultPriority(log_level) < 0)
        return -1;

    /* In case the config is empty, both filters and outputs will become empty,
     * however we can't start with empty outputs, thus we'll need to define and
     * setup a default one.
     */
    if (virLogSetFilters(log_filters) < 0 ||
        virLogSetOutputs(log_outputs) < 0)
        return -1;

    /* If there are some environment variables defined, use those instead */
    if (virLogSetFromEnv() < 0)
        return -1;

    /*
     * Command line override for --verbose
     */
    if (verbose &&
        virLogGetDefaultPriority() > VIR_LOG_INFO &&
        virLogSetDefaultPriority(VIR_LOG_INFO) < 0)
        return -1;

    /* Define the default output. This is only applied if there was no setting
     * from either the config or the environment.
     */
    if (virLogSetDefaultOutput(daemon_name, godaemon, privileged) < 0)
        return -1;

    if (virLogGetNbOutputs() == 0 &&
        virLogSetOutputs(virLogGetDefaultOutput()) < 0)
        return -1;

    return 0;
}


int
virDaemonUnixSocketPaths(const char *sock_prefix,
                         bool privileged,
                         char *unix_sock_dir,
                         char **sockfile,
                         char **rosockfile,
                         char **admsockfile)
{
    if (unix_sock_dir) {
        if (sockfile)
            *sockfile = g_strdup_printf("%s/%s-sock", unix_sock_dir, sock_prefix);

        if (privileged) {
            if (rosockfile)
                *rosockfile = g_strdup_printf("%s/%s-sock-ro",
                                              unix_sock_dir, sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/%s-admin-sock",
                                               unix_sock_dir, sock_prefix);
        }
    } else {
        if (privileged) {
            if (sockfile)
                *sockfile = g_strdup_printf("%s/libvirt/%s-sock",
                                            VIR_INSTALL_PATH(RUNSTATEDIR), sock_prefix);
            if (rosockfile)
                *rosockfile = g_strdup_printf("%s/libvirt/%s-sock-ro",
                                              VIR_INSTALL_PATH(RUNSTATEDIR), sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/libvirt/%s-admin-sock",
                                               VIR_INSTALL_PATH(RUNSTATEDIR), sock_prefix);
        } else {
            mode_t old_umask;
            g_autofree char *rundir = virGetUserRuntimeDirectory();

            old_umask = umask(077);
            if (g_mkdir_with_parents(rundir, 0777) < 0) {
                umask(old_umask);
                return -1;
            }
            umask(old_umask);

            if (sockfile)
                *sockfile = g_strdup_printf("%s/%s-sock", rundir, sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/%s-admin-sock", rundir, sock_prefix);
        }
    }

    return 0;
}

