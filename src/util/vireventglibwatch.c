/*
 * vireventglibwatch.c: GSource impl for sockets
 *
 * Copyright (C) 2015-2020 Red Hat, Inc.
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
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "vireventglibwatch.h"

#ifndef WIN32
typedef struct virEventGLibFDSource virEventGLibFDSource;
struct virEventGLibFDSource {
    GSource parent;
    GPollFD pollfd;
    int fd;
    GIOCondition condition;
};


static gboolean
virEventGLibFDSourcePrepare(GSource *source G_GNUC_UNUSED,
                            gint *timeout)
{
    *timeout = -1;

    return FALSE;
}


static gboolean
virEventGLibFDSourceCheck(GSource *source)
{
    virEventGLibFDSource *ssource = (virEventGLibFDSource *)source;

    return ssource->pollfd.revents & ssource->condition;
}


static gboolean
virEventGLibFDSourceDispatch(GSource *source,
                             GSourceFunc callback,
                             gpointer user_data)
{
    virEventGLibSocketFunc func = (virEventGLibSocketFunc)callback;
    virEventGLibFDSource *ssource = (virEventGLibFDSource *)source;

    return (*func)(ssource->fd,
                   ssource->pollfd.revents & ssource->condition,
                   user_data);
}


static void
virEventGLibFDSourceFinalize(GSource *source G_GNUC_UNUSED)
{
}


GSourceFuncs virEventGLibFDSourceFuncs = {
    .prepare = virEventGLibFDSourcePrepare,
    .check = virEventGLibFDSourceCheck,
    .dispatch = virEventGLibFDSourceDispatch,
    .finalize = virEventGLibFDSourceFinalize
};


GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition)
{
    GSource *source;
    virEventGLibFDSource *ssource;

    source = g_source_new(&virEventGLibFDSourceFuncs,
                          sizeof(virEventGLibFDSource));
    ssource = (virEventGLibFDSource *)source;

    ssource->condition = condition | G_IO_HUP | G_IO_ERR;
    ssource->fd = fd;

    ssource->pollfd.fd = fd;
    ssource->pollfd.events = condition | G_IO_HUP | G_IO_ERR;

    g_source_add_poll(source, &ssource->pollfd);

    return source;
}

#else /* WIN32 */

# define WIN32_LEAN_AND_MEAN
# include <winsock2.h>

typedef struct virEventGLibSocketSource virEventGLibSocketSource;
struct virEventGLibSocketSource {
    GSource parent;
    GPollFD pollfd;
    int fd;
    SOCKET socket;
    HANDLE event;
    int revents;
    GIOCondition condition;
};


/*
 * A socket has a single WSAEventSelect() association, yet it can have
 * several watches: one for reading and one for writing when it is both
 * stdin and stdout, or an old watch being finalized after its replacement
 * was created.  So all the watches of a socket share one event, each
 * waiting on its own duplicate of the handle (GLib cannot wait twice on
 * the same handle), and the association lasts as long as one of them.
 */
typedef struct {
    HANDLE event;
    unsigned int refs;
} virEventGLibSocketEvent;

static GHashTable *socketEvents;
static GMutex socketEventsLock;


static gboolean virEventGLibSocketSourceCheck(GSource *source);


/*
 * WSAEventSelect() events are edge triggered: FD_WRITE for instance is only
 * signaled once after connecting, so a watch created on a socket that is
 * already ready would never wake up.  Check the actual state of the socket
 * first, as poll() would.
 */
static gboolean
virEventGLibSocketSourcePrepare(GSource *source,
                                gint *timeout)
{
    *timeout = -1;

    return virEventGLibSocketSourceCheck(source);
}


/*
 * NB, this impl only works when the socket is in non-blocking
 * mode on Win32
 */
static gboolean
virEventGLibSocketSourceCheck(GSource *source)
{
    static struct timeval tv0;

    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;
    WSANETWORKEVENTS ev;
    fd_set rfds, wfds, xfds;

    if (!ssource->condition)
        return 0;

    WSAEnumNetworkEvents(ssource->socket, ssource->event, &ev);

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);
    if (ssource->condition & G_IO_IN)
        FD_SET(ssource->socket, &rfds);
    if (ssource->condition & G_IO_OUT)
        FD_SET(ssource->socket, &wfds);
    if (ssource->condition & G_IO_PRI)
        FD_SET(ssource->socket, &xfds);

    ssource->revents = 0;
    if (select(0, &rfds, &wfds, &xfds, &tv0) == 0)
        return 0;

    if (FD_ISSET(ssource->socket, &rfds))
        ssource->revents |= G_IO_IN;

    if (FD_ISSET(ssource->socket, &wfds))
        ssource->revents |= G_IO_OUT;

    if (FD_ISSET(ssource->socket, &xfds))
        ssource->revents |= G_IO_PRI;

    return ssource->revents;
}


static gboolean
virEventGLibSocketSourceDispatch(GSource *source,
                                 GSourceFunc callback,
                                 gpointer user_data)
{
    virEventGLibSocketFunc func = (virEventGLibSocketFunc)callback;
    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;

    return (*func)(ssource->fd, ssource->revents, user_data);
}


static gboolean
virEventGLibSocketCloseHandle(gpointer handle)
{
    CloseHandle(handle);
    return G_SOURCE_REMOVE;
}


static void
virEventGLibSocketSourceFinalize(GSource *source)
{
    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;
    gpointer key = GSIZE_TO_POINTER(ssource->socket);
    virEventGLibSocketEvent *shared;
    GMainContext *context = g_source_get_context(source);

    /*
     * A watch replaced from another thread is finalized while the thread
     * of its context may be waiting on its handle: close the handle at the
     * next iteration of that context, which no longer waits on it.
     */
    if (context) {
        GSource *idle = g_idle_source_new();

        g_source_set_callback(idle, virEventGLibSocketCloseHandle,
                              ssource->event, NULL);
        g_source_attach(idle, context);
        g_source_unref(idle);
    } else {
        CloseHandle(ssource->event);
    }

    g_mutex_lock(&socketEventsLock);
    shared = g_hash_table_lookup(socketEvents, key);
    if (shared && --shared->refs == 0) {
        WSAEventSelect(ssource->socket, NULL, 0);
        CloseHandle(shared->event);
        g_hash_table_remove(socketEvents, key);
    }
    g_mutex_unlock(&socketEventsLock);
}


GSourceFuncs virEventGLibSocketSourceFuncs = {
    .prepare = virEventGLibSocketSourcePrepare,
    .check = virEventGLibSocketSourceCheck,
    .dispatch = virEventGLibSocketSourceDispatch,
    .finalize = virEventGLibSocketSourceFinalize
};


GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition)
{
    GSource *source;
    virEventGLibSocketSource *ssource;
    virEventGLibSocketEvent *shared;

    source = g_source_new(&virEventGLibSocketSourceFuncs,
                          sizeof(virEventGLibSocketSource));
    ssource = (virEventGLibSocketSource *)source;

    ssource->condition = condition;
    ssource->fd = fd;
    ssource->socket = _get_osfhandle(fd);
    ssource->revents = 0;

    g_mutex_lock(&socketEventsLock);
    if (!socketEvents)
        socketEvents = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    shared = g_hash_table_lookup(socketEvents, GSIZE_TO_POINTER(ssource->socket));
    if (!shared) {
        shared = g_new0(virEventGLibSocketEvent, 1);
        shared->event = CreateEvent(NULL, FALSE, FALSE, NULL);
        g_hash_table_insert(socketEvents, GSIZE_TO_POINTER(ssource->socket),
                            shared);
    }
    shared->refs++;
    /* again for every watch, in case the handle value of a closed socket
     * was reused */
    WSAEventSelect(ssource->socket, shared->event,
                   FD_READ | FD_ACCEPT | FD_CLOSE |
                   FD_CONNECT | FD_WRITE | FD_OOB);
    DuplicateHandle(GetCurrentProcess(), shared->event, GetCurrentProcess(),
                    &ssource->event, 0, FALSE, DUPLICATE_SAME_ACCESS);
    g_mutex_unlock(&socketEventsLock);

    ssource->pollfd.fd = (gintptr)ssource->event;
    ssource->pollfd.events = G_IO_IN;

    g_source_add_poll(source, &ssource->pollfd);

    return source;
}

#endif /* WIN32 */


GSource *
virEventGLibAddSocketWatch(int fd,
                           GIOCondition condition,
                           GMainContext *context,
                           virEventGLibSocketFunc func,
                           gpointer opaque,
                           GDestroyNotify notify)
{
    GSource *source = NULL;

    source = virEventGLibCreateSocketWatch(fd, condition);
    g_source_set_callback(source, (GSourceFunc)func, opaque, notify);

    g_source_attach(source, context);

    return source;
}
