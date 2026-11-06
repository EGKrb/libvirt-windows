/*
 * Copyright (C) 2020 Red Hat, Inc.
 * Copyright (C) 2011-2021 Free Software Foundation, Inc.
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

#include <gio/gio.h>

#include "virsocket.h"
#include "virutil.h"
#include "virfile.h"

#include <fcntl.h>

#ifdef WIN32

# define FD2SK(fd) _get_osfhandle(fd)
# define SK2FD(sk) (_open_osfhandle((intptr_t) (sk), O_RDWR | O_BINARY))

# define GET_HANDLE(fd) \

# define RETURN_ERROR(call) \
    if ((call) < 0) { \
        set_errno(); \
        return -1; \
    }

# undef accept
# undef bind
# undef closesocket
# undef connect
# undef getpeername
# undef getsockname
# undef getsockopt
# undef ioctlsocket
# undef listen
# undef setsockopt
# undef socket

static void
set_errno(void)
{
    int err = WSAGetLastError();

    /* Map some WSAE* errors to the runtime library's error codes.  */
    switch (err) {
    case WSA_INVALID_HANDLE:
        errno = EBADF;
        break;
    case WSA_NOT_ENOUGH_MEMORY:
        errno = ENOMEM;
        break;
    case WSA_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    case WSAENAMETOOLONG:
        errno = ENAMETOOLONG;
        break;
    case WSAENOTEMPTY:
        errno = ENOTEMPTY;
        break;
    case WSAEWOULDBLOCK:
        /* EWOULDBLOCK is EAGAIN on POSIX hosts, which callers check for,
         * but a distinct value in the Windows C runtime */
        errno = EAGAIN;
        break;
    case WSAEINPROGRESS:
        errno = EINPROGRESS;
        break;
    case WSAEALREADY:
        errno = EALREADY;
        break;
    case WSAENOTSOCK:
        errno = ENOTSOCK;
        break;
    case WSAEDESTADDRREQ:
        errno = EDESTADDRREQ;
        break;
    case WSAEMSGSIZE:
        errno = EMSGSIZE;
        break;
    case WSAEPROTOTYPE:
        errno = EPROTOTYPE;
        break;
    case WSAENOPROTOOPT:
        errno = ENOPROTOOPT;
        break;
    case WSAEPROTONOSUPPORT:
        errno = EPROTONOSUPPORT;
        break;
    case WSAEOPNOTSUPP:
        errno = EOPNOTSUPP;
        break;
    case WSAEAFNOSUPPORT:
        errno = EAFNOSUPPORT;
        break;
    case WSAEADDRINUSE:
        errno = EADDRINUSE;
        break;
    case WSAEADDRNOTAVAIL:
        errno = EADDRNOTAVAIL;
        break;
    case WSAENETDOWN:
        errno = ENETDOWN;
        break;
    case WSAENETUNREACH:
        errno = ENETUNREACH;
        break;
    case WSAENETRESET:
        errno = ENETRESET;
        break;
    case WSAECONNABORTED:
        errno = ECONNABORTED;
        break;
    case WSAECONNRESET:
        errno = ECONNRESET;
        break;
    case WSAENOBUFS:
        errno = ENOBUFS;
        break;
    case WSAEISCONN:
        errno = EISCONN;
        break;
    case WSAENOTCONN:
        errno = ENOTCONN;
        break;
    case WSAETIMEDOUT:
        errno = ETIMEDOUT;
        break;
    case WSAECONNREFUSED:
        errno = ECONNREFUSED;
        break;
    case WSAELOOP:
        errno = ELOOP;
        break;
    case WSAEHOSTUNREACH:
        errno = EHOSTUNREACH;
        break;
    default:
        errno = (err > 10000 && err < 10025) ? err - 10000 : err;
        break;
    }
}


int
vir_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);
    SOCKET csk;

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    csk = accept(sk, addr, addrlen);

    if (csk == INVALID_SOCKET) {
        set_errno();
        return -1;
    }

    return SK2FD(csk);
}


/*
 * read() and write() cannot be used on non-blocking sockets on Windows:
 * they are not files.
 */
ssize_t
vir_recv(int fd, void *buf, size_t len)
{
    SOCKET sk = FD2SK(fd);
    int ret;

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    ret = recv(sk, buf, MIN(len, INT_MAX), 0);
    if (ret == SOCKET_ERROR) {
        set_errno();
        return -1;
    }

    return ret;
}


ssize_t
vir_send(int fd, const void *buf, size_t len)
{
    SOCKET sk = FD2SK(fd);
    int ret;

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    ret = send(sk, buf, MIN(len, INT_MAX), 0);
    if (ret == SOCKET_ERROR) {
        set_errno();
        return -1;
    }

    return ret;
}


int
vir_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (bind(sk, addr, addrlen) < 0)  {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_closesocket(int fd)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (closesocket(sk) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (connect(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getpeername(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getsockname(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_listen(int fd, int backlog)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (listen(sk, backlog) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_ioctlsocket(int fd, int cmd, void *arg)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (ioctlsocket(sk, cmd, arg) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getsockopt(sk, level, optname, optval, optlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (setsockopt(sk, level, optname, optval, optlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_socket(int domain, int type, int protocol)
{
    SOCKET sk;

    /* We have to use WSASocket() instead of socket(), to create
     * non-overlapped IO sockets. Overlapped IO sockets cannot
     * be used with read/write.
     */
    sk = WSASocket(domain, type, protocol, NULL, 0, 0);
    if (sk == INVALID_SOCKET) {
        set_errno();
        return -1;
    }

    return SK2FD(sk);
}

#endif /* WIN32 */


#ifdef WIN32
static ssize_t
virSocketGLibResult(gssize ret, GError *err)
{
    if (ret >= 0)
        return ret;
    if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        errno = EAGAIN;
    else if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED) ||
             g_error_matches(err, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))
        errno = ECONNRESET;
    else
        errno = EIO;
    return -1;
}


/* recv() through @sock, without blocking; -1 with errno set on failure */
ssize_t
virSocketGLibRecv(GSocket *sock, void *buf, size_t len)
{
    g_autoptr(GError) err = NULL;
    gssize ret = g_socket_receive_with_blocking(sock, buf, len, FALSE, NULL, &err);

    return virSocketGLibResult(ret, err);
}


/* send() through @sock, without blocking; -1 with errno set on failure */
ssize_t
virSocketGLibSend(GSocket *sock, const void *buf, size_t len)
{
    g_autoptr(GError) err = NULL;
    gssize ret = g_socket_send_with_blocking(sock, buf, len, FALSE, NULL, &err);

    return virSocketGLibResult(ret, err);
}
#endif /* WIN32 */


/**
 * virSocketGLibFD:
 * @fd: a socket
 *
 * Returns the fd to give to g_socket_new_from_fd(), which then owns it: on
 * POSIX @fd itself; on Windows, where GSocket owns a SOCKET handle, a
 * duplicate of the handle of @fd, so that @fd keeps its own and must still
 * be closed.  Returns -1 with errno set on failure.
 */
int
virSocketGLibFD(int fd)
{
#ifdef WIN32
    SOCKET sk = FD2SK(fd);
    HANDLE dup;

    if (sk == INVALID_SOCKET ||
        !DuplicateHandle(GetCurrentProcess(), (HANDLE) sk, GetCurrentProcess(),
                         &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        errno = EBADF;
        return -1;
    }
    return (int) (intptr_t) dup;
#else
    return fd;
#endif
}


/**
 * virSocketGLibFDFree:
 * @gfd: a result of virSocketGLibFD() that no GSocket took
 */
void
virSocketGLibFDFree(int gfd G_GNUC_UNUSED)
{
#ifdef WIN32
    if (gfd >= 0)
        CloseHandle((HANDLE) (intptr_t) gfd);
#endif
}


/**
 * virSocketPair:
 * @fds: filled with two connected sockets
 *
 * socketpair(AF_UNIX, SOCK_STREAM), which Windows lacks: there the two
 * sockets are connected through a listener on a private temporary path,
 * removed at once.
 *
 * Returns 0 on success, -1 with errno set on failure.
 */
int
virSocketPair(int fds[2])
{
#ifndef WIN32
    return socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
#else
    static int counter;
    g_autofree char *path = NULL;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int listenfd = -1;
    int saved;

    fds[0] = fds[1] = -1;
    path = g_strdup_printf("%s/libvirt-pair-%lld-%d-%u", g_get_tmp_dir(),
                           (long long) getpid(), g_atomic_int_add(&counter, 1),
                           g_random_int());
    if (g_strlcpy(addr.sun_path, path, sizeof(addr.sun_path)) >=
        sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if ((listenfd = vir_socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ||
        vir_bind(listenfd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        vir_listen(listenfd, 1) < 0 ||
        (fds[1] = vir_socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ||
        vir_connect(fds[1], (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        (fds[0] = vir_accept(listenfd, NULL, NULL)) < 0)
        goto error;

    vir_closesocket(listenfd);
    unlink(path);
    return 0;

 error:
    saved = errno;
    if (listenfd >= 0) {
        vir_closesocket(listenfd);
        unlink(path);
    }
    if (fds[0] >= 0)
        vir_closesocket(fds[0]);
    if (fds[1] >= 0)
        vir_closesocket(fds[1]);
    fds[0] = fds[1] = -1;
    errno = saved;
    return -1;
#endif
}


/* The following two methods are derived from GNULIB's
 * passfd code */

/* MSG_CMSG_CLOEXEC is defined only on Linux, as of 2011.  */
#ifndef MSG_CMSG_CLOEXEC
# define MSG_CMSG_CLOEXEC 0
#endif

#ifndef WIN32
/* virSocketSendFD sends the file descriptor fd along the socket
   to a process calling virSocketRecvFD on the other end.

   Return 1 on success, or -1 with errno set in case of error.
*/
int
virSocketSendFD(int sock, int fd)
{
    char byte = 0;
    int fds[] = { fd };

    return virSocketSendMsgWithFDs(sock, &byte, sizeof(byte),
                                   fds, G_N_ELEMENTS(fds));
}


/* virSocketRecvFD receives a file descriptor through the socket.
   The flags are a bitmask, possibly including O_CLOEXEC (defined in <fcntl.h>).

   Return the fd on success, or -1 with errno set in case of error.
*/
int
virSocketRecvFD(int sock, int fdflags)
{
    char byte = 0;
    struct iovec iov;
    struct msghdr msg = { 0 };
    int fd = -1;
    ssize_t len;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];
    int fdflags_recvmsg = fdflags & O_CLOEXEC ? MSG_CMSG_CLOEXEC : 0;

    if ((fdflags & ~O_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }

    /* send at least one char */
    iov.iov_base = &byte;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    /* Initialize the payload: */
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    len = recvmsg(sock, &msg, fdflags_recvmsg);
    if (len < 0)
        return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    /* be paranoiac */
    if (len == 0 || cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))
        || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        /* fake errno: at end the file is not available */
        errno = len ? EACCES : ENOTCONN;
        return -1;
    }

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

    /* set close-on-exec flag */
    if (!MSG_CMSG_CLOEXEC && (fdflags & O_CLOEXEC)) {
        if (virSetCloseExec(fd) < 0) {
            VIR_FORCE_CLOSE(fd);
            return -1;
        }
    }

    return fd;
}


/**
 * virSocketSendMsgWithFDs:
 * @sock: socket to send payload and fds to
 * @payload: payload to send
 * @payload_len: length of @payload
 * @fds: array of fds to send
 * @fds_len: len of fds array

 * Send @fds along with @payload to @sock using SCM_RIGHTS.
 * Return number of bytes sent on success.
 * On error, set errno and return -1.
 */
int
virSocketSendMsgWithFDs(int sock,
                        const char *payload,
                        size_t payload_len,
                        int *fds,
                        size_t fds_len)
{
    g_autofree char *control = NULL;
    const size_t control_size = CMSG_SPACE(sizeof(int) * fds_len);
    struct cmsghdr *cmsg;
    struct msghdr msg = { 0 };
    struct iovec iov[1]; /* Send a single payload, so set vector len to 1 */
    int ret;

    control = g_new0(char, control_size);

    iov[0].iov_base = (void *) payload;
    iov[0].iov_len = payload_len;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control;
    msg.msg_controllen = control_size;

    cmsg = CMSG_FIRSTHDR(&msg);
    /* check to eliminate "potential null pointer dereference" errors during build */
    if (!cmsg) {
        errno = ENOSPC;
        return -1;
    }

    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fds_len);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * fds_len);

    do {
        ret = sendmsg(sock, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

#else /* WIN32 */
int
virSocketSendFD(int sock G_GNUC_UNUSED, int fd G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}

int
virSocketRecvFD(int sock G_GNUC_UNUSED, int fdflags G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}

int
virSocketSendMsgWithFDs(int sock G_GNUC_UNUSED,
                        const char *payload G_GNUC_UNUSED,
                        size_t payload_len G_GNUC_UNUSED,
                        int *fds G_GNUC_UNUSED,
                        size_t fds_len G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif  /* WIN32 */
