/*
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "internal.h"

int virSocketPair(int fds[2]);
#ifdef WIN32
int virSocketPairRelay(int fds[2]);
#endif
int virSocketGLibFD(int fd);
void virSocketGLibFDFree(int gfd);

/*
 * I/O on a socket watched by a GSocket source (QEMU monitor, guest agent):
 * on Windows GLib tells when such a socket is ready from the I/O done
 * through the GSocket, so the I/O has to go through it.
 */
#ifdef WIN32
struct _GSocket;
ssize_t virSocketGLibRecv(struct _GSocket *sock, void *buf, size_t len);
ssize_t virSocketGLibSend(struct _GSocket *sock, const void *buf, size_t len);
# define virSocketRecvWatched(gsock, fd, buf, len) virSocketGLibRecv(gsock, buf, len)
# define virSocketSendWatched(gsock, fd, buf, len) virSocketGLibSend(gsock, buf, len)
#else
# define virSocketRecvWatched(gsock, fd, buf, len) read(fd, buf, len)
# define virSocketSendWatched(gsock, fd, buf, len) write(fd, buf, len) /* sc_avoid_write */
#endif

/* read() and write() on a socket: Windows needs recv() and send() */
#ifdef WIN32
# define virSocketRecv(fd, buf, len) vir_recv(fd, buf, len)
# define virSocketSend(fd, buf, len) vir_send(fd, buf, len)
#else
# define virSocketRecv(fd, buf, len) read(fd, buf, len)
# define virSocketSend(fd, buf, len) write(fd, buf, len) /* sc_avoid_write */
#endif
int virSocketSendFD(int sock, int fd);
int virSocketRecvFD(int sock, int fdflags);
int virSocketSendMsgWithFDs(int sock, const char *payload, size_t payload_len,
                            int *fds, size_t fds_len);

#ifdef WIN32

# define WIN32_LEAN_AND_MEAN
# include <errno.h>
# include <winsock2.h>
# include <ws2tcpip.h>
# include <afunix.h>
# include <io.h>

/* AF_UNIX stream sockets exist since Windows 10 1803 */
# ifndef PF_UNIX
#  define PF_UNIX AF_UNIX
# endif

int vir_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t vir_recv(int fd, void *buf, size_t len);
ssize_t vir_send(int fd, const void *buf, size_t len);
int vir_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int vir_closesocket(int fd);
int vir_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int vir_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
int vir_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int vir_listen(int fd, int backlog);
int vir_ioctlsocket(int fd, int cmd, void *arg);
int vir_getsockopt(int fd, int level, int optname,
                   void *optval, socklen_t *optlen);
int vir_setsockopt(int fd, int level, int optname,
                   const void *optval, socklen_t optlen);
int vir_socket(int domain, int type, int protocol);


/* Provide our own replacements */
# define accept vir_accept
# define bind vir_bind
# define closesocket vir_closesocket
# define connect vir_connect
# define dup _dup
# define dup2 _dup2
# define ioctlsocket vir_ioctlsocket
# define getpeername vir_getpeername
# define getsockname vir_getsockname
# define getsockopt vir_getsockopt
# define listen vir_listen
# define setsockopt vir_setsockopt
# define socket vir_socket

#else

# include <sys/socket.h>
# include <sys/ioctl.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/in.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <sys/un.h>
# include <netdb.h>

# define closesocket close
# define ioctlsocket ioctl

#endif
