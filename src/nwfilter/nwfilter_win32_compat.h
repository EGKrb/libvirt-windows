/*
 * nwfilter_win32_compat.h: what the IP address learning of nwfilter takes
 * from <net/ethernet.h>, <net/if_arp.h>, <net/if.h> and <poll.h> on Linux
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#ifdef WIN32

# include <winsock2.h>
# include <ws2tcpip.h>
# include <stdint.h>

# ifndef ETH_ALEN
#  define ETH_ALEN 6
# endif

# ifndef ETHERTYPE_IP
#  define ETHERTYPE_IP 0x0800
# endif
# ifndef ETHERTYPE_ARP
#  define ETHERTYPE_ARP 0x0806
# endif
# ifndef ETHERTYPE_REVARP
#  define ETHERTYPE_REVARP 0x8035
# endif
# ifndef ETHERTYPE_VLAN
#  define ETHERTYPE_VLAN 0x8100
# endif
# ifndef ETHERTYPE_IPV6
#  define ETHERTYPE_IPV6 0x86dd
# endif

struct ether_header {
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
} __attribute__((__packed__));

# define ARPHRD_ETHER 1
# define ARPOP_REQUEST 1
# define ARPOP_REPLY 2

struct arphdr {
    unsigned short ar_hrd;
    unsigned short ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short ar_op;
};

/* <netinet/ip.h> and <netinet/udp.h> of Linux, for x86 */
/* uint8_t bit fields: with the -mms-bitfields of MinGW, unsigned int ones
 * would take 4 bytes */
struct iphdr {
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

_Static_assert(sizeof(struct iphdr) == 20, "struct iphdr of Linux");
_Static_assert(sizeof(struct udphdr) == 8, "struct udphdr of Linux");

# ifndef IF_NAMESIZE
#  define IF_NAMESIZE 256
# endif
# ifndef IFNAMSIZ
#  define IFNAMSIZ IF_NAMESIZE
# endif

# include <errno.h>

/* struct pollfd and POLLIN come with winsock2.h; the descriptors polled
 * are sockets (those of the switch, see nwfilter_win32_pcap.h).  As
 * poll(2): POLLERR, POLLHUP and POLLNVAL are ignored in events (WSAPoll()
 * fails with them), errno is set on failure */
static inline int
nwfilterWin32Poll(struct pollfd *fds, unsigned long nfds, int timeout)
{
    unsigned long i;
    int rc;

    for (i = 0; i < nfds; i++)
        fds[i].events &= POLLRDNORM | POLLRDBAND | POLLWRNORM;
    rc = WSAPoll(fds, nfds, timeout);
    if (rc < 0)
        errno = WSAGetLastError() == WSAEINTR ? EINTR : EIO;
    return rc;
}

# define poll(fds, nfds, timeout) nwfilterWin32Poll((fds), (nfds), (timeout))

#endif /* WIN32 */
