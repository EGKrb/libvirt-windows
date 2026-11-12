/*
 * nwfilter_win32_pcap.h: what the IP address learning and the DHCP
 * snooping of nwfilter use of libpcap, on the ports of the switch of a
 * libvirt network on Windows
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * On Linux they capture on the TAP device of the guest; on Windows the
 * switch of the network (libvirt_netswitch) gives a copy of the frames to
 * and from the port of an interface on its monitor socket (ports/NAME.mon),
 * with their direction. The filters are the expressions nwfilter uses:
 * "src port N", "dst port N", "ether host MAC", "ether src MAC",
 * "ether dst MAC", joined by "and" and "or" (of the same precedence, from
 * left to right, as in pcap-filter(7)).
 */

#pragma once

#ifdef WIN32

# include <winsock2.h>
# include <stdint.h>

# define PCAP_ERRBUF_SIZE 256
# define PCAP_NETMASK_UNKNOWN 0xffffffff
# define PCAP_ERROR -1

typedef uint32_t bpf_u_int32;
typedef unsigned char u_char;

typedef struct pcap pcap_t;

typedef enum {
    PCAP_D_INOUT = 0,
    PCAP_D_IN,                  /* sent by the guest */
    PCAP_D_OUT,                 /* sent to the guest */
} pcap_direction_t;

struct bpf_program {
    unsigned int bf_len;
    void *bf_insns;             /* the parsed expression */
};

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

pcap_t *pcap_create(const char *source, char *errbuf);
int pcap_set_snaplen(pcap_t *p, int snaplen);
int pcap_set_immediate_mode(pcap_t *p, int immediate);
int pcap_activate(pcap_t *p);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                       int to_ms, char *errbuf);
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
                 int optimize, bpf_u_int32 netmask);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
void pcap_freecode(struct bpf_program *fp);
int pcap_setdirection(pcap_t *p, pcap_direction_t d);
int pcap_fileno(pcap_t *p);
char *pcap_geterr(pcap_t *p);
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data);
void pcap_close(pcap_t *p);

#endif /* WIN32 */
