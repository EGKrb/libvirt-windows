/*
 * nwfilter_win32_pcap.c: what the IP address learning and the DHCP
 * snooping of nwfilter use of libpcap, on the ports of the switch of a
 * libvirt network on Windows (see nwfilter_win32_pcap.h)
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "internal.h"
#include "viralloc.h"
#include "virmacaddr.h"
#include "virstring.h"
#include "configmake.h"

#include "nwfilter_win32_pcap.h"

#include <afunix.h>

/* the Winsock API itself, not the file descriptors of virsocket.h: the
 * socket is polled with WSAPoll() */
#undef socket
#undef connect
#undef recv
#undef closesocket
#undef ioctlsocket

#define NS_MON_FRAME_MAX 65536

typedef enum {
    PF_SRC_PORT,
    PF_DST_PORT,
    PF_ETHER_HOST,
    PF_ETHER_SRC,
    PF_ETHER_DST,
} pfTermKind;

typedef struct {
    pfTermKind kind;
    bool orBefore;              /* joined to the previous term by "or" */
    uint16_t port;
    virMacAddr mac;
} pfTerm;

typedef struct {
    pfTerm *terms;
    size_t nterms;
} pfExpr;

struct pcap {
    SOCKET sock;
    char *source;
    pcap_direction_t dir;
    pfExpr filter;
    uint8_t buf[5 + NS_MON_FRAME_MAX];
    struct pcap_pkthdr hdr;
    char err[PCAP_ERRBUF_SIZE];
};


pcap_t *
pcap_create(const char *source, char *errbuf)
{
    pcap_t *p = g_new0(pcap_t, 1);

    p->sock = INVALID_SOCKET;
    p->source = g_strdup(source);
    if (errbuf)
        errbuf[0] = '\0';
    return p;
}


int
pcap_set_snaplen(pcap_t *p G_GNUC_UNUSED, int snaplen G_GNUC_UNUSED)
{
    return 0;
}


int
pcap_set_immediate_mode(pcap_t *p G_GNUC_UNUSED, int immediate G_GNUC_UNUSED)
{
    return 0;
}


/* the monitor socket of the interface on its switch */
int
pcap_activate(pcap_t *p)
{
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    g_autofree char *path = g_strdup_printf("%s/ports/%s.mon",
                                            VIR_INSTALL_PATH(RUNSTATEDIR "/libvirt/network"),
                                            p->source);

    if (strlen(path) >= sizeof(un.sun_path)) {
        g_snprintf(p->err, sizeof(p->err), "path too long: %s", path);
        return PCAP_ERROR;
    }
    g_strlcpy(un.sun_path, path, sizeof(un.sun_path));

    if ((p->sock = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET ||
        connect(p->sock, (struct sockaddr *)&un, sizeof(un)) == SOCKET_ERROR) {
        g_snprintf(p->err, sizeof(p->err),
                   "%s is not a port of the switch of a libvirt network (%s: error %d)",
                   p->source, path, WSAGetLastError());
        if (p->sock != INVALID_SOCKET)
            closesocket(p->sock);
        p->sock = INVALID_SOCKET;
        return PCAP_ERROR;
    }
    return 0;
}


pcap_t *
pcap_open_live(const char *device, int snaplen G_GNUC_UNUSED,
               int promisc G_GNUC_UNUSED, int to_ms G_GNUC_UNUSED,
               char *errbuf)
{
    pcap_t *p = pcap_create(device, errbuf);

    if (pcap_activate(p) < 0) {
        if (errbuf)
            g_strlcpy(errbuf, p->err, PCAP_ERRBUF_SIZE);
        pcap_close(p);
        return NULL;
    }
    return p;
}


int
pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
             int optimize G_GNUC_UNUSED, bpf_u_int32 netmask G_GNUC_UNUSED)
{
    g_auto(GStrv) tok = g_strsplit_set(str, " \t", 0);
    pfExpr *e = g_new0(pfExpr, 1);
    bool orNext = false;
    size_t i = 0;

    while (tok[i]) {
        pfTerm t = { .orBefore = orNext };

        if (!*tok[i]) {
            i++;
            continue;
        }
        if (e->nterms > 0) {
            if (STREQ(tok[i], "and")) {
                orNext = false;
                i++;
                continue;
            }
            if (STREQ(tok[i], "or")) {
                orNext = true;
                i++;
                continue;
            }
        }
        if ((STREQ(tok[i], "src") || STREQ(tok[i], "dst")) &&
            tok[i + 1] && STREQ(tok[i + 1], "port") && tok[i + 2]) {
            unsigned int port;

            if (virStrToLong_ui(tok[i + 2], NULL, 10, &port) < 0 || port > 65535)
                goto error;
            t.kind = STREQ(tok[i], "src") ? PF_SRC_PORT : PF_DST_PORT;
            t.port = port;
            i += 3;
        } else if (STREQ(tok[i], "ether") && tok[i + 1] && tok[i + 2]) {
            if (STREQ(tok[i + 1], "host"))
                t.kind = PF_ETHER_HOST;
            else if (STREQ(tok[i + 1], "src"))
                t.kind = PF_ETHER_SRC;
            else if (STREQ(tok[i + 1], "dst"))
                t.kind = PF_ETHER_DST;
            else
                goto error;
            if (virMacAddrParse(tok[i + 2], &t.mac) < 0)
                goto error;
            i += 3;
        } else {
            goto error;
        }
        VIR_APPEND_ELEMENT(e->terms, e->nterms, t);
        orNext = false;
    }

    fp->bf_len = e->nterms;
    fp->bf_insns = e;
    return 0;

 error:
    g_snprintf(p->err, sizeof(p->err), "unsupported filter expression '%s'", str);
    g_free(e->terms);
    g_free(e);
    return PCAP_ERROR;
}


int
pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    pfExpr *e = fp->bf_insns;

    g_free(p->filter.terms);
    p->filter.nterms = e ? e->nterms : 0;
    p->filter.terms = e ? g_memdup2(e->terms, sizeof(pfTerm) * e->nterms) : NULL;
    return 0;
}


void
pcap_freecode(struct bpf_program *fp)
{
    pfExpr *e = fp->bf_insns;

    if (e) {
        g_free(e->terms);
        g_free(e);
    }
    fp->bf_insns = NULL;
    fp->bf_len = 0;
}


int
pcap_setdirection(pcap_t *p, pcap_direction_t d)
{
    p->dir = d;
    return 0;
}


int
pcap_fileno(pcap_t *p)
{
    return (int)p->sock;
}


char *
pcap_geterr(pcap_t *p)
{
    return p->err;
}


/* TCP, UDP, SCTP or DCCP over IPv4 or IPv6, as "port" in pcap */
static bool
pfPorts(const uint8_t *f, size_t len, uint16_t *sport, uint16_t *dport)
{
    uint16_t type;
    const uint8_t *l4;
    uint8_t proto;

    if (len < 14)
        return false;
    type = (f[12] << 8) | f[13];
    if (type == 0x0800 && len >= 14 + 20) {
        size_t ihl = (f[14] & 0x0f) * 4;

        if (((f[14 + 6] << 8 | f[14 + 7]) & 0x1fff) != 0)
            return false;
        proto = f[14 + 9];
        l4 = f + 14 + ihl;
    } else if (type == 0x86dd && len >= 14 + 40) {
        proto = f[14 + 6];
        l4 = f + 14 + 40;
    } else {
        return false;
    }
    if (proto != 6 && proto != 17 && proto != 132 && proto != 33)
        return false;
    if (l4 + 4 > f + len)
        return false;
    *sport = (l4[0] << 8) | l4[1];
    *dport = (l4[2] << 8) | l4[3];
    return true;
}


static bool
pfTermMatch(const pfTerm *t, const uint8_t *f, size_t len)
{
    uint16_t sport, dport;

    switch (t->kind) {
    case PF_SRC_PORT:
        return pfPorts(f, len, &sport, &dport) && sport == t->port;
    case PF_DST_PORT:
        return pfPorts(f, len, &sport, &dport) && dport == t->port;
    case PF_ETHER_HOST:
        return virMacAddrCmpRaw(&t->mac, f) == 0 || virMacAddrCmpRaw(&t->mac, f + 6) == 0;
    case PF_ETHER_SRC:
        return virMacAddrCmpRaw(&t->mac, f + 6) == 0;
    case PF_ETHER_DST:
        return virMacAddrCmpRaw(&t->mac, f) == 0;
    }
    return false;
}


static bool
pfMatch(const pfExpr *e, const uint8_t *f, size_t len)
{
    bool v = true;
    size_t i;

    if (len < 14)
        return false;
    for (i = 0; i < e->nterms; i++) {
        bool m = pfTermMatch(&e->terms[i], f, len);

        if (i == 0)
            v = m;
        else if (e->terms[i].orBefore)
            v = v || m;
        else
            v = v && m;
    }
    return v;
}


static int
pcapRecvAll(SOCKET s, uint8_t *buf, size_t len)
{
    size_t got = 0;

    while (got < len) {
        int n = recv(s, (char *)buf + got, len - got, 0);

        if (n <= 0)
            return -1;
        got += n;
    }
    return 0;
}


/* 1 with a frame, 0 when no more is there now, -1 when the switch closed
 * the socket */
static int
pcapRead(pcap_t *p)
{
    for (;;) {
        u_long avail = 0;
        size_t len;
        uint8_t dir;

        if (ioctlsocket(p->sock, FIONREAD, &avail) == SOCKET_ERROR)
            return -1;
        if (avail == 0) {
            WSAPOLLFD pfd = { .fd = p->sock, .events = POLLRDNORM };

            /* readable without data: closed */
            if (WSAPoll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLHUP | POLLERR)))
                return -1;
            if (pfd.revents & POLLRDNORM) {
                char c;

                if (recv(p->sock, &c, 1, MSG_PEEK) <= 0)
                    return -1;
            }
            return 0;
        }

        /* 4 bytes of length, 1 of direction (0 from the guest), the frame */
        if (pcapRecvAll(p->sock, p->buf, 5) < 0)
            return -1;
        len = ((size_t)p->buf[0] << 24) | (p->buf[1] << 16) | (p->buf[2] << 8) | p->buf[3];
        dir = p->buf[4];
        if (len > NS_MON_FRAME_MAX || pcapRecvAll(p->sock, p->buf + 5, len) < 0)
            return -1;

        if (p->dir == PCAP_D_IN && dir != 0)
            continue;
        if (p->dir == PCAP_D_OUT && dir != 1)
            continue;
        if (!pfMatch(&p->filter, p->buf + 5, len))
            continue;

        p->hdr.caplen = p->hdr.len = len;
        p->hdr.ts.tv_sec = g_get_real_time() / G_USEC_PER_SEC;
        p->hdr.ts.tv_usec = g_get_real_time() % G_USEC_PER_SEC;
        return 1;
    }
}


const u_char *
pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    if (pcapRead(p) != 1)
        return NULL;
    *h = p->hdr;
    return p->buf + 5;
}


int
pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data)
{
    int rc = pcapRead(p);

    if (rc < 0) {
        g_snprintf(p->err, sizeof(p->err), "the switch closed the monitor of %s",
                   p->source);
        return PCAP_ERROR;
    }
    if (rc == 0)
        return 0;
    *h = &p->hdr;
    *data = p->buf + 5;
    return 1;
}


void
pcap_close(pcap_t *p)
{
    if (!p)
        return;
    if (p->sock != INVALID_SOCKET)
        closesocket(p->sock);
    g_free(p->filter.terms);
    g_free(p->source);
    g_free(p);
}
