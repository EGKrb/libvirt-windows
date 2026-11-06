/*
 * netswitch.c: the virtual network of a libvirt network on Windows
 *
 * Windows has no bridge device, no TAP device of its own, no dnsmasq and
 * no iptables. This helper takes their place for the networks libvirt
 * builds itself (forward mode 'nat' or none): it is an Ethernet switch the
 * guests join with QEMU's "-netdev stream" on a UNIX socket named after the
 * bridge, whose gateway is libslirp (the NAT to the host and the world),
 * and which serves DHCP and DNS from the network XML like dnsmasq does with
 * the configuration libvirt generates for it.  The leases are written where
 * and how the leaseshelper of dnsmasq writes them.
 *
 * SIGHUP (the named event of virProcessKill()) reloads the network XML,
 * as dnsmasq rereads its hosts files; SIGTERM stops the switch.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <slirp/libslirp.h>

#include "internal.h"
#include "virerror.h"
#include "virfile.h"
#include "virgettext.h"
#include "virjson.h"
#include "virmacaddr.h"
#include "virprocess.h"
#include "virstring.h"
#include "network_conf.h"

#include <iphlpapi.h>

/* virsocket.h maps the socket API onto C runtime file descriptors: this
 * helper only deals with Winsock sockets, as libslirp does */
#undef accept
#undef bind
#undef closesocket
#undef connect
#undef ioctlsocket
#undef getsockname
#undef getsockopt
#undef listen
#undef setsockopt
#undef socket

#define VIR_FROM_THIS VIR_FROM_NETWORK

#define NS_ETH_HLEN 14
#define NS_ETH_P_IP 0x0800
#define NS_ETH_P_ARP 0x0806
#define NS_ETH_P_IPV6 0x86dd
#define NS_FRAME_MAX 65536
#define NS_PORT_BACKLOG (4 * 1024 * 1024)   /* bytes queued for a slow guest */
#define NS_DHCP_DEFAULT_LEASE 3600          /* dnsmasq's default */
#define NS_DHCP_OFFER_HOLD 60
#define NS_DNS_RETRY_MS 1500
#define NS_DNS_PENDING_MAX 1024


/* A token bucket (rates in bytes per second).  Tokens may go below zero:
 * a frame passes when the bucket is not in debt, then is paid for, so
 * that a frame larger than the bucket still goes through in time */
typedef struct _nsBucket nsBucket;
struct _nsBucket {
    bool on;
    double rate;
    double size;
    double tokens;
    gint64 last;                /* us */
};

typedef struct _nsQueued nsQueued;
struct _nsQueued {
    bool fromGateway;
    size_t len;
    uint8_t data[];
};

typedef struct _nsPort nsPort;
struct _nsPort {
    SOCKET sock;
    uint8_t *rbuf;              /* 4 byte big endian length + frame */
    size_t rlen;
    GByteArray *wbuf;
    bool dead;

    /* the guest behind the port: its first source MAC address */
    bool hasMac;
    virMacAddr mac;

    /* QoS of the interface (its port file) and its floor on the network */
    nsBucket inAvg, inPeak;     /* to the guest: shaped (queue) */
    nsBucket outAvg, outPeak;   /* from the guest: policed (dropped) */
    nsBucket floor;
    GQueue *queue;              /* nsQueued, frames waiting for tokens */
    size_t queued;

    /* domifstat, in the domain's view */
    unsigned long long rxBytes, rxPackets, rxDrop;
    unsigned long long txBytes, txPackets, txDrop;
};

typedef struct _nsMacEntry nsMacEntry;
struct _nsMacEntry {
    nsPort *port;
    gint64 seen;
};

typedef struct _nsLease nsLease;
struct _nsLease {
    virMacAddr mac;
    uint32_t ip;                /* network order; IPv4 leases */
    bool v6;
    struct in6_addr ip6;        /* IPv6 leases (DHCPv6) */
    uint32_t iaid;
    char *hostname;
    char *clientid;             /* DHCPv6: the DUID of the client */
    long long expiry;           /* time(); 0 means infinite */
    bool offered;               /* offered but not yet requested */
};

typedef struct _nsTimer nsTimer;
struct _nsTimer {
    SlirpTimerId id;
    void *cb_opaque;
    int64_t expire;             /* ms, -1 when not armed */
};

typedef struct _nsUpstream nsUpstream;
struct _nsUpstream {
    struct sockaddr_storage addr;
    int addrlen;
};

typedef struct _nsDnsQuery nsDnsQuery;
struct _nsDnsQuery {
    uint16_t id;                /* id sent upstream */
    uint16_t clientId;
    bool v6;
    virMacAddr clientMac;
    uint8_t clientIP[16];
    uint16_t clientPort;
    uint8_t *query;
    size_t querylen;
    nsUpstream *servers;        /* the servers to try, in order */
    size_t nservers;
    size_t next;
    gint64 deadline;            /* ms */
};

typedef struct _nsSwitch nsSwitch;
struct _nsSwitch {
    char *configFile;
    char *socketPath;
    char *leaseFile;
    virNetworkDef *def;

    SOCKET listener;
    GPtrArray *ports;           /* nsPort */
    GHashTable *macs;           /* uint64 MAC -> nsMacEntry */

    Slirp *slirp;
    GPtrArray *timers;          /* nsTimer */
    bool isolated;
    virNetworkIPDef *ip4;       /* gateway addresses */
    virNetworkIPDef *ip6;
    uint32_t gw4;               /* network order */
    uint32_t mask4;
    struct in6_addr gw6;
    uint8_t gwMac4[6];
    uint8_t gwMac6[6];

    /* DHCP */
    virNetworkIPDef *dhcp4;     /* the IPv4 address with DHCP, if any */
    virNetworkIPDef *dhcp6;     /* the IPv6 address with DHCPv6, if any */
    uint8_t duid[10];           /* our DUID-LL, for DHCPv6 */
    struct in6_addr ll6;        /* our link-local address */
    GPtrArray *leases;          /* nsLease */

    /* DNS */
    bool wantDNS;
    SOCKET dns4;
    SOCKET dns6;
    nsUpstream *hostServers;
    size_t nhostServers;
    gint64 hostServersTime;
    GHashTable *queries;        /* upstream id -> nsDnsQuery */

    /* QoS: the network's bandwidth, between the guests and the gateway
     * (what crosses the bridge device on Linux) */
    nsBucket netInAvg, netInPeak;
    nsBucket netOutAvg, netOutPeak;
    GHashTable *qos;            /* MAC key -> GKeyFile of the port file */
    GHashTable *floors;         /* MAC key -> floor in KiB/s */
    gint64 qosWaitUs;           /* until a queued frame may go */
    char *statsFile;
    gint64 statsTime;
    bool statsDirty;

    /* forward mode route or open: the host's interface is a Wintun
     * adapter, the gateway is the host itself instead of libslirp */
    bool routed;
    HMODULE wintunDll;
    void *wintunAdapter;
    void *wintunSession;
    NET_LUID luid;
    HANDLE wintunRead;          /* Wintun's read wait event */
    HANDLE wintunDrained;       /* the loop emptied the receive ring */
    HANDLE wintunStop;
    HANDLE wintunThread;
    SOCKET wake;                /* the waiter thread wakes the loop by it */
    struct sockaddr_in wakeAddr;
    GHashTable *neigh4;         /* guest IPv4 (uint32) -> MAC key */
    GHashTable *neigh6;         /* guest IPv6 (text) -> MAC key */
    gint64 raTime;              /* ms, last router advertisement */

    HANDLE evHup;
    HANDLE evTerm;
    HANDLE evQos;               /* ports or floors changed */
    bool quit;
};


static void G_GNUC_PRINTF(1, 2)
nsLog(const char *fmt, ...)
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


static uint16_t
nsGet16(const uint8_t *p)
{
    return (p[0] << 8) | p[1];
}


static void
nsPut16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v & 0xff;
}


static void
nsPut32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}


static uint64_t
nsMacKey(const uint8_t *mac)
{
    uint64_t key = 0;
    size_t i;

    for (i = 0; i < 6; i++)
        key = (key << 8) | mac[i];
    return key;
}


/* "00:03:00:01:..." as dnsmasq writes client and server DUIDs */
static char *
nsHexColon(const uint8_t *data, size_t len)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    for (i = 0; i < len; i++)
        virBufferAsprintf(&buf, "%s%02x", i ? ":" : "", data[i]);
    return virBufferContentAndReset(&buf);
}


static gint64
nsNowMs(void)
{
    return g_get_monotonic_time() / 1000;
}


/* ---------------------------------------------------------------------
 * Ports: the guests, connected by QEMU's stream netdev
 */

static void
nsPortSend(nsPort *port, const uint8_t *frame, size_t len)
{
    uint8_t hdr[4];

    if (port->dead)
        return;
    if (port->wbuf->len + len + 4 > NS_PORT_BACKLOG)
        return; /* the guest does not keep up: drop, as a switch does */

    nsPut32(hdr, len);
    g_byte_array_append(port->wbuf, hdr, 4);
    g_byte_array_append(port->wbuf, frame, len);
}


/* ---------------------------------------------------------------------
 * QoS, as libvirt has tc do it: what a guest receives is shaped (htb:
 * average, peak, burst), what it sends is policed (police ... drop); the
 * bandwidth of the network bounds the traffic with its gateway, and a
 * floor guarantees an interface its share of that inbound bandwidth
 */

#define NS_QOS_QUEUE_MAX (512 * 1024)   /* bytes waiting for one guest */
#define NS_QOS_PEAK_SIZE 3028           /* two frames at peak rate */

static void
nsBucketSet(nsBucket *b,
            unsigned long long rateKiB,
            unsigned long long sizeKiB,
            double defaultSize)
{
    if (!rateKiB) {
        b->on = false;
        return;
    }
    b->rate = rateKiB * 1024.0;
    b->size = sizeKiB ? sizeKiB * 1024.0 : defaultSize;
    if (!b->on) {
        b->tokens = b->size;
        b->last = g_get_monotonic_time();
    } else {
        b->tokens = MIN(b->tokens, b->size);
    }
    b->on = true;
}


static bool
nsBucketReady(nsBucket *b, gint64 now)
{
    if (!b->on)
        return true;
    b->tokens = MIN(b->size, b->tokens + b->rate * (now - b->last) / 1e6);
    b->last = now;
    return b->tokens >= 0;
}


static void
nsBucketTake(nsBucket *b, size_t len)
{
    if (b->on)
        b->tokens -= len;
}


/* us until @b is out of debt */
static gint64
nsBucketWait(const nsBucket *b)
{
    if (!b->on || b->tokens >= 0)
        return 0;
    return (gint64)(-b->tokens / b->rate * 1e6) + 1;
}


/* The burst when none is given: what the rate sends in a tick of the
 * Windows timer (15.6 ms, the period the loop may sleep between two
 * drains), else a bucket refilled less than it is drained caps the rate */
#define NS_QOS_TICK 0.02

static double
nsShapeSize(unsigned long long rateKiB)
{
    return MAX(rateKiB * 1024.0 * NS_QOS_TICK, NS_QOS_PEAK_SIZE);
}


static void
nsPortSendCounted(nsSwitch *sw, nsPort *port, const uint8_t *frame, size_t len)
{
    nsPortSend(port, frame, len);
    port->rxBytes += len;
    port->rxPackets++;
    sw->statsDirty = true;
}


/* A frame for the guest of @port: sent, queued for its tokens, or dropped
 * when the queue is full */
static void
nsPortOffer(nsSwitch *sw, nsPort *port, const uint8_t *frame, size_t len,
            bool fromGateway)
{
    bool shaped = port->inAvg.on || port->inPeak.on ||
        (fromGateway && (sw->netInAvg.on || sw->netInPeak.on));
    nsQueued *q;

    if (!shaped && g_queue_is_empty(port->queue)) {
        nsPortSendCounted(sw, port, frame, len);
        return;
    }
    if (port->queued + len > NS_QOS_QUEUE_MAX) {
        port->rxDrop++;
        sw->statsDirty = true;
        return;
    }
    q = g_malloc(sizeof(*q) + len);
    q->fromGateway = fromGateway;
    q->len = len;
    memcpy(q->data, frame, len);
    g_queue_push_tail(port->queue, q);
    port->queued += len;
}


/* Send what the buckets allow; returns the us until the next frame may */
static gint64
nsPortDrain(nsSwitch *sw, nsPort *port, gint64 now)
{
    nsQueued *q;

    while ((q = g_queue_peek_head(port->queue))) {
        gint64 wait = 0;
        bool viaFloor = false;

        if (!nsBucketReady(&port->inAvg, now))
            wait = MAX(wait, nsBucketWait(&port->inAvg));
        if (!nsBucketReady(&port->inPeak, now))
            wait = MAX(wait, nsBucketWait(&port->inPeak));
        if (q->fromGateway &&
            !(nsBucketReady(&sw->netInAvg, now) & nsBucketReady(&sw->netInPeak, now))) {
            /* the network is full: the floor of the port still goes */
            if (port->floor.on && nsBucketReady(&port->floor, now)) {
                viaFloor = true;
            } else {
                gint64 netWait = MAX(nsBucketWait(&sw->netInAvg),
                                     nsBucketWait(&sw->netInPeak));

                if (port->floor.on)
                    netWait = MIN(netWait, nsBucketWait(&port->floor));
                wait = MAX(wait, netWait);
            }
        }
        if (wait > 0)
            return wait;

        nsBucketTake(&port->inAvg, q->len);
        nsBucketTake(&port->inPeak, q->len);
        if (q->fromGateway) {
            nsBucketTake(&sw->netInAvg, q->len);
            nsBucketTake(&sw->netInPeak, q->len);
            if (viaFloor || port->floor.on)
                nsBucketTake(&port->floor, q->len);
        }
        nsPortSendCounted(sw, port, q->data, q->len);
        g_queue_pop_head(port->queue);
        port->queued -= q->len;
        g_free(q);
    }
    return 0;
}


/* The QoS of the port's guest, from its port file and its floor */
static void
nsPortApplyQos(nsSwitch *sw, nsPort *port)
{
    uint64_t key;
    GKeyFile *kf;
    gpointer floor;

    if (!port->hasMac)
        return;
    key = nsMacKey(port->mac.addr);
    kf = g_hash_table_lookup(sw->qos, &key);

    nsBucketSet(&port->inAvg,
                kf ? g_key_file_get_uint64(kf, "inbound", "average", NULL) : 0,
                kf ? g_key_file_get_uint64(kf, "inbound", "burst", NULL) : 0,
                nsShapeSize(kf ? g_key_file_get_uint64(kf, "inbound", "average", NULL) : 0));
    nsBucketSet(&port->inPeak,
                kf ? g_key_file_get_uint64(kf, "inbound", "peak", NULL) : 0,
                0, nsShapeSize(kf ? g_key_file_get_uint64(kf, "inbound", "peak", NULL) : 0));
    /* police burst: the given one, else a second at the average rate */
    nsBucketSet(&port->outAvg,
                kf ? g_key_file_get_uint64(kf, "outbound", "average", NULL) : 0,
                kf ? g_key_file_get_uint64(kf, "outbound", "burst", NULL) : 0,
                kf ? g_key_file_get_uint64(kf, "outbound", "average", NULL) * 1024.0 : 0);
    nsBucketSet(&port->outPeak,
                kf ? g_key_file_get_uint64(kf, "outbound", "peak", NULL) : 0,
                0, nsShapeSize(kf ? g_key_file_get_uint64(kf, "outbound", "peak", NULL) : 0));
    floor = g_hash_table_lookup(sw->floors, &key);
    nsBucketSet(&port->floor, floor ? GPOINTER_TO_SIZE(floor) : 0, 0,
                nsShapeSize(floor ? GPOINTER_TO_SIZE(floor) : 0));
}


static void
nsPortFlush(nsPort *port)
{
    while (port->wbuf->len && !port->dead) {
        int n = send(port->sock, (const char *)port->wbuf->data,
                     MIN(port->wbuf->len, 256 * 1024), 0);

        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                port->dead = true;
            return;
        }
        g_byte_array_remove_range(port->wbuf, 0, n);
    }
}


static void
nsPortFree(nsPort *port)
{
    closesocket(port->sock);
    g_free(port->rbuf);
    g_byte_array_unref(port->wbuf);
    g_queue_free_full(port->queue, g_free);
    g_free(port);
}


static bool
nsIsGatewayMac(nsSwitch *sw, const uint8_t *mac)
{
    return memcmp(mac, sw->gwMac4, 6) == 0 || memcmp(mac, sw->gwMac6, 6) == 0;
}


static void nsGatewayInput(nsSwitch *sw, const uint8_t *frame, size_t len);

/*
 * Forward a frame coming from @src (NULL for the gateway): learn where its
 * source lives, then send it to the port of its destination, or flood it.
 * The gateway only gets the frames addressed to it and the broadcasts and
 * multicasts: libslirp would NAT to the host network any IP packet it is
 * given, those between two guests included.
 */
static void
nsDeliver(nsSwitch *sw, nsPort *src, const uint8_t *frame, size_t len)
{
    const uint8_t *dst = frame;
    size_t i;

    if (len < NS_ETH_HLEN)
        return;

    if (src && !(frame[6] & 1)) {
        uint64_t key = nsMacKey(frame + 6);
        nsMacEntry *ent = g_hash_table_lookup(sw->macs, &key);

        if (!ent) {
            uint64_t *k = g_new(uint64_t, 1);

            *k = key;
            ent = g_new0(nsMacEntry, 1);
            g_hash_table_insert(sw->macs, k, ent);
        }
        ent->port = src;
        ent->seen = nsNowMs();

        /* the guest of the port, whose QoS the port applies */
        if (!src->hasMac) {
            virMacAddrSetRaw(&src->mac, frame + 6);
            src->hasMac = true;
            nsPortApplyQos(sw, src);
        }
    }

    if (src) {
        gint64 now = g_get_monotonic_time();

        /* what the guest sends is policed: the excess is dropped */
        if (!(nsBucketReady(&src->outAvg, now) & nsBucketReady(&src->outPeak, now)) ||
            (nsIsGatewayMac(sw, dst) &&
             !(nsBucketReady(&sw->netOutAvg, now) & nsBucketReady(&sw->netOutPeak, now)))) {
            src->txDrop++;
            sw->statsDirty = true;
            return;
        }
        nsBucketTake(&src->outAvg, len);
        nsBucketTake(&src->outPeak, len);
        if (nsIsGatewayMac(sw, dst)) {
            nsBucketTake(&sw->netOutAvg, len);
            nsBucketTake(&sw->netOutPeak, len);
        }
        src->txBytes += len;
        src->txPackets++;
        sw->statsDirty = true;
    }

    if (dst[0] & 1) {
        for (i = 0; i < sw->ports->len; i++) {
            nsPort *port = g_ptr_array_index(sw->ports, i);

            if (port != src)
                nsPortOffer(sw, port, frame, len, !src);
        }
        if (src)
            nsGatewayInput(sw, frame, len);
        return;
    }

    if (nsIsGatewayMac(sw, dst)) {
        if (src)
            nsGatewayInput(sw, frame, len);
        return;
    }

    {
        uint64_t key = nsMacKey(dst);
        nsMacEntry *ent = g_hash_table_lookup(sw->macs, &key);

        if (ent && ent->port) {
            if (ent->port != src)
                nsPortOffer(sw, ent->port, frame, len, !src);
            return;
        }
    }

    /* unknown unicast: every guest but the sender */
    for (i = 0; i < sw->ports->len; i++) {
        nsPort *port = g_ptr_array_index(sw->ports, i);

        if (port != src)
            nsPortOffer(sw, port, frame, len, !src);
    }
}


static void
nsPortInput(nsSwitch *sw, nsPort *port)
{
    for (;;) {
        int n = recv(port->sock, (char *)port->rbuf + port->rlen,
                     4 + NS_FRAME_MAX - port->rlen, 0);
        size_t off = 0;

        if (n == 0) {
            port->dead = true;
            return;
        }
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                port->dead = true;
            return;
        }
        port->rlen += n;

        while (port->rlen - off >= 4) {
            const uint8_t *p = port->rbuf + off;
            size_t flen = ((size_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];

            if (flen > NS_FRAME_MAX) {
                nsLog("port %p: invalid frame length %zu, disconnected",
                      (void *)port, flen);
                port->dead = true;
                return;
            }
            if (port->rlen - off < 4 + flen)
                break;
            nsDeliver(sw, port, p + 4, flen);
            off += 4 + flen;
        }
        memmove(port->rbuf, port->rbuf + off, port->rlen - off);
        port->rlen -= off;
    }
}


static void
nsForgetPort(nsSwitch *sw, nsPort *port)
{
    GHashTableIter iter;
    nsMacEntry *ent;

    g_hash_table_iter_init(&iter, sw->macs);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&ent)) {
        if (ent->port == port)
            g_hash_table_iter_remove(&iter);
    }
}


static void
nsAccept(nsSwitch *sw)
{
    for (;;) {
        SOCKET s = accept(sw->listener, NULL, NULL);
        u_long nonblock = 1;
        nsPort *port;

        if (s == INVALID_SOCKET)
            return;
        ioctlsocket(s, FIONBIO, &nonblock);

        port = g_new0(nsPort, 1);
        port->sock = s;
        port->rbuf = g_new(uint8_t, 4 + NS_FRAME_MAX);
        port->wbuf = g_byte_array_new();
        port->queue = g_queue_new();
        g_ptr_array_add(sw->ports, port);
        nsLog("guest port %p connected (%u ports)", (void *)port, sw->ports->len);
    }
}


/* ---------------------------------------------------------------------
 * Frames sent by the gateway
 */

static uint32_t
nsChecksumAdd(uint32_t sum, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += (data[i] << 8) | data[i + 1];
    if (len & 1)
        sum += data[len - 1] << 8;
    return sum;
}


static uint16_t
nsChecksumFold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
}


/* Send a UDP datagram from the gateway to a guest */
static void
nsGatewaySendUDP(nsSwitch *sw,
                 bool v6,
                 const uint8_t *dstMac,
                 const uint8_t *srcIP,
                 const uint8_t *dstIP,
                 uint16_t srcPort,
                 uint16_t dstPort,
                 const uint8_t *payload,
                 size_t len)
{
    size_t iphlen = v6 ? 40 : 20;
    size_t total = NS_ETH_HLEN + iphlen + 8 + len;
    g_autofree uint8_t *f = g_new0(uint8_t, total);
    uint8_t *ip = f + NS_ETH_HLEN;
    uint8_t *udp = ip + iphlen;
    uint32_t sum;

    memcpy(f, dstMac, 6);
    memcpy(f + 6, v6 ? sw->gwMac6 : sw->gwMac4, 6);
    nsPut16(f + 12, v6 ? NS_ETH_P_IPV6 : NS_ETH_P_IP);

    if (v6) {
        ip[0] = 0x60;
        nsPut16(ip + 4, 8 + len);
        ip[6] = IPPROTO_UDP;
        ip[7] = 64;
        memcpy(ip + 8, srcIP, 16);
        memcpy(ip + 24, dstIP, 16);
    } else {
        ip[0] = 0x45;
        nsPut16(ip + 2, iphlen + 8 + len);
        ip[8] = 64;
        ip[9] = IPPROTO_UDP;
        memcpy(ip + 12, srcIP, 4);
        memcpy(ip + 16, dstIP, 4);
        nsPut16(ip + 10, nsChecksumFold(nsChecksumAdd(0, ip, 20)));
    }

    nsPut16(udp, srcPort);
    nsPut16(udp + 2, dstPort);
    nsPut16(udp + 4, 8 + len);
    memcpy(udp + 8, payload, len);

    /* pseudo header + UDP */
    sum = v6 ? nsChecksumAdd(0, ip + 8, 32) : nsChecksumAdd(0, ip + 12, 8);
    sum += IPPROTO_UDP + 8 + len;
    sum = nsChecksumAdd(sum, udp, 8 + len);
    sum = nsChecksumFold(sum);
    nsPut16(udp + 6, sum ? sum : 0xffff);

    nsDeliver(sw, NULL, f, total);
}


/* ---------------------------------------------------------------------
 * DHCP (IPv4), as dnsmasq serves it with the configuration of libvirt:
 * dhcp-range, dhcp-host, dhcp-authoritative, dhcp-no-override, dhcp-boot
 */

enum {
    NS_DHCP_DISCOVER = 1,
    NS_DHCP_OFFER = 2,
    NS_DHCP_REQUEST = 3,
    NS_DHCP_DECLINE = 4,
    NS_DHCP_ACK = 5,
    NS_DHCP_NAK = 6,
    NS_DHCP_RELEASE = 7,
    NS_DHCP_INFORM = 8,
};


static uint32_t
nsAddr4(const virSocketAddr *addr)
{
    return addr->data.inet4.sin_addr.s_addr;
}


static void
nsLeaseFree(nsLease *lease)
{
    g_free(lease->hostname);
    g_free(lease->clientid);
    g_free(lease);
}


static void
nsLeasesSave(nsSwitch *sw)
{
    g_autoptr(virJSONValue) array = virJSONValueNewArray();
    g_autofree char *str = NULL;
    long long now = time(NULL);
    size_t i;

    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);
        g_autoptr(virJSONValue) obj = virJSONValueNewObject();
        char macstr[VIR_MAC_STRING_BUFLEN];
        char ipstr[INET6_ADDRSTRLEN];
        struct in_addr in = { .s_addr = lease->ip };

        if (lease->offered || (lease->expiry && lease->expiry < now))
            continue;

        if (lease->v6) {
            /* what the leaseshelper of dnsmasq records for DHCPv6 */
            g_autofree char *iaid = g_strdup_printf("%u", lease->iaid);
            g_autofree char *duid = nsHexColon(sw->duid, sizeof(sw->duid));

            inet_ntop(AF_INET6, &lease->ip6, ipstr, sizeof(ipstr));
            if (virJSONValueObjectAppendString(obj, "iaid", iaid) < 0 ||
                virJSONValueObjectAppendString(obj, "server-duid", duid) < 0)
                return;
        } else {
            inet_ntop(AF_INET, &in, ipstr, sizeof(ipstr));
        }
        virMacAddrFormat(&lease->mac, macstr);
        if (virJSONValueObjectAppendString(obj, "ip-address", ipstr) < 0 ||
            virJSONValueObjectAppendString(obj, "mac-address", macstr) < 0 ||
            (lease->hostname &&
             virJSONValueObjectAppendString(obj, "hostname", lease->hostname) < 0) ||
            (lease->clientid &&
             virJSONValueObjectAppendString(obj, "client-id", lease->clientid) < 0) ||
            virJSONValueObjectAppendNumberLong(obj, "expiry-time", lease->expiry) < 0 ||
            virJSONValueArrayAppend(array, &obj) < 0)
            return;
    }

    if (!(str = virJSONValueToString(array, true)) ||
        virFileRewriteStr(sw->leaseFile, 0644, str) < 0)
        nsLog("cannot write the leases to %s: %s",
              sw->leaseFile, virGetLastErrorMessage());
}


static void
nsLeasesLoad(nsSwitch *sw)
{
    g_autofree char *str = NULL;
    g_autoptr(virJSONValue) array = NULL;
    size_t i;

    if (virFileReadAllQuiet(sw->leaseFile, 32 * 1024 * 1024, &str) < 0 ||
        !(array = virJSONValueFromString(str)) ||
        !virJSONValueIsArray(array))
        return;

    for (i = 0; i < virJSONValueArraySize(array); i++) {
        virJSONValue *obj = virJSONValueArrayGet(array, i);
        const char *ip = virJSONValueObjectGetString(obj, "ip-address");
        const char *mac = virJSONValueObjectGetString(obj, "mac-address");
        nsLease *lease = g_new0(nsLease, 1);
        struct in_addr in;

        if (!ip || !mac ||
            virMacAddrParse(mac, &lease->mac) < 0 ||
            virJSONValueObjectGetNumberLong(obj, "expiry-time", &lease->expiry) < 0) {
            nsLeaseFree(lease);
            continue;
        }
        if (strchr(ip, ':')) {
            const char *iaid = virJSONValueObjectGetString(obj, "iaid");

            lease->v6 = true;
            if (inet_pton(AF_INET6, ip, &lease->ip6) != 1 ||
                !iaid || virStrToLong_ui(iaid, NULL, 10, &lease->iaid) < 0) {
                nsLeaseFree(lease);
                continue;
            }
        } else if (inet_pton(AF_INET, ip, &in) == 1) {
            lease->ip = in.s_addr;
        } else {
            nsLeaseFree(lease);
            continue;
        }
        lease->hostname = g_strdup(virJSONValueObjectGetString(obj, "hostname"));
        lease->clientid = g_strdup(virJSONValueObjectGetString(obj, "client-id"));
        g_ptr_array_add(sw->leases, lease);
    }
    nsLog("%u leases loaded from %s", sw->leases->len, sw->leaseFile);
}


static nsLease *
nsLeaseFindMac(nsSwitch *sw, const virMacAddr *mac)
{
    size_t i;

    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);

        if (!lease->v6 && virMacAddrCmp(&lease->mac, mac) == 0)
            return lease;
    }
    return NULL;
}


/* Is @ip taken by another client (lease or static host)? */
static bool
nsAddrTaken(nsSwitch *sw, uint32_t ip, const virMacAddr *mac)
{
    long long now = time(NULL);
    size_t i;

    if (ip == sw->gw4)
        return true;

    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);

        if (!lease->v6 && lease->ip == ip && virMacAddrCmp(&lease->mac, mac) != 0 &&
            (!lease->expiry || lease->expiry >= now))
            return true;
    }

    for (i = 0; i < sw->dhcp4->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp4->hosts[i];
        virMacAddr hmac;

        if (VIR_SOCKET_ADDR_VALID(&host->ip) && nsAddr4(&host->ip) == ip &&
            !(host->mac && virMacAddrParse(host->mac, &hmac) == 0 &&
              virMacAddrCmp(&hmac, mac) == 0))
            return true;
    }
    return false;
}


static virNetworkDHCPHostDef *
nsDhcpFindHost(nsSwitch *sw, const virMacAddr *mac, const char *hostname)
{
    size_t i;

    for (i = 0; i < sw->dhcp4->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp4->hosts[i];
        virMacAddr hmac;

        if (host->mac && virMacAddrParse(host->mac, &hmac) == 0 &&
            virMacAddrCmp(&hmac, mac) == 0)
            return host;
    }
    /* dhcp-host=name,ip matches the name the client sends */
    for (i = 0; hostname && i < sw->dhcp4->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp4->hosts[i];

        if (!host->mac && host->name && STRCASEEQ(host->name, hostname))
            return host;
    }
    return NULL;
}


static virNetworkDHCPRangeDef *
nsDhcpFindRange(nsSwitch *sw, uint32_t ip)
{
    size_t i;

    for (i = 0; i < sw->dhcp4->nranges; i++) {
        virNetworkDHCPRangeDef *range = &sw->dhcp4->ranges[i];
        uint32_t start = ntohl(nsAddr4(&range->addr.start));
        uint32_t end = ntohl(nsAddr4(&range->addr.end));

        if (ntohl(ip) >= start && ntohl(ip) <= end)
            return range;
    }
    return NULL;
}


/* Lease time in seconds, 0 for infinite */
static unsigned long long
nsLeaseTime(const virNetworkDHCPLeaseTimeDef *lease)
{
    if (!lease)
        return NS_DHCP_DEFAULT_LEASE;
    switch (lease->unit) {
    case VIR_NETWORK_DHCP_LEASETIME_UNIT_MINUTES:
        return lease->expiry * 60;
    case VIR_NETWORK_DHCP_LEASETIME_UNIT_HOURS:
        return lease->expiry * 3600;
    case VIR_NETWORK_DHCP_LEASETIME_UNIT_SECONDS:
    case VIR_NETWORK_DHCP_LEASETIME_UNIT_LAST:
    default:
        return lease->expiry;
    }
}


/* The lease time of @ip: the host's, else that of its dhcp-range, else
 * (a static address out of the ranges) that of the subnet's range, as
 * dnsmasq takes it from the dhcp-range context */
static unsigned long long
nsDhcpLeaseTime(nsSwitch *sw, virNetworkDHCPHostDef *host, uint32_t ip)
{
    virNetworkDHCPRangeDef *range;

    if (host && host->lease)
        return nsLeaseTime(host->lease);
    if ((range = nsDhcpFindRange(sw, ip)))
        return nsLeaseTime(range->lease);
    if (sw->dhcp4->nranges)
        return nsLeaseTime(sw->dhcp4->ranges[0].lease);
    return nsLeaseTime(NULL);
}


/* The address for a client, 0 if none can be given */
static uint32_t
nsDhcpChoose(nsSwitch *sw,
             const virMacAddr *mac,
             virNetworkDHCPHostDef *host,
             uint32_t requested)
{
    nsLease *lease;
    size_t i;

    if (host && VIR_SOCKET_ADDR_VALID(&host->ip))
        return nsAddr4(&host->ip);

    /* no dhcp-range: only the static hosts are served */
    if (sw->dhcp4->nranges == 0)
        return 0;

    if ((lease = nsLeaseFindMac(sw, mac)) && nsDhcpFindRange(sw, lease->ip) &&
        !nsAddrTaken(sw, lease->ip, mac))
        return lease->ip;

    if (requested && nsDhcpFindRange(sw, requested) &&
        !nsAddrTaken(sw, requested, mac))
        return requested;

    for (i = 0; i < sw->dhcp4->nranges; i++) {
        virNetworkDHCPRangeDef *range = &sw->dhcp4->ranges[i];
        uint32_t a;

        for (a = ntohl(nsAddr4(&range->addr.start));
             a <= ntohl(nsAddr4(&range->addr.end)); a++) {
            if (!nsAddrTaken(sw, htonl(a), mac))
                return htonl(a);
            if (a == UINT32_MAX)
                break;
        }
    }
    return 0;
}


static void
nsDhcpAddOpt(GByteArray *opts, uint8_t code, const void *data, size_t len)
{
    uint8_t hdr[2] = { code, len };

    g_byte_array_append(opts, hdr, 2);
    g_byte_array_append(opts, data, len);
}


static void
nsDhcpAddOpt32(GByteArray *opts, uint8_t code, uint32_t v)
{
    uint8_t b[4];

    nsPut32(b, v);
    nsDhcpAddOpt(opts, code, b, 4);
}


static void
nsDhcpReply(nsSwitch *sw,
            const uint8_t *req,
            uint8_t type,
            uint32_t yiaddr,
            unsigned long long leaseTime,
            const char *hostname,
            const uint8_t *clientMac)
{
    g_autoptr(GByteArray) opts = g_byte_array_new();
    uint8_t reply[1500] = { 0 };
    uint32_t ciaddr;
    uint8_t dstIP[4];
    const uint8_t *dstMac = clientMac;
    static const uint8_t bcastMac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    size_t len;
    uint32_t mask = sw->mask4;
    uint32_t bcast = (sw->gw4 & mask) | ~mask;

    reply[0] = 2;                       /* BOOTREPLY */
    reply[1] = 1;
    reply[2] = 6;
    memcpy(reply + 4, req + 4, 4);      /* xid */
    memcpy(reply + 10, req + 10, 2);    /* flags */
    memcpy(reply + 12, req + 12, 4);    /* ciaddr */
    if (type != NS_DHCP_NAK)
        memcpy(reply + 16, &yiaddr, 4);
    memcpy(reply + 28, req + 28, 16);   /* chaddr */
    memcpy(&ciaddr, req + 12, 4);

    /* dhcp-boot=file[,,server] */
    if (type != NS_DHCP_NAK && sw->dhcp4->bootfile) {
        uint32_t server = VIR_SOCKET_ADDR_VALID(&sw->dhcp4->bootserver) ?
            nsAddr4(&sw->dhcp4->bootserver) : sw->gw4;

        memcpy(reply + 20, &server, 4); /* siaddr */
        g_strlcpy((char *)reply + 108, sw->dhcp4->bootfile, 128);
    }

    reply[236] = 99;
    reply[237] = 130;
    reply[238] = 83;
    reply[239] = 99;

    nsDhcpAddOpt(opts, 53, &type, 1);
    nsDhcpAddOpt(opts, 54, &sw->gw4, 4);
    if (type == NS_DHCP_OFFER || type == NS_DHCP_ACK) {
        if (yiaddr) {
            if (leaseTime == 0) {
                nsDhcpAddOpt32(opts, 51, 0xffffffff);
            } else {
                nsDhcpAddOpt32(opts, 51, leaseTime);
                nsDhcpAddOpt32(opts, 58, leaseTime / 2);
                nsDhcpAddOpt32(opts, 59, leaseTime * 7 / 8);
            }
        }
        nsDhcpAddOpt(opts, 1, &mask, 4);
        nsDhcpAddOpt(opts, 28, &bcast, 4);
        /* an isolated network gives no default route (dhcp-option=3) */
        if (!sw->isolated)
            nsDhcpAddOpt(opts, 3, &sw->gw4, 4);
        if (sw->wantDNS)
            nsDhcpAddOpt(opts, 6, &sw->gw4, 4);
        if (sw->def->domain)
            nsDhcpAddOpt(opts, 15, sw->def->domain,
                         MIN(strlen(sw->def->domain), 255));
        if (hostname)
            nsDhcpAddOpt(opts, 12, hostname, MIN(strlen(hostname), 255));
        if (sw->def->mtu > 0) {
            uint8_t mtu[2];

            nsPut16(mtu, sw->def->mtu);
            nsDhcpAddOpt(opts, 26, mtu, 2);
        }
    }
    g_byte_array_append(opts, (const uint8_t *)"\xff", 1);

    len = MIN(240 + opts->len, sizeof(reply));
    memcpy(reply + 240, opts->data, len - 240);
    len = MAX(len, 300);

    /* RFC 2131 4.1: to ciaddr if set, else broadcast if the client asks or
     * on NAK, else straight to the hardware address of the client */
    if (ciaddr && type != NS_DHCP_NAK) {
        memcpy(dstIP, &ciaddr, 4);
    } else if (type == NS_DHCP_NAK || (req[10] & 0x80)) {
        memset(dstIP, 0xff, 4);
        dstMac = bcastMac;
    } else {
        memcpy(dstIP, &yiaddr, 4);
    }

    nsGatewaySendUDP(sw, false, dstMac, (const uint8_t *)&sw->gw4, dstIP,
                     67, 68, reply, len);
}


static char *
nsDhcpOptString(const uint8_t *opt)
{
    char *s = g_strndup((const char *)opt + 2, opt[1]);
    char *p;

    for (p = s; *p; p++) {
        if (!g_ascii_isalnum(*p) && *p != '-' && *p != '.' && *p != '_')
            *p = '-';
    }
    return s;
}


static void
nsDhcpInput(nsSwitch *sw, const uint8_t *msg, size_t len)
{
    const uint8_t *opt;
    const uint8_t *end = msg + len;
    uint8_t type = 0;
    uint32_t requested = 0;
    uint32_t serverId = 0;
    g_autofree char *hostname = NULL;
    g_autofree char *clientid = NULL;
    virMacAddr mac;
    virNetworkDHCPHostDef *host;
    nsLease *lease;
    uint32_t ciaddr;
    uint32_t ip;
    unsigned long long leaseTime;
    const char *name;
    char macstr[VIR_MAC_STRING_BUFLEN];
    char ipstr[INET_ADDRSTRLEN];

    if (!sw->dhcp4 || len < 240 || msg[0] != 1 || msg[1] != 1 || msg[2] != 6 ||
        msg[236] != 99 || msg[237] != 130 || msg[238] != 83 || msg[239] != 99)
        return;

    for (opt = msg + 240; opt < end && *opt != 255;) {
        if (*opt == 0) {
            opt++;
            continue;
        }
        if (opt + 2 > end || opt + 2 + opt[1] > end)
            break;
        switch (opt[0]) {
        case 53:
            if (opt[1] >= 1)
                type = opt[2];
            break;
        case 50:
            if (opt[1] == 4)
                memcpy(&requested, opt + 2, 4);
            break;
        case 54:
            if (opt[1] == 4)
                memcpy(&serverId, opt + 2, 4);
            break;
        case 12:
            g_free(hostname);
            hostname = nsDhcpOptString(opt);
            break;
        case 61: {
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
            size_t i;

            for (i = 0; i < opt[1]; i++)
                virBufferAsprintf(&buf, "%s%02x", i ? ":" : "", opt[2 + i]);
            g_free(clientid);
            clientid = virBufferContentAndReset(&buf);
            break;
        }
        }
        opt += 2 + opt[1];
    }

    virMacAddrSetRaw(&mac, msg + 28);
    virMacAddrFormat(&mac, macstr);
    memcpy(&ciaddr, msg + 12, 4);
    host = nsDhcpFindHost(sw, &mac, hostname);
    name = host && host->name ? host->name : hostname;
    lease = nsLeaseFindMac(sw, &mac);

    switch (type) {
    case NS_DHCP_DISCOVER:
        if (!(ip = nsDhcpChoose(sw, &mac, host, requested))) {
            nsLog("DHCPDISCOVER(%s) %s: no address available", sw->def->bridge, macstr);
            return;
        }
        if (!lease) {
            lease = g_new0(nsLease, 1);
            lease->mac = mac;
            lease->offered = true;
            g_ptr_array_add(sw->leases, lease);
        }
        if (lease->offered) {
            lease->ip = ip;
            lease->expiry = time(NULL) + NS_DHCP_OFFER_HOLD;
        }
        leaseTime = nsDhcpLeaseTime(sw, host, ip);
        inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
        nsLog("DHCPOFFER(%s) %s %s", sw->def->bridge, ipstr, macstr);
        nsDhcpReply(sw, msg, NS_DHCP_OFFER, ip, leaseTime,
                    host ? host->name : NULL, msg + 28);
        return;

    case NS_DHCP_REQUEST:
        /* the client took the offer of another server */
        if (serverId && serverId != sw->gw4) {
            if (lease && lease->offered) {
                g_ptr_array_remove(sw->leases, lease);
                nsLeaseFree(lease);
            }
            return;
        }
        ip = requested ? requested : ciaddr;
        if (!ip || ip != nsDhcpChoose(sw, &mac, host, ip)) {
            /* dhcp-authoritative: refuse an address we would not give */
            if (ip && ((ntohl(ip) & ntohl(sw->mask4)) == (ntohl(sw->gw4) & ntohl(sw->mask4)))) {
                inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
                nsLog("DHCPNAK(%s) %s %s", sw->def->bridge, ipstr, macstr);
                nsDhcpReply(sw, msg, NS_DHCP_NAK, 0, 0, NULL, msg + 28);
            }
            return;
        }
        leaseTime = nsDhcpLeaseTime(sw, host, ip);
        if (!lease) {
            lease = g_new0(nsLease, 1);
            lease->mac = mac;
            g_ptr_array_add(sw->leases, lease);
        }
        lease->ip = ip;
        lease->offered = false;
        lease->expiry = leaseTime ? time(NULL) + leaseTime : 0;
        g_free(lease->hostname);
        lease->hostname = g_strdup(name);
        if (clientid) {
            g_free(lease->clientid);
            lease->clientid = g_steal_pointer(&clientid);
        }
        nsLeasesSave(sw);
        inet_ntop(AF_INET, &ip, ipstr, sizeof(ipstr));
        nsLog("DHCPACK(%s) %s %s %s", sw->def->bridge, ipstr, macstr, NULLSTR_EMPTY(name));
        nsDhcpReply(sw, msg, NS_DHCP_ACK, ip, leaseTime,
                    host ? host->name : NULL, msg + 28);
        return;

    case NS_DHCP_INFORM:
        nsDhcpReply(sw, msg, NS_DHCP_ACK, 0, 0, NULL, msg + 28);
        return;

    case NS_DHCP_RELEASE:
    case NS_DHCP_DECLINE:
        if (lease) {
            nsLog("DHCP%s(%s) %s", type == NS_DHCP_RELEASE ? "RELEASE" : "DECLINE",
                  sw->def->bridge, macstr);
            g_ptr_array_remove(sw->leases, lease);
            nsLeaseFree(lease);
            nsLeasesSave(sw);
        }
        return;
    }
}


/* ---------------------------------------------------------------------
 * DHCPv6 (RFC 8415), as dnsmasq serves an IPv6 dhcp-range or dhcp-host:
 * stateful addresses (IA_NA), the DNS server and domain, hosts by DUID
 * (the libvirt 'id'), MAC address or name
 */

static size_t nsDnsReadName(const uint8_t *msg, size_t len, size_t off,
                            char *name, size_t namelen);
static void nsDnsPutName(GByteArray *out, const char *name);

enum {
    NS_DHCP6_SOLICIT = 1,
    NS_DHCP6_ADVERTISE = 2,
    NS_DHCP6_REQUEST = 3,
    NS_DHCP6_CONFIRM = 4,
    NS_DHCP6_RENEW = 5,
    NS_DHCP6_REBIND = 6,
    NS_DHCP6_REPLY = 7,
    NS_DHCP6_RELEASE = 8,
    NS_DHCP6_DECLINE = 9,
    NS_DHCP6_INFORMATION_REQUEST = 11,
};

enum {
    NS_DHCP6_OPT_CLIENTID = 1,
    NS_DHCP6_OPT_SERVERID = 2,
    NS_DHCP6_OPT_IA_NA = 3,
    NS_DHCP6_OPT_IAADDR = 5,
    NS_DHCP6_OPT_STATUS_CODE = 13,
    NS_DHCP6_OPT_DNS_SERVERS = 23,
    NS_DHCP6_OPT_DOMAIN_LIST = 24,
    NS_DHCP6_OPT_CLIENT_FQDN = 39,
};

enum {
    NS_DHCP6_STATUS_SUCCESS = 0,
    NS_DHCP6_STATUS_NOADDRSAVAIL = 2,
    NS_DHCP6_STATUS_NOBINDING = 3,
    NS_DHCP6_STATUS_NOTONLINK = 4,
};


static const uint8_t *
nsDhcp6FindOpt(const uint8_t *opts, size_t len, uint16_t code, size_t *optlen)
{
    while (len >= 4) {
        uint16_t c = nsGet16(opts);
        size_t l = nsGet16(opts + 2);

        if (l + 4 > len)
            return NULL;
        if (c == code) {
            *optlen = l;
            return opts + 4;
        }
        opts += 4 + l;
        len -= 4 + l;
    }
    return NULL;
}


static void
nsDhcp6AddOpt(GByteArray *out, uint16_t code, const void *data, size_t len)
{
    uint8_t hdr[4];

    nsPut16(hdr, code);
    nsPut16(hdr + 2, len);
    g_byte_array_append(out, hdr, 4);
    if (len)
        g_byte_array_append(out, data, len);
}


static void
nsDhcp6AddStatus(GByteArray *out, uint16_t status, const char *msg)
{
    g_autoptr(GByteArray) st = g_byte_array_new();
    uint8_t code[2];

    nsPut16(code, status);
    g_byte_array_append(st, code, 2);
    g_byte_array_append(st, (const uint8_t *)msg, strlen(msg));
    nsDhcp6AddOpt(out, NS_DHCP6_OPT_STATUS_CODE, st->data, st->len);
}


/* The DUID of a libvirt <host id='0:3:0:1:...'/> */
static GByteArray *
nsDhcp6ParseDuid(const char *id)
{
    g_auto(GStrv) parts = g_strsplit(id, ":", -1);
    GByteArray *duid = g_byte_array_new();
    GStrv p;

    for (p = parts; *p; p++) {
        unsigned int v;
        uint8_t b;

        if (virStrToLong_ui(*p, NULL, 16, &v) < 0 || v > 255) {
            g_byte_array_unref(duid);
            return NULL;
        }
        b = v;
        g_byte_array_append(duid, &b, 1);
    }
    return duid;
}


static virNetworkDHCPHostDef *
nsDhcp6FindHost(nsSwitch *sw,
                const uint8_t *duid,
                size_t duidlen,
                const virMacAddr *mac,
                const char *hostname)
{
    size_t i;

    for (i = 0; i < sw->dhcp6->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp6->hosts[i];
        g_autoptr(GByteArray) hduid = NULL;
        virMacAddr hmac;

        if (host->id && (hduid = nsDhcp6ParseDuid(host->id)) &&
            hduid->len == duidlen && memcmp(hduid->data, duid, duidlen) == 0)
            return host;
        if (host->mac && virMacAddrParse(host->mac, &hmac) == 0 &&
            virMacAddrCmp(&hmac, mac) == 0)
            return host;
    }
    for (i = 0; hostname && i < sw->dhcp6->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp6->hosts[i];

        if (!host->id && !host->mac && host->name && STRCASEEQ(host->name, hostname))
            return host;
    }
    return NULL;
}


static nsLease *
nsDhcp6FindLease(nsSwitch *sw, const char *clientid, uint32_t iaid)
{
    size_t i;

    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);

        if (lease->v6 && lease->iaid == iaid && lease->clientid &&
            STREQ(lease->clientid, clientid))
            return lease;
    }
    return NULL;
}


static bool
nsAddr6InRange(const struct in6_addr *a, const virSocketAddrRange *range)
{
    return memcmp(a, &range->start.data.inet6.sin6_addr, 16) >= 0 &&
        memcmp(a, &range->end.data.inet6.sin6_addr, 16) <= 0;
}


static virNetworkDHCPRangeDef *
nsDhcp6FindRange(nsSwitch *sw, const struct in6_addr *a)
{
    size_t i;

    for (i = 0; i < sw->dhcp6->nranges; i++) {
        if (nsAddr6InRange(a, &sw->dhcp6->ranges[i].addr))
            return &sw->dhcp6->ranges[i];
    }
    return NULL;
}


/* Is @a taken by another binding (lease or static host)? */
static bool
nsAddr6Taken(nsSwitch *sw, const struct in6_addr *a, const char *clientid, uint32_t iaid)
{
    long long now = time(NULL);
    size_t i;

    if (memcmp(a, &sw->gw6, 16) == 0)
        return true;
    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);

        if (lease->v6 && memcmp(&lease->ip6, a, 16) == 0 &&
            (!lease->expiry || lease->expiry >= now) &&
            !(lease->iaid == iaid && lease->clientid && STREQ(lease->clientid, clientid)))
            return true;
    }
    for (i = 0; i < sw->dhcp6->nhosts; i++) {
        virNetworkDHCPHostDef *host = &sw->dhcp6->hosts[i];

        if (VIR_SOCKET_ADDR_VALID(&host->ip) &&
            memcmp(&host->ip.data.inet6.sin6_addr, a, 16) == 0)
            return true;
    }
    return false;
}


/* The address of a binding: its host's, its lease's, the one it asks
 * for, else the first free one of the ranges */
static bool
nsDhcp6Choose(nsSwitch *sw,
              virNetworkDHCPHostDef *host,
              const char *clientid,
              uint32_t iaid,
              const struct in6_addr *requested,
              struct in6_addr *out)
{
    nsLease *lease;
    size_t i;

    if (host && VIR_SOCKET_ADDR_VALID(&host->ip)) {
        *out = host->ip.data.inet6.sin6_addr;
        return true;
    }
    if (sw->dhcp6->nranges == 0)
        return false;

    if ((lease = nsDhcp6FindLease(sw, clientid, iaid)) &&
        nsDhcp6FindRange(sw, &lease->ip6)) {
        *out = lease->ip6;
        return true;
    }
    if (requested && nsDhcp6FindRange(sw, requested) &&
        !nsAddr6Taken(sw, requested, clientid, iaid)) {
        *out = *requested;
        return true;
    }

    for (i = 0; i < sw->dhcp6->nranges; i++) {
        const virSocketAddrRange *range = &sw->dhcp6->ranges[i].addr;
        struct in6_addr a = range->start.data.inet6.sin6_addr;
        size_t tries;

        /* the lowest 32 bits are enough to walk any sensible range */
        for (tries = 0; tries < 65536 && nsAddr6InRange(&a, range); tries++) {
            int b;

            if (!nsAddr6Taken(sw, &a, clientid, iaid)) {
                *out = a;
                return true;
            }
            for (b = 15; b >= 0 && ++a.s6_addr[b] == 0; b--)
                ;
        }
    }
    return false;
}


static unsigned long long
nsDhcp6LeaseTime(nsSwitch *sw, virNetworkDHCPHostDef *host, const struct in6_addr *a)
{
    virNetworkDHCPRangeDef *range;

    if (host && host->lease)
        return nsLeaseTime(host->lease);
    if ((range = nsDhcp6FindRange(sw, a)))
        return nsLeaseTime(range->lease);
    if (sw->dhcp6->nranges)
        return nsLeaseTime(sw->dhcp6->ranges[0].lease);
    return nsLeaseTime(NULL);
}


static void
nsDhcp6AddInfo(nsSwitch *sw, GByteArray *out)
{
    if (sw->wantDNS)
        nsDhcp6AddOpt(out, NS_DHCP6_OPT_DNS_SERVERS, &sw->gw6, 16);
    if (sw->def->domain) {
        g_autoptr(GByteArray) name = g_byte_array_new();

        nsDnsPutName(name, sw->def->domain);
        nsDhcp6AddOpt(out, NS_DHCP6_OPT_DOMAIN_LIST, name->data, name->len);
    }
}


static void
nsDhcp6Input(nsSwitch *sw,
             const uint8_t *clientMac,
             const uint8_t *clientIP,
             uint16_t clientPort,
             const uint8_t *msg,
             size_t len)
{
    const uint8_t *opts = msg + 4;
    size_t optslen = len - 4;
    const uint8_t *clientDuid;
    const uint8_t *serverDuid;
    const uint8_t *fqdn;
    size_t clientDuidLen = 0;
    size_t serverDuidLen = 0;
    size_t fqdnlen = 0;
    uint8_t type = msg[0];
    uint8_t replyType = NS_DHCP6_REPLY;
    g_autoptr(GByteArray) reply = g_byte_array_new();
    g_autofree char *clientid = NULL;
    g_autofree char *hostname = NULL;
    virNetworkDHCPHostDef *host = NULL;
    virMacAddr mac;
    bool changed = false;
    const uint8_t *p;
    size_t left;

    if (!sw->dhcp6 || len < 4)
        return;
    if (!(clientDuid = nsDhcp6FindOpt(opts, optslen, NS_DHCP6_OPT_CLIENTID, &clientDuidLen)) &&
        type != NS_DHCP6_INFORMATION_REQUEST)
        return;
    serverDuid = nsDhcp6FindOpt(opts, optslen, NS_DHCP6_OPT_SERVERID, &serverDuidLen);

    /* Request, Renew, Release, Decline: for us only; Solicit, Rebind,
     * Confirm: for any server */
    switch (type) {
    case NS_DHCP6_REQUEST:
    case NS_DHCP6_RENEW:
    case NS_DHCP6_RELEASE:
    case NS_DHCP6_DECLINE:
        if (!serverDuid || serverDuidLen != sizeof(sw->duid) ||
            memcmp(serverDuid, sw->duid, serverDuidLen) != 0)
            return;
        break;
    case NS_DHCP6_SOLICIT:
    case NS_DHCP6_REBIND:
    case NS_DHCP6_CONFIRM:
        if (serverDuid)
            return;
        break;
    case NS_DHCP6_INFORMATION_REQUEST:
        break;
    default:
        return;
    }

    virMacAddrSetRaw(&mac, clientMac);
    if (clientDuid)
        clientid = nsHexColon(clientDuid, clientDuidLen);
    /* the name in the Client FQDN option: flags, then a DNS name */
    if ((fqdn = nsDhcp6FindOpt(opts, optslen, NS_DHCP6_OPT_CLIENT_FQDN, &fqdnlen)) &&
        fqdnlen > 1) {
        g_autofree uint8_t *wire = g_new0(uint8_t, fqdnlen + 12);
        char name[256];
        char *dot;

        memcpy(wire + 12, fqdn + 1, fqdnlen - 1);
        if (nsDnsReadName(wire, fqdnlen + 11, 12, name, sizeof(name)) && name[0]) {
            if ((dot = strchr(name, '.')))
                *dot = '\0';
            hostname = g_strdup(name);
        }
    }
    if (clientDuid)
        host = nsDhcp6FindHost(sw, clientDuid, clientDuidLen, &mac, hostname);

    if (type == NS_DHCP6_SOLICIT)
        replyType = NS_DHCP6_ADVERTISE;
    g_byte_array_append(reply, &replyType, 1);
    g_byte_array_append(reply, msg + 1, 3);     /* transaction id */
    nsDhcp6AddOpt(reply, NS_DHCP6_OPT_SERVERID, sw->duid, sizeof(sw->duid));
    if (clientDuid)
        nsDhcp6AddOpt(reply, NS_DHCP6_OPT_CLIENTID, clientDuid, clientDuidLen);

    if (type == NS_DHCP6_CONFIRM) {
        /* are the addresses of the client still on this link? */
        bool onlink = true;
        int prefix = virNetworkIPDefPrefix(sw->dhcp6);

        for (p = opts, left = optslen; left >= 4;) {
            uint16_t c = nsGet16(p);
            size_t l = MIN(nsGet16(p + 2), left - 4);

            if (c == NS_DHCP6_OPT_IA_NA && l >= 12) {
                const uint8_t *ia = p + 4 + 12;
                size_t ialen = l - 12;
                const uint8_t *addr;
                size_t alen;

                if ((addr = nsDhcp6FindOpt(ia, ialen, NS_DHCP6_OPT_IAADDR, &alen)) &&
                    alen >= 16) {
                    virSocketAddr a = { .len = sizeof(struct sockaddr_in6) };
                    virSocketAddr an;
                    virSocketAddr net;

                    a.data.inet6.sin6_family = AF_INET6;
                    memcpy(&a.data.inet6.sin6_addr, addr, 16);
                    if (virSocketAddrMaskByPrefix(&a, prefix, &an) < 0 ||
                        virSocketAddrMaskByPrefix(&sw->dhcp6->address, prefix, &net) < 0 ||
                        !virSocketAddrEqual(&an, &net))
                        onlink = false;
                }
            }
            p += 4 + l;
            left -= 4 + l;
        }
        nsDhcp6AddStatus(reply, onlink ? NS_DHCP6_STATUS_SUCCESS : NS_DHCP6_STATUS_NOTONLINK,
                         onlink ? "all addresses still on link" : "not on link");
        goto send;
    }

    if (type == NS_DHCP6_INFORMATION_REQUEST) {
        nsDhcp6AddInfo(sw, reply);
        goto send;
    }

    /* every IA_NA of the client */
    for (p = opts, left = optslen; left >= 4;) {
        uint16_t c = nsGet16(p);
        size_t l = MIN(nsGet16(p + 2), left - 4);
        const uint8_t *ia = p + 4;

        p += 4 + l;
        left -= 4 + l;
        if (c != NS_DHCP6_OPT_IA_NA || l < 12)
            continue;

        {
            uint32_t iaid = ((uint32_t)ia[0] << 24) | (ia[1] << 16) | (ia[2] << 8) | ia[3];
            const uint8_t *req = NULL;
            size_t reqlen = 0;
            struct in6_addr requested;
            struct in6_addr addr;
            nsLease *lease = nsDhcp6FindLease(sw, clientid, iaid);
            g_autoptr(GByteArray) iaout = g_byte_array_new();
            uint8_t fixed[12];
            char addrstr[INET6_ADDRSTRLEN];

            if ((req = nsDhcp6FindOpt(ia + 12, l - 12, NS_DHCP6_OPT_IAADDR, &reqlen)) &&
                reqlen >= 16)
                memcpy(&requested, req, 16);
            else
                req = NULL;

            memcpy(fixed, ia, 4);

            if (type == NS_DHCP6_RELEASE || type == NS_DHCP6_DECLINE) {
                if (lease) {
                    g_ptr_array_remove(sw->leases, lease);
                    changed = true;
                }
                nsPut32(fixed + 4, 0);
                nsPut32(fixed + 8, 0);
                g_byte_array_append(iaout, fixed, 12);
                nsDhcp6AddStatus(iaout, NS_DHCP6_STATUS_SUCCESS, "released");
                nsDhcp6AddOpt(reply, NS_DHCP6_OPT_IA_NA, iaout->data, iaout->len);
                continue;
            }

            /* Renew and Rebind keep a binding we know, Solicit and Request
             * make one */
            if ((type == NS_DHCP6_RENEW || type == NS_DHCP6_REBIND) && !lease) {
                nsPut32(fixed + 4, 0);
                nsPut32(fixed + 8, 0);
                g_byte_array_append(iaout, fixed, 12);
                nsDhcp6AddStatus(iaout, NS_DHCP6_STATUS_NOBINDING, "no binding");
                nsDhcp6AddOpt(reply, NS_DHCP6_OPT_IA_NA, iaout->data, iaout->len);
                continue;
            }

            if (!nsDhcp6Choose(sw, host, clientid, iaid, req ? &requested : NULL, &addr)) {
                nsPut32(fixed + 4, 0);
                nsPut32(fixed + 8, 0);
                g_byte_array_append(iaout, fixed, 12);
                nsDhcp6AddStatus(iaout, NS_DHCP6_STATUS_NOADDRSAVAIL, "no addresses available");
                nsDhcp6AddOpt(reply, NS_DHCP6_OPT_IA_NA, iaout->data, iaout->len);
                nsLog("DHCPSOLICIT(%s) %s: no address available", sw->def->bridge, clientid);
                continue;
            }

            {
                unsigned long long lt = nsDhcp6LeaseTime(sw, host, &addr);
                uint32_t valid = lt ? MIN(lt, 0xfffffffe) : 0xffffffff;
                uint8_t iaaddr[24];

                nsPut32(fixed + 4, lt ? valid / 2 : 0xffffffff);
                nsPut32(fixed + 8, lt ? valid / 5 * 4 : 0xffffffff);
                g_byte_array_append(iaout, fixed, 12);
                memcpy(iaaddr, &addr, 16);
                nsPut32(iaaddr + 16, valid);    /* preferred */
                nsPut32(iaaddr + 20, valid);
                nsDhcp6AddOpt(iaout, NS_DHCP6_OPT_IAADDR, iaaddr, sizeof(iaaddr));
                nsDhcp6AddOpt(reply, NS_DHCP6_OPT_IA_NA, iaout->data, iaout->len);

                inet_ntop(AF_INET6, &addr, addrstr, sizeof(addrstr));
                if (type == NS_DHCP6_SOLICIT) {
                    nsLog("DHCPADVERTISE(%s) %s %s", sw->def->bridge, addrstr, clientid);
                    continue;
                }

                if (!lease) {
                    lease = g_new0(nsLease, 1);
                    lease->v6 = true;
                    lease->iaid = iaid;
                    lease->clientid = g_strdup(clientid);
                    g_ptr_array_add(sw->leases, lease);
                }
                lease->mac = mac;
                lease->ip6 = addr;
                lease->expiry = lt ? time(NULL) + lt : 0;
                g_free(lease->hostname);
                lease->hostname = g_strdup(host && host->name ? host->name : hostname);
                changed = true;
                nsLog("DHCPREPLY(%s) %s %s %s", sw->def->bridge, addrstr, clientid,
                      NULLSTR_EMPTY(lease->hostname));
            }
        }
    }
    nsDhcp6AddInfo(sw, reply);

 send:
    if (changed)
        nsLeasesSave(sw);
    nsGatewaySendUDP(sw, true, clientMac, (const uint8_t *)&sw->ll6, clientIP,
                     547, clientPort, reply->data, reply->len);
}


/* ---------------------------------------------------------------------
 * DNS, as dnsmasq answers with the configuration of libvirt: local hosts
 * (dns host, dhcp hosts and leases, expand-hosts with the domain), TXT,
 * SRV and local PTR records, then forwarding in strict order
 */

#define NS_DNS_A 1
#define NS_DNS_PTR 12
#define NS_DNS_TXT 16
#define NS_DNS_AAAA 28
#define NS_DNS_SRV 33
#define NS_DNS_ANY 255

#define NS_RCODE_NOERROR 0
#define NS_RCODE_SERVFAIL 2
#define NS_RCODE_NXDOMAIN 3
#define NS_RCODE_REFUSED 5


/* Read the name at @off into dotted form; returns the offset after it in
 * the message (pointers followed), or 0 if malformed */
static size_t
nsDnsReadName(const uint8_t *msg, size_t len, size_t off, char *name, size_t namelen)
{
    size_t out = 0;
    size_t next = 0;
    int jumps = 0;

    name[0] = '\0';
    while (off < len) {
        uint8_t l = msg[off];

        if (l == 0) {
            if (!next)
                next = off + 1;
            if (out && name[out - 1] == '.')
                name[--out] = '\0';
            return next;
        }
        if ((l & 0xc0) == 0xc0) {
            if (off + 1 >= len || ++jumps > 16)
                return 0;
            if (!next)
                next = off + 2;
            off = ((l & 0x3f) << 8) | msg[off + 1];
            continue;
        }
        if (off + 1 + l > len || out + l + 2 > namelen)
            return 0;
        memcpy(name + out, msg + off + 1, l);
        out += l;
        name[out++] = '.';
        name[out] = '\0';
        off += 1 + l;
    }
    return 0;
}


static void
nsDnsPutName(GByteArray *out, const char *name)
{
    g_auto(GStrv) labels = g_strsplit(name, ".", -1);
    GStrv l;

    for (l = labels; *l; l++) {
        uint8_t n = MIN(strlen(*l), 63);

        if (n == 0)
            continue;
        g_byte_array_append(out, &n, 1);
        g_byte_array_append(out, (const uint8_t *)*l, n);
    }
    g_byte_array_append(out, (const uint8_t *)"", 1);
}


static void
nsDnsPutRR(GByteArray *out, uint16_t type, uint32_t ttl,
           const uint8_t *rdata, size_t rdlen)
{
    uint8_t rr[12] = { 0xc0, 0x0c };    /* the name of the question */

    nsPut16(rr + 2, type);
    nsPut16(rr + 4, 1);                 /* IN */
    nsPut32(rr + 6, ttl);
    nsPut16(rr + 10, rdlen);
    g_byte_array_append(out, rr, 12);
    g_byte_array_append(out, rdata, rdlen);
}


/* Does @qname name @name, as is or completed with the network's domain? */
static bool
nsDnsNameMatches(nsSwitch *sw, const char *qname, const char *name)
{
    size_t nlen;

    if (!name)
        return false;
    if (STRCASEEQ(qname, name))
        return true;
    if (!sw->def->domain || strchr(name, '.'))
        return false;
    nlen = strlen(name);
    return g_ascii_strncasecmp(qname, name, nlen) == 0 && qname[nlen] == '.' &&
        STRCASEEQ(qname + nlen + 1, sw->def->domain);
}


typedef struct {
    int family;
    uint8_t addr[16];
} nsDnsAddr;


/* Add @a unless known already: a static host and its lease give the same
 * address, which dnsmasq answers once */
static void
nsDnsAddrAdd(GArray *addrs, const nsDnsAddr *a)
{
    size_t i;

    for (i = 0; i < addrs->len; i++) {
        nsDnsAddr *o = &g_array_index(addrs, nsDnsAddr, i);

        if (o->family == a->family &&
            memcmp(o->addr, a->addr, a->family == AF_INET ? 4 : 16) == 0)
            return;
    }
    g_array_append_vals(addrs, a, 1);
}


/* The local addresses of @qname; returns whether the name is known */
static bool
nsDnsLookupLocal(nsSwitch *sw, const char *qname, GArray *addrs)
{
    bool known = false;
    long long now = time(NULL);
    size_t i, j;

    for (i = 0; i < sw->def->dns.nhosts; i++) {
        virNetworkDNSHostDef *host = &sw->def->dns.hosts[i];

        for (j = 0; j < host->nnames; j++) {
            if (nsDnsNameMatches(sw, qname, host->names[j])) {
                nsDnsAddr a = { .family = VIR_SOCKET_ADDR_FAMILY(&host->ip) };

                if (a.family == AF_INET)
                    memcpy(a.addr, &host->ip.data.inet4.sin_addr, 4);
                else
                    memcpy(a.addr, &host->ip.data.inet6.sin6_addr, 16);
                nsDnsAddrAdd(addrs, &a);
                known = true;
                break;
            }
        }
    }

    for (i = 0; i < sw->def->nips; i++) {
        virNetworkIPDef *ipdef = &sw->def->ips[i];

        for (j = 0; j < ipdef->nhosts; j++) {
            virNetworkDHCPHostDef *host = &ipdef->hosts[j];

            if (VIR_SOCKET_ADDR_VALID(&host->ip) &&
                nsDnsNameMatches(sw, qname, host->name)) {
                nsDnsAddr a = { .family = VIR_SOCKET_ADDR_FAMILY(&host->ip) };

                if (a.family == AF_INET)
                    memcpy(a.addr, &host->ip.data.inet4.sin_addr, 4);
                else
                    memcpy(a.addr, &host->ip.data.inet6.sin6_addr, 16);
                nsDnsAddrAdd(addrs, &a);
                known = true;
            }
        }
    }

    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);

        if (!lease->offered && (!lease->expiry || lease->expiry >= now) &&
            nsDnsNameMatches(sw, qname, lease->hostname)) {
            nsDnsAddr a = { .family = lease->v6 ? AF_INET6 : AF_INET };

            if (lease->v6)
                memcpy(a.addr, &lease->ip6, 16);
            else
                memcpy(a.addr, &lease->ip, 4);
            nsDnsAddrAdd(addrs, &a);
            known = true;
        }
    }
    return known;
}


/* The name of a local address, for a PTR query */
static const char *
nsDnsLookupAddr(nsSwitch *sw, int family, const uint8_t *addr)
{
    long long now = time(NULL);
    size_t alen = family == AF_INET ? 4 : 16;
    size_t i, j;

    for (i = 0; i < sw->def->dns.nhosts; i++) {
        virNetworkDNSHostDef *host = &sw->def->dns.hosts[i];
        const void *ha = family == AF_INET ?
            (const void *)&host->ip.data.inet4.sin_addr :
            (const void *)&host->ip.data.inet6.sin6_addr;

        if (VIR_SOCKET_ADDR_FAMILY(&host->ip) == family && host->nnames &&
            memcmp(ha, addr, alen) == 0)
            return host->names[0];
    }
    for (i = 0; i < sw->def->nips; i++) {
        virNetworkIPDef *ipdef = &sw->def->ips[i];

        for (j = 0; j < ipdef->nhosts; j++) {
            virNetworkDHCPHostDef *host = &ipdef->hosts[j];
            const void *ha = family == AF_INET ?
                (const void *)&host->ip.data.inet4.sin_addr :
                (const void *)&host->ip.data.inet6.sin6_addr;

            if (host->name && VIR_SOCKET_ADDR_FAMILY(&host->ip) == family &&
                memcmp(ha, addr, alen) == 0)
                return host->name;
        }
    }
    for (i = 0; i < sw->leases->len; i++) {
        nsLease *lease = g_ptr_array_index(sw->leases, i);
        const void *la = lease->v6 ? (const void *)&lease->ip6 : (const void *)&lease->ip;

        if (!lease->offered && lease->hostname && lease->v6 == (family == AF_INET6) &&
            (!lease->expiry || lease->expiry >= now) &&
            memcmp(la, addr, alen) == 0)
            return lease->hostname;
    }
    return NULL;
}


/* Parse a reverse name (in-addr.arpa or ip6.arpa) */
static int
nsDnsParseReverse(const char *qname, uint8_t *addr)
{
    g_auto(GStrv) parts = g_strsplit(qname, ".", -1);
    size_t n = g_strv_length(parts);
    size_t i;

    if (n == 6 && STRCASEEQ(parts[4], "in-addr") && STRCASEEQ(parts[5], "arpa")) {
        for (i = 0; i < 4; i++) {
            unsigned int v;

            if (virStrToLong_ui(parts[3 - i], NULL, 10, &v) < 0 || v > 255)
                return -1;
            addr[i] = v;
        }
        return AF_INET;
    }
    if (n == 34 && STRCASEEQ(parts[32], "ip6") && STRCASEEQ(parts[33], "arpa")) {
        for (i = 0; i < 32; i++) {
            int v = g_ascii_xdigit_value(parts[31 - i][0]);

            if (v < 0 || parts[31 - i][1])
                return -1;
            if (i % 2)
                addr[i / 2] |= v;
            else
                addr[i / 2] = v << 4;
        }
        return AF_INET6;
    }
    return -1;
}


/* Is @addr in a subnet of the network with localPTR='yes'? */
static bool
nsDnsLocalPTR(nsSwitch *sw, int family, const uint8_t *addr)
{
    size_t i;

    for (i = 0; i < sw->def->nips; i++) {
        virNetworkIPDef *ipdef = &sw->def->ips[i];
        virSocketAddr a = { 0 };
        virSocketAddr anet;
        virSocketAddr net;
        int prefix = virNetworkIPDefPrefix(ipdef);

        if (ipdef->localPTR != VIR_TRISTATE_BOOL_YES ||
            VIR_SOCKET_ADDR_FAMILY(&ipdef->address) != family || prefix < 0)
            continue;
        a.data.stor.ss_family = family;
        if (family == AF_INET) {
            memcpy(&a.data.inet4.sin_addr, addr, 4);
            a.len = sizeof(struct sockaddr_in);
        } else {
            memcpy(&a.data.inet6.sin6_addr, addr, 16);
            a.len = sizeof(struct sockaddr_in6);
        }
        if (virSocketAddrMaskByPrefix(&a, prefix, &anet) == 0 &&
            virSocketAddrMaskByPrefix(&ipdef->address, prefix, &net) == 0 &&
            virSocketAddrEqual(&anet, &net))
            return true;
    }
    return false;
}


/* Answer from the local data; returns the rcode, or -1 to forward */
static int
nsDnsAnswerLocal(nsSwitch *sw,
                 const char *qname,
                 uint16_t qtype,
                 GByteArray *answers,
                 uint16_t *nanswers)
{
    g_autoptr(GArray) addrs = g_array_new(FALSE, FALSE, sizeof(nsDnsAddr));
    bool known = false;
    size_t i;

    if (nsDnsLookupLocal(sw, qname, addrs)) {
        known = true;
        for (i = 0; i < addrs->len; i++) {
            nsDnsAddr *a = &g_array_index(addrs, nsDnsAddr, i);

            if (a->family == AF_INET && (qtype == NS_DNS_A || qtype == NS_DNS_ANY)) {
                nsDnsPutRR(answers, NS_DNS_A, 0, a->addr, 4);
                (*nanswers)++;
            } else if (a->family == AF_INET6 &&
                       (qtype == NS_DNS_AAAA || qtype == NS_DNS_ANY)) {
                nsDnsPutRR(answers, NS_DNS_AAAA, 0, a->addr, 16);
                (*nanswers)++;
            }
        }
    }

    for (i = 0; i < sw->def->dns.ntxts; i++) {
        virNetworkDNSTxtDef *txt = &sw->def->dns.txts[i];

        if (STRCASEEQ(qname, txt->name)) {
            g_autoptr(GByteArray) rd = g_byte_array_new();
            const char *v = txt->value;
            size_t left = strlen(v);

            known = true;
            if (qtype != NS_DNS_TXT && qtype != NS_DNS_ANY)
                continue;
            do {
                uint8_t n = MIN(left, 255);

                g_byte_array_append(rd, &n, 1);
                g_byte_array_append(rd, (const uint8_t *)v, n);
                v += n;
                left -= n;
            } while (left);
            nsDnsPutRR(answers, NS_DNS_TXT, 0, rd->data, rd->len);
            (*nanswers)++;
        }
    }

    for (i = 0; i < sw->def->dns.nsrvs; i++) {
        virNetworkDNSSrvDef *srv = &sw->def->dns.srvs[i];
        g_autofree char *name = NULL;

        if (!srv->service || !srv->protocol)
            continue;
        name = g_strdup_printf("_%s._%s%s%s", srv->service, srv->protocol,
                               srv->domain ? "." : "", NULLSTR_EMPTY(srv->domain));
        if (STRCASEEQ(qname, name)) {
            known = true;
            if (srv->target && (qtype == NS_DNS_SRV || qtype == NS_DNS_ANY)) {
                g_autoptr(GByteArray) rd = g_byte_array_new();
                uint8_t fixed[6];

                nsPut16(fixed, srv->priority);
                nsPut16(fixed + 2, srv->weight);
                nsPut16(fixed + 4, srv->port);
                g_byte_array_append(rd, fixed, 6);
                nsDnsPutName(rd, srv->target);
                nsDnsPutRR(answers, NS_DNS_SRV, 0, rd->data, rd->len);
                (*nanswers)++;
            }
        }
    }

    if (qtype == NS_DNS_PTR) {
        uint8_t addr[16];
        int family = nsDnsParseReverse(qname, addr);
        const char *name;

        if (family > 0) {
            if ((name = nsDnsLookupAddr(sw, family, addr))) {
                g_autoptr(GByteArray) rd = g_byte_array_new();
                g_autofree char *fqdn = NULL;

                if (sw->def->domain && !strchr(name, '.'))
                    fqdn = g_strdup_printf("%s.%s", name, sw->def->domain);
                nsDnsPutName(rd, fqdn ? fqdn : name);
                nsDnsPutRR(answers, NS_DNS_PTR, 0, rd->data, rd->len);
                (*nanswers)++;
                return NS_RCODE_NOERROR;
            }
            if (nsDnsLocalPTR(sw, family, addr))
                return NS_RCODE_NXDOMAIN;
        }
    }

    if (known)
        return NS_RCODE_NOERROR;

    /* local=/domain/ (localOnly='yes') */
    if (sw->def->domain && sw->def->domainLocalOnly == VIR_TRISTATE_BOOL_YES) {
        size_t qlen = strlen(qname);
        size_t dlen = strlen(sw->def->domain);

        if (STRCASEEQ(qname, sw->def->domain) ||
            (qlen > dlen && qname[qlen - dlen - 1] == '.' &&
             STRCASEEQ(qname + qlen - dlen, sw->def->domain)))
            return NS_RCODE_NXDOMAIN;
    }

    /* domain-needed + local=// (forwardPlainNames='no') */
    if (sw->def->dns.forwardPlainNames == VIR_TRISTATE_BOOL_NO && !strchr(qname, '.'))
        return NS_RCODE_NXDOMAIN;

    return -1;
}


static void
nsUpstreamFromAddr(nsUpstream *up, const virSocketAddr *addr, int defport)
{
    int port = virSocketAddrGetPort((virSocketAddr *)addr);

    memset(up, 0, sizeof(*up));
    memcpy(&up->addr, &addr->data.stor, addr->len);
    up->addrlen = addr->len;
    if (port <= 0)
        port = defport;
    if (up->addr.ss_family == AF_INET)
        ((struct sockaddr_in *)&up->addr)->sin_port = htons(port);
    else
        ((struct sockaddr_in6 *)&up->addr)->sin6_port = htons(port);
}


/* The DNS servers of the host, as resolv.conf gives them to dnsmasq */
static void
nsRefreshHostServers(nsSwitch *sw)
{
    ULONG size = 16 * 1024;
    g_autofree IP_ADAPTER_ADDRESSES *addrs = NULL;
    IP_ADAPTER_ADDRESSES *a;
    GArray *servers = g_array_new(FALSE, TRUE, sizeof(nsUpstream));
    ULONG rc;

    sw->hostServersTime = nsNowMs();
    do {
        g_free(addrs);
        addrs = g_malloc(size);
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, addrs, &size);
    } while (rc == ERROR_BUFFER_OVERFLOW);

    for (a = rc == NO_ERROR ? addrs : NULL; a; a = a->Next) {
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;

        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        for (d = a->FirstDnsServerAddress; d; d = d->Next) {
            struct sockaddr *sa = d->Address.lpSockaddr;
            nsUpstream up = { 0 };
            size_t i;
            bool dup = false;

            if (sa->sa_family == AF_INET6) {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;

                /* Windows' placeholders when IPv6 DNS is not configured */
                if (s6->sin6_addr.s6_addr[0] == 0xfe && (s6->sin6_addr.s6_addr[1] & 0xc0) == 0xc0)
                    continue;
            } else if (sa->sa_family != AF_INET) {
                continue;
            }
            memcpy(&up.addr, sa, d->Address.iSockaddrLength);
            up.addrlen = d->Address.iSockaddrLength;
            if (sa->sa_family == AF_INET)
                ((struct sockaddr_in *)&up.addr)->sin_port = htons(53);
            else
                ((struct sockaddr_in6 *)&up.addr)->sin6_port = htons(53);

            for (i = 0; i < servers->len; i++) {
                nsUpstream *o = &g_array_index(servers, nsUpstream, i);

                if (o->addrlen == up.addrlen && memcmp(&o->addr, &up.addr, up.addrlen) == 0)
                    dup = true;
            }
            /* IPv4 first: IPv6 DNS servers are often unreachable */
            if (!dup) {
                if (sa->sa_family == AF_INET)
                    g_array_prepend_val(servers, up);
                else
                    g_array_append_val(servers, up);
            }
        }
    }

    g_free(sw->hostServers);
    sw->nhostServers = servers->len;
    sw->hostServers = (nsUpstream *)g_array_free(servers, FALSE);
}


/* The servers a query goes to, in order (strict-order); NULL when it must
 * not be forwarded, with *rcode set */
static nsUpstream *
nsDnsServersFor(nsSwitch *sw, const char *qname, size_t *n, int *rcode)
{
    virNetworkDNSForwarder *best = NULL;
    size_t bestlen = 0;
    size_t qlen = strlen(qname);
    GArray *servers;
    size_t i;

    *n = 0;
    /* server=/domain/addr and server=/domain/# : the longest domain wins */
    for (i = 0; i < sw->def->dns.nfwds; i++) {
        virNetworkDNSForwarder *fwd = &sw->def->dns.forwarders[i];
        size_t dlen;

        if (!fwd->domain)
            continue;
        dlen = strlen(fwd->domain);
        if ((STRCASEEQ(qname, fwd->domain) ||
             (qlen > dlen && qname[qlen - dlen - 1] == '.' &&
              STRCASEEQ(qname + qlen - dlen, fwd->domain))) && dlen > bestlen) {
            best = fwd;
            bestlen = dlen;
        }
    }

    servers = g_array_new(FALSE, TRUE, sizeof(nsUpstream));
    if (best) {
        for (i = 0; i < sw->def->dns.nfwds; i++) {
            virNetworkDNSForwarder *fwd = &sw->def->dns.forwarders[i];

            if (fwd->domain && STRCASEEQ(fwd->domain, best->domain) &&
                VIR_SOCKET_ADDR_VALID(&fwd->addr)) {
                nsUpstream up;

                nsUpstreamFromAddr(&up, &fwd->addr, 53);
                g_array_append_val(servers, up);
            }
        }
        if (servers->len == 0) {
            g_array_free(servers, TRUE);
            *rcode = NS_RCODE_NXDOMAIN;
            return NULL;
        }
    } else {
        bool noResolv = sw->isolated;

        for (i = 0; i < sw->def->dns.nfwds; i++) {
            virNetworkDNSForwarder *fwd = &sw->def->dns.forwarders[i];

            if (!fwd->domain && VIR_SOCKET_ADDR_VALID(&fwd->addr)) {
                nsUpstream up;

                nsUpstreamFromAddr(&up, &fwd->addr, 53);
                g_array_append_val(servers, up);
                noResolv = true;
            }
        }
        if (!noResolv) {
            if (nsNowMs() - sw->hostServersTime > 60000)
                nsRefreshHostServers(sw);
            g_array_append_vals(servers, sw->hostServers, sw->nhostServers);
        }
        if (servers->len == 0) {
            g_array_free(servers, TRUE);
            *rcode = NS_RCODE_REFUSED;
            return NULL;
        }
    }

    *n = servers->len;
    return (nsUpstream *)g_array_free(servers, FALSE);
}


static void
nsDnsQueryFree(nsDnsQuery *q)
{
    g_free(q->query);
    g_free(q->servers);
    g_free(q);
}


static void
nsDnsSendToClient(nsSwitch *sw, nsDnsQuery *q, const uint8_t *msg, size_t len)
{
    size_t max = (sw->def->mtu > 0 ? sw->def->mtu : 1500) - (q->v6 ? 48 : 28);
    g_autofree uint8_t *copy = g_memdup2(msg, len);
    const uint8_t *src = q->v6 ? (const uint8_t *)&sw->gw6 : (const uint8_t *)&sw->gw4;

    nsPut16(copy, q->clientId);
    if (len > max) {
        /* too big for a datagram: truncated, so that the client retries */
        size_t qend = 12;
        char name[256];

        if ((qend = nsDnsReadName(copy, len, 12, name, sizeof(name))))
            len = MIN(qend + 4, max);
        else
            len = 12;
        copy[2] |= 0x02;    /* TC */
        nsPut16(copy + 6, 0);
        nsPut16(copy + 8, 0);
        nsPut16(copy + 10, 0);
    }
    nsGatewaySendUDP(sw, q->v6, q->clientMac.addr, src, q->clientIP,
                     53, q->clientPort, copy, len);
}


static bool
nsDnsForwardNext(nsSwitch *sw, nsDnsQuery *q)
{
    while (q->next < q->nservers) {
        nsUpstream *up = &q->servers[q->next++];
        SOCKET s = up->addr.ss_family == AF_INET ? sw->dns4 : sw->dns6;

        if (s == INVALID_SOCKET)
            continue;
        if (sendto(s, (const char *)q->query, q->querylen, 0,
                   (struct sockaddr *)&up->addr, up->addrlen) != SOCKET_ERROR) {
            q->deadline = nsNowMs() + NS_DNS_RETRY_MS;
            return true;
        }
    }
    return false;
}


static void
nsDnsReplyCode(nsSwitch *sw, nsDnsQuery *q, int rcode)
{
    char name[256];
    size_t qend = nsDnsReadName(q->query, q->querylen, 12, name, sizeof(name));
    size_t len = qend && qend + 4 <= q->querylen ? qend + 4 : 12;
    g_autofree uint8_t *msg = g_memdup2(q->query, len);

    msg[2] = 0x80 | (msg[2] & 0x79);    /* QR, opcode and RD kept */
    msg[3] = 0x80 | rcode;              /* RA */
    nsPut16(msg + 4, len > 12 ? 1 : 0);
    nsPut16(msg + 6, 0);
    nsPut16(msg + 8, 0);
    nsPut16(msg + 10, 0);
    nsDnsSendToClient(sw, q, msg, len);
}


static void
nsDnsInput(nsSwitch *sw,
           bool v6,
           const uint8_t *clientMac,
           const uint8_t *clientIP,
           uint16_t clientPort,
           const uint8_t *msg,
           size_t len)
{
    char qname[256];
    size_t qend;
    uint16_t qtype;
    g_autoptr(GByteArray) answers = g_byte_array_new();
    uint16_t nanswers = 0;
    int rcode;
    nsDnsQuery *q;

    if (!sw->wantDNS || len < 12 || (msg[2] & 0x80) || nsGet16(msg + 4) != 1)
        return;
    if (!(qend = nsDnsReadName(msg, len, 12, qname, sizeof(qname))) || qend + 4 > len)
        return;
    qtype = nsGet16(msg + qend);

    q = g_new0(nsDnsQuery, 1);
    q->clientId = nsGet16(msg);
    q->v6 = v6;
    virMacAddrSetRaw(&q->clientMac, clientMac);
    memcpy(q->clientIP, clientIP, v6 ? 16 : 4);
    q->clientPort = clientPort;
    q->query = g_memdup2(msg, len);
    q->querylen = len;

    if ((msg[2] & 0x78) == 0 &&
        (rcode = nsDnsAnswerLocal(sw, qname, qtype, answers, &nanswers)) >= 0) {
        g_autoptr(GByteArray) reply = g_byte_array_new();

        g_byte_array_append(reply, msg, qend + 4);
        reply->data[2] = 0x84 | (msg[2] & 0x01);    /* QR AA, RD kept */
        reply->data[3] = 0x80 | rcode;
        nsPut16(reply->data + 4, 1);
        nsPut16(reply->data + 6, nanswers);
        nsPut16(reply->data + 8, 0);
        nsPut16(reply->data + 10, 0);
        g_byte_array_append(reply, answers->data, answers->len);
        nsDnsSendToClient(sw, q, reply->data, reply->len);
        nsDnsQueryFree(q);
        return;
    }

    if (!(q->servers = nsDnsServersFor(sw, qname, &q->nservers, &rcode))) {
        nsDnsReplyCode(sw, q, rcode);
        nsDnsQueryFree(q);
        return;
    }

    if (g_hash_table_size(sw->queries) >= NS_DNS_PENDING_MAX) {
        nsDnsQueryFree(q);
        return;
    }
    do {
        q->id = g_random_int_range(0, 65536);
    } while (g_hash_table_contains(sw->queries, GUINT_TO_POINTER(q->id)));
    nsPut16(q->query, q->id);

    if (!nsDnsForwardNext(sw, q)) {
        nsDnsReplyCode(sw, q, NS_RCODE_SERVFAIL);
        nsDnsQueryFree(q);
        return;
    }
    g_hash_table_insert(sw->queries, GUINT_TO_POINTER(q->id), q);
}


static void
nsDnsUpstreamInput(nsSwitch *sw, SOCKET s)
{
    static uint8_t buf[NS_FRAME_MAX];   /* one thread */

    for (;;) {
        int n = recvfrom(s, (char *)buf, sizeof(buf), 0, NULL, NULL);
        nsDnsQuery *q;

        if (n == SOCKET_ERROR) {
            /* WSAECONNRESET: an ICMP port unreachable from a server */
            if (WSAGetLastError() == WSAECONNRESET)
                continue;
            return;
        }
        if (n < 12)
            continue;
        if (!(q = g_hash_table_lookup(sw->queries, GUINT_TO_POINTER(nsGet16(buf)))))
            continue;
        g_hash_table_steal(sw->queries, GUINT_TO_POINTER(q->id));
        nsDnsSendToClient(sw, q, buf, n);
        nsDnsQueryFree(q);
    }
}


static void
nsDnsTimeouts(nsSwitch *sw)
{
    GHashTableIter iter;
    nsDnsQuery *q;
    gint64 now = nsNowMs();

    g_hash_table_iter_init(&iter, sw->queries);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&q)) {
        if (q->deadline > now)
            continue;
        if (nsDnsForwardNext(sw, q))
            continue;
        g_hash_table_iter_steal(&iter);
        nsDnsReplyCode(sw, q, NS_RCODE_SERVFAIL);
        nsDnsQueryFree(q);
    }
}


/* ---------------------------------------------------------------------
 * The gateway: DHCP and DNS here, the rest to libslirp
 */

static bool
nsIsIPv4Broadcast(nsSwitch *sw, uint32_t dst)
{
    return dst == 0xffffffff || (ntohl(dst) >> 28) == 0xe ||
        dst == ((sw->gw4 & sw->mask4) | ~sw->mask4);
}


/* ---------------------------------------------------------------------
 * Routed networks (forward mode route and open): the host has a real
 * interface on the network, a Wintun adapter named after the bridge with
 * the addresses of the gateway, as virbr0 has on Linux, and routes.  The
 * switch is the link layer between that IP interface and the guests:
 * ARP, neighbour and router discovery for the gateway, and the MAC
 * address of each guest for the packets of the host.
 */

typedef void *(WINAPI *nsWintunCreateAdapterFn)(LPCWSTR name, LPCWSTR type,
                                                const GUID *guid);
typedef void (WINAPI *nsWintunCloseAdapterFn)(void *adapter);
typedef void (WINAPI *nsWintunGetAdapterLUIDFn)(void *adapter, NET_LUID *luid);
typedef void *(WINAPI *nsWintunStartSessionFn)(void *adapter, DWORD capacity);
typedef void (WINAPI *nsWintunEndSessionFn)(void *session);
typedef HANDLE (WINAPI *nsWintunGetReadWaitEventFn)(void *session);
typedef BYTE *(WINAPI *nsWintunReceivePacketFn)(void *session, DWORD *size);
typedef void (WINAPI *nsWintunReleaseReceivePacketFn)(void *session, const BYTE *packet);
typedef BYTE *(WINAPI *nsWintunAllocateSendPacketFn)(void *session, DWORD size);
typedef void (WINAPI *nsWintunSendPacketFn)(void *session, const BYTE *packet);

static struct {
    nsWintunCreateAdapterFn CreateAdapter;
    nsWintunCloseAdapterFn CloseAdapter;
    nsWintunGetAdapterLUIDFn GetAdapterLUID;
    nsWintunStartSessionFn StartSession;
    nsWintunEndSessionFn EndSession;
    nsWintunGetReadWaitEventFn GetReadWaitEvent;
    nsWintunReceivePacketFn ReceivePacket;
    nsWintunReleaseReceivePacketFn ReleaseReceivePacket;
    nsWintunAllocateSendPacketFn AllocateSendPacket;
    nsWintunSendPacketFn SendPacket;
} nsWintun;

#define NS_RA_INTERVAL_MS 200000


static void
nsArpSend(nsSwitch *sw, uint16_t op, const uint8_t *dstMac,
          const uint8_t *tha, uint32_t tpa)
{
    uint8_t f[42] = { 0 };

    memcpy(f, dstMac, 6);
    memcpy(f + 6, sw->gwMac4, 6);
    nsPut16(f + 12, NS_ETH_P_ARP);
    nsPut16(f + 14, 1);
    nsPut16(f + 16, NS_ETH_P_IP);
    f[18] = 6;
    f[19] = 4;
    nsPut16(f + 20, op);
    memcpy(f + 22, sw->gwMac4, 6);
    memcpy(f + 28, &sw->gw4, 4);
    memcpy(f + 32, tha, 6);
    memcpy(f + 38, &tpa, 4);
    nsDeliver(sw, NULL, f, sizeof(f));
}


/* An ICMPv6 message of the router, from its link-local address */
static void
nsIcmp6Send(nsSwitch *sw, const uint8_t *dstMac, const uint8_t *dstIP,
            const uint8_t *icmp, size_t len)
{
    size_t total = NS_ETH_HLEN + 40 + len;
    g_autofree uint8_t *f = g_new0(uint8_t, total);
    uint8_t *ip = f + NS_ETH_HLEN;
    uint8_t *msg = ip + 40;
    uint32_t sum;

    memcpy(f, dstMac, 6);
    memcpy(f + 6, sw->gwMac6, 6);
    nsPut16(f + 12, NS_ETH_P_IPV6);
    ip[0] = 0x60;
    nsPut16(ip + 4, len);
    ip[6] = IPPROTO_ICMPV6;
    ip[7] = 255;
    memcpy(ip + 8, &sw->ll6, 16);
    memcpy(ip + 24, dstIP, 16);
    memcpy(msg, icmp, len);
    nsPut16(msg + 2, 0);
    sum = nsChecksumAdd(0, ip + 8, 32);
    sum += len + IPPROTO_ICMPV6;
    sum = nsChecksumAdd(sum, msg, len);
    nsPut16(msg + 2, nsChecksumFold(sum));
    nsDeliver(sw, NULL, f, total);
}


static void
nsMulticastMac6(const uint8_t *ip6, uint8_t *mac)
{
    mac[0] = 0x33;
    mac[1] = 0x33;
    memcpy(mac + 2, ip6 + 12, 4);
}


/* Router advertisement, as dnsmasq's enable-ra: the prefix (SLAAC unless
 * DHCPv6 manages the addresses), the MTU and the DNS server */
static void
nsRoutedAdvertise(nsSwitch *sw, const uint8_t *dstMac, const uint8_t *dstIP)
{
    uint8_t ra[16 + 8 + 8 + 32 + 24] = { 134 };
    size_t len = 16;
    int prefix = virNetworkIPDefPrefix(sw->ip6);
    virSocketAddr net;

    if (prefix < 0 || virSocketAddrMaskByPrefix(&sw->ip6->address, prefix, &net) < 0)
        return;
    ra[4] = 64;                         /* hop limit */
    ra[5] = sw->dhcp6 ? 0xc0 : 0;       /* managed, other */
    nsPut16(ra + 6, 1800);              /* router lifetime */

    ra[len] = 1;                        /* source link-layer address */
    ra[len + 1] = 1;
    memcpy(ra + len + 2, sw->gwMac6, 6);
    len += 8;
    if (sw->def->mtu > 0) {
        ra[len] = 5;
        ra[len + 1] = 1;
        nsPut32(ra + len + 4, sw->def->mtu);
        len += 8;
    }
    ra[len] = 3;                        /* prefix information */
    ra[len + 1] = 4;
    ra[len + 2] = prefix;
    ra[len + 3] = 0x80 | (sw->dhcp6 ? 0 : 0x40);
    nsPut32(ra + len + 4, 86400);
    nsPut32(ra + len + 8, 14400);
    memcpy(ra + len + 16, &net.data.inet6.sin6_addr, 16);
    len += 32;
    if (sw->wantDNS) {
        ra[len] = 25;                   /* recursive DNS server */
        ra[len + 1] = 3;
        nsPut32(ra + len + 4, 1800);
        memcpy(ra + len + 8, &sw->gw6, 16);
        len += 24;
    }
    nsIcmp6Send(sw, dstMac, dstIP, ra, len);
}


static void
nsRoutedAdvertiseAll(nsSwitch *sw)
{
    static const uint8_t allNodes[16] = { 0xff, 0x02, [15] = 1 };
    uint8_t mac[6];

    nsMulticastMac6(allNodes, mac);
    nsRoutedAdvertise(sw, mac, allNodes);
    sw->raTime = nsNowMs();
}


static void
nsNeighLearn6(nsSwitch *sw, const uint8_t *ip6, const uint8_t *mac)
{
    char key[INET6_ADDRSTRLEN];
    uint64_t *m;

    if (ip6[0] == 0xff || !memcmp(ip6, (uint8_t[16]){ 0 }, 16))
        return;
    inet_ntop(AF_INET6, ip6, key, sizeof(key));
    m = g_new(uint64_t, 1);
    *m = nsMacKey(mac);
    g_hash_table_insert(sw->neigh6, g_strdup(key), m);
}


static void
nsNeighLearn4(nsSwitch *sw, uint32_t ip, const uint8_t *mac)
{
    uint64_t *m = g_new(uint64_t, 1);

    *m = nsMacKey(mac);
    g_hash_table_insert(sw->neigh4, GUINT_TO_POINTER(ntohl(ip)), m);
}


static void
nsMacFromKey(uint64_t key, uint8_t *mac)
{
    int i;

    for (i = 5; i >= 0; i--, key >>= 8)
        mac[i] = key & 0xff;
}


static void
nsWintunSend(nsSwitch *sw, const uint8_t *pkt, size_t len)
{
    BYTE *out;

    if (!len || len > 0xffff ||
        !(out = nsWintun.AllocateSendPacket(sw->wintunSession, len)))
        return;     /* ring full: dropped, as by a busy link */
    memcpy(out, pkt, len);
    nsWintun.SendPacket(sw->wintunSession, out);
}


/* A frame of a guest for the host (the gateway) on a routed network */
static void
nsRoutedInput(nsSwitch *sw, const uint8_t *frame, size_t len)
{
    uint16_t proto = nsGet16(frame + 12);

    if (proto == NS_ETH_P_ARP && len >= 42) {
        const uint8_t *a = frame + NS_ETH_HLEN;
        uint32_t spa, tpa;

        memcpy(&spa, a + 14, 4);
        memcpy(&tpa, a + 24, 4);
        if (spa)
            nsNeighLearn4(sw, spa, a + 8);
        if (nsGet16(a + 6) == 1 && tpa == sw->gw4)
            nsArpSend(sw, 2, a + 8, a + 8, spa);
        return;
    }

    if (proto == NS_ETH_P_IP && len >= NS_ETH_HLEN + 20) {
        uint32_t src;

        memcpy(&src, frame + NS_ETH_HLEN + 12, 4);
        if (src)
            nsNeighLearn4(sw, src, frame + 6);
        nsWintunSend(sw, frame + NS_ETH_HLEN, len - NS_ETH_HLEN);
        return;
    }

    if (proto == NS_ETH_P_IPV6 && len >= NS_ETH_HLEN + 40) {
        const uint8_t *ip = frame + NS_ETH_HLEN;
        const uint8_t *icmp = ip + 40;
        size_t plen = MIN(nsGet16(ip + 4), len - NS_ETH_HLEN - 40);

        nsNeighLearn6(sw, ip + 8, frame + 6);
        if (ip[6] == IPPROTO_ICMPV6 && plen >= 8) {
            /* neighbour solicitation for an address of the router */
            if (icmp[0] == 135 && plen >= 24 &&
                (!memcmp(icmp + 8, &sw->gw6, 16) || !memcmp(icmp + 8, &sw->ll6, 16))) {
                uint8_t na[32] = { 136 };
                static const uint8_t allNodes[16] = { 0xff, 0x02, [15] = 1 };
                bool dad = !memcmp(ip + 8, (uint8_t[16]){ 0 }, 16);
                uint8_t mac[6];

                na[4] = 0x80 | 0x20 | (dad ? 0 : 0x40);     /* R, O, S */
                memcpy(na + 8, icmp + 8, 16);
                na[24] = 2;                                 /* target LL */
                na[25] = 1;
                memcpy(na + 26, sw->gwMac6, 6);
                if (dad) {
                    nsMulticastMac6(allNodes, mac);
                    nsIcmp6Send(sw, mac, allNodes, na, sizeof(na));
                } else {
                    nsIcmp6Send(sw, frame + 6, ip + 8, na, sizeof(na));
                }
                return;
            }
            if (icmp[0] == 133) {                   /* router solicitation */
                if (memcmp(ip + 8, (uint8_t[16]){ 0 }, 16))
                    nsRoutedAdvertise(sw, frame + 6, ip + 8);
                else
                    nsRoutedAdvertiseAll(sw);
                return;
            }
            if (icmp[0] == 135 || icmp[0] == 136 || icmp[0] == 134)
                return;     /* the guests' own discovery */
        }
        if (ip[24] == 0xff)
            return;         /* the host needs no guest multicast */
        nsWintunSend(sw, ip, len - NS_ETH_HLEN);
    }
}


/* A packet of the host for the guests: framed for the guest (or the
 * route's next hop) it goes to, whose MAC address is learnt from its
 * traffic, else asked for and the packet dropped as by a neighbour cache
 * still incomplete */
static void
nsRoutedToGuest(nsSwitch *sw, const uint8_t *pkt, size_t len)
{
    g_autofree uint8_t *f = g_new(uint8_t, NS_ETH_HLEN + len);
    uint8_t dstMac[6];
    uint64_t *key = NULL;

    if (len < 20)
        return;
    memcpy(f + NS_ETH_HLEN, pkt, len);

    if ((pkt[0] >> 4) == 4 && sw->ip4) {
        uint32_t dst;
        uint32_t hop;
        size_t i;

        memcpy(&dst, pkt + 16, 4);
        hop = dst;
        if (nsIsIPv4Broadcast(sw, dst)) {
            if ((ntohl(dst) >> 28) == 0xe) {
                dstMac[0] = 0x01;
                dstMac[1] = 0x00;
                dstMac[2] = 0x5e;
                dstMac[3] = (ntohl(dst) >> 16) & 0x7f;
                dstMac[4] = (ntohl(dst) >> 8) & 0xff;
                dstMac[5] = ntohl(dst) & 0xff;
            } else {
                memset(dstMac, 0xff, 6);
            }
        } else {
            /* static <route>s of the network go through a guest */
            if ((dst & sw->mask4) != (sw->gw4 & sw->mask4)) {
                for (i = 0; i < sw->def->nroutes; i++) {
                    virNetDevIPRoute *r = sw->def->routes[i];
                    virSocketAddr *addr = virNetDevIPRouteGetAddress(r);
                    virSocketAddr *gw = virNetDevIPRouteGetGateway(r);
                    unsigned int prefix = virNetDevIPRouteGetPrefix(r);
                    uint32_t mask = prefix ? htonl(0xffffffffu << (32 - prefix)) : 0;

                    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET) && gw &&
                        (dst & mask) == (nsAddr4(addr) & mask)) {
                        hop = nsAddr4(gw);
                        break;
                    }
                }
            }
            if (!(key = g_hash_table_lookup(sw->neigh4, GUINT_TO_POINTER(ntohl(hop))))) {
                static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
                static const uint8_t zero[6] = { 0 };

                nsArpSend(sw, 1, bcast, zero, hop);
                return;
            }
            nsMacFromKey(*key, dstMac);
        }
        memcpy(f, dstMac, 6);
        memcpy(f + 6, sw->gwMac4, 6);
        nsPut16(f + 12, NS_ETH_P_IP);
    } else if ((pkt[0] >> 4) == 6 && sw->ip6 && len >= 40) {
        const uint8_t *dst = pkt + 24;
        char k[INET6_ADDRSTRLEN];

        if (dst[0] == 0xff) {
            nsMulticastMac6(dst, dstMac);
        } else {
            inet_ntop(AF_INET6, dst, k, sizeof(k));
            if (!(key = g_hash_table_lookup(sw->neigh6, k))) {
                /* neighbour solicitation to the solicited-node address */
                uint8_t ns[32] = { 135 };
                uint8_t snm[16] = { 0xff, 0x02, [11] = 1, [12] = 0xff };
                uint8_t mac[6];

                memcpy(snm + 13, dst + 13, 3);
                memcpy(ns + 8, dst, 16);
                ns[24] = 1;
                ns[25] = 1;
                memcpy(ns + 26, sw->gwMac6, 6);
                nsMulticastMac6(snm, mac);
                nsIcmp6Send(sw, mac, snm, ns, sizeof(ns));
                return;
            }
            nsMacFromKey(*key, dstMac);
        }
        memcpy(f, dstMac, 6);
        memcpy(f + 6, sw->gwMac6, 6);
        nsPut16(f + 12, NS_ETH_P_IPV6);
    } else {
        return;
    }
    nsDeliver(sw, NULL, f, NS_ETH_HLEN + len);
}


static void
nsRoutedDrain(nsSwitch *sw)
{
    char buf[64];
    BYTE *pkt;
    DWORD size;

    while (recv(sw->wake, buf, sizeof(buf), 0) > 0)
        ;
    while ((pkt = nsWintun.ReceivePacket(sw->wintunSession, &size))) {
        nsRoutedToGuest(sw, pkt, size);
        nsWintun.ReleaseReceivePacket(sw->wintunSession, pkt);
    }
    SetEvent(sw->wintunDrained);
}


/* Wakes the loop (WSAPoll waits on sockets only) when Wintun has packets */
static DWORD WINAPI
nsWintunWaiter(LPVOID opaque)
{
    nsSwitch *sw = opaque;
    HANDLE readEvs[2] = { sw->wintunRead, sw->wintunStop };
    HANDLE drainEvs[2] = { sw->wintunDrained, sw->wintunStop };
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    for (;;) {
        if (WaitForMultipleObjects(2, readEvs, FALSE, INFINITE) != WAIT_OBJECT_0)
            break;
        sendto(s, "w", 1, 0, (struct sockaddr *)&sw->wakeAddr, sizeof(sw->wakeAddr));
        if (WaitForMultipleObjects(2, drainEvs, FALSE, INFINITE) != WAIT_OBJECT_0)
            break;
    }
    closesocket(s);
    return 0;
}


static int
nsStartRouted(nsSwitch *sw)
{
    g_autofree wchar_t *name = g_utf8_to_utf16(sw->def->bridge, -1, NULL, NULL, NULL);
    GUID guid;
    int namelen = sizeof(sw->wakeAddr);
    u_long nonblock = 1;
    size_t i;

    /* wintun.dll beside the switch, from https://www.wintun.net */
    if (!(sw->wintunDll = LoadLibraryExW(L"wintun.dll", NULL,
                                         LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                         LOAD_LIBRARY_SEARCH_SYSTEM32))) {
        nsLog("forward mode %s needs Wintun: wintun.dll was not found beside "
              "libvirt_netswitch.exe (error %lu)",
              virNetworkForwardTypeToString(sw->def->forward.type), GetLastError());
        return -1;
    }
#define NS_WINTUN_FN(fn) \
    if (!(nsWintun.fn = (void *)GetProcAddress(sw->wintunDll, "Wintun" #fn))) { \
        nsLog("wintun.dll has no Wintun%s", #fn); \
        return -1; \
    }
    NS_WINTUN_FN(CreateAdapter);
    NS_WINTUN_FN(CloseAdapter);
    NS_WINTUN_FN(GetAdapterLUID);
    NS_WINTUN_FN(StartSession);
    NS_WINTUN_FN(EndSession);
    NS_WINTUN_FN(GetReadWaitEvent);
    NS_WINTUN_FN(ReceivePacket);
    NS_WINTUN_FN(ReleaseReceivePacket);
    NS_WINTUN_FN(AllocateSendPacket);
    NS_WINTUN_FN(SendPacket);
#undef NS_WINTUN_FN

    /* the same adapter identity for the network each time */
    G_STATIC_ASSERT(sizeof(guid) == VIR_UUID_BUFLEN);
    memcpy(&guid, sw->def->uuid, sizeof(guid));
    if (!(sw->wintunAdapter = nsWintun.CreateAdapter(name, L"libvirt", &guid))) {
        DWORD err = GetLastError();

        nsLog("cannot create the Wintun adapter %s (error %lu%s)", sw->def->bridge, err,
              err == ERROR_ACCESS_DENIED ? ": administrator rights are needed" : "");
        return -1;
    }
    nsWintun.GetAdapterLUID(sw->wintunAdapter, &sw->luid);

    /* the addresses of the bridge */
    for (i = 0; i < 2; i++) {
        virNetworkIPDef *ipdef = i ? sw->ip6 : sw->ip4;
        MIB_UNICASTIPADDRESS_ROW row;
        DWORD rc;

        if (!ipdef)
            continue;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = sw->luid;
        if (i) {
            row.Address.Ipv6.sin6_family = AF_INET6;
            row.Address.Ipv6.sin6_addr = sw->gw6;
        } else {
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.s_addr = sw->gw4;
        }
        row.OnLinkPrefixLength = virNetworkIPDefPrefix(ipdef);
        row.DadState = IpDadStatePreferred;
        if ((rc = CreateUnicastIpAddressEntry(&row)) != NO_ERROR &&
            rc != ERROR_OBJECT_ALREADY_EXISTS) {
            nsLog("cannot add the address of %s (error %lu)", sw->def->bridge, rc);
            return -1;
        }
    }

    /* route: the host forwards (ip_forward), open: as configured */
    if (sw->def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        PMIB_IPFORWARD_TABLE2 routes = NULL;
        ULONG j;

        for (i = 0; i < 2; i++) {
            MIB_IPINTERFACE_ROW ir;

            if (!(i ? sw->ip6 : sw->ip4))
                continue;
            InitializeIpInterfaceEntry(&ir);
            ir.Family = i ? AF_INET6 : AF_INET;
            ir.InterfaceLuid = sw->luid;
            if (GetIpInterfaceEntry(&ir) == NO_ERROR) {
                ir.ForwardingEnabled = TRUE;
                ir.SitePrefixLength = 0;
                SetIpInterfaceEntry(&ir);
            }
        }
        /* and the interfaces of the default routes, to which it forwards */
        if (GetIpForwardTable2(AF_UNSPEC, &routes) == NO_ERROR) {
            for (j = 0; j < routes->NumEntries; j++) {
                MIB_IPFORWARD_ROW2 *r = &routes->Table[j];
                MIB_IPINTERFACE_ROW ir;

                if (r->DestinationPrefix.PrefixLength != 0)
                    continue;
                InitializeIpInterfaceEntry(&ir);
                ir.Family = r->DestinationPrefix.Prefix.si_family;
                ir.InterfaceLuid = r->InterfaceLuid;
                if (GetIpInterfaceEntry(&ir) == NO_ERROR && !ir.ForwardingEnabled) {
                    ir.ForwardingEnabled = TRUE;
                    if (ir.Family == AF_INET)
                        ir.SitePrefixLength = 0;
                    SetIpInterfaceEntry(&ir);
                }
            }
            FreeMibTable(routes);
        }
    }

    /* the static <route>s of the network, through the bridge */
    for (i = 0; i < sw->def->nroutes; i++) {
        virNetDevIPRoute *r = sw->def->routes[i];
        virSocketAddr *addr = virNetDevIPRouteGetAddress(r);
        virSocketAddr *gw = virNetDevIPRouteGetGateway(r);
        MIB_IPFORWARD_ROW2 row;
        DWORD rc;

        if (!gw || !VIR_SOCKET_ADDR_VALID(gw))
            continue;
        InitializeIpForwardEntry(&row);
        row.InterfaceLuid = sw->luid;
        memcpy(&row.DestinationPrefix.Prefix, &addr->data.stor, addr->len);
        row.DestinationPrefix.PrefixLength = virNetDevIPRouteGetPrefix(r);
        memcpy(&row.NextHop, &gw->data.stor, gw->len);
        row.Metric = virNetDevIPRouteGetMetric(r);
        row.Protocol = MIB_IPPROTO_NETMGMT;
        if ((rc = CreateIpForwardEntry2(&row)) != NO_ERROR &&
            rc != ERROR_OBJECT_ALREADY_EXISTS)
            nsLog("cannot add a route of %s (error %lu)", sw->def->bridge, rc);
    }

    if (!(sw->wintunSession = nsWintun.StartSession(sw->wintunAdapter, 0x400000))) {
        nsLog("cannot start the Wintun session (error %lu)", GetLastError());
        return -1;
    }
    sw->wintunRead = nsWintun.GetReadWaitEvent(sw->wintunSession);
    sw->wintunDrained = CreateEventW(NULL, FALSE, FALSE, NULL);
    sw->wintunStop = CreateEventW(NULL, TRUE, FALSE, NULL);

    sw->wakeAddr.sin_family = AF_INET;
    sw->wakeAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if ((sw->wake = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET ||
        bind(sw->wake, (struct sockaddr *)&sw->wakeAddr, sizeof(sw->wakeAddr)) == SOCKET_ERROR ||
        getsockname(sw->wake, (struct sockaddr *)&sw->wakeAddr, &namelen) == SOCKET_ERROR) {
        nsLog("cannot create the wake socket (error %d)", WSAGetLastError());
        return -1;
    }
    ioctlsocket(sw->wake, FIONBIO, &nonblock);
    sw->wintunThread = CreateThread(NULL, 0, nsWintunWaiter, sw, 0, NULL);

    nsLog("Wintun %s: forward mode %s", sw->def->bridge,
          virNetworkForwardTypeToString(sw->def->forward.type));
    if (sw->ip6)
        nsRoutedAdvertiseAll(sw);
    return 0;
}


static void
nsStopRouted(nsSwitch *sw)
{
    if (sw->wintunStop)
        SetEvent(sw->wintunStop);
    if (sw->wintunThread)
        WaitForSingleObject(sw->wintunThread, 2000);
    if (sw->wintunSession)
        nsWintun.EndSession(sw->wintunSession);
    /* closing the adapter removes it, with its addresses and routes */
    if (sw->wintunAdapter)
        nsWintun.CloseAdapter(sw->wintunAdapter);
}


/* To the host: libslirp (nat, none) or the host's interface (route, open) */
static void
nsGatewayToHost(nsSwitch *sw, const uint8_t *frame, size_t len)
{
    if (sw->routed) {
        if (sw->wintunSession)
            nsRoutedInput(sw, frame, len);
    } else if (sw->slirp) {
        slirp_input(sw->slirp, frame, len);
    }
}


static void
nsGatewayInput(nsSwitch *sw, const uint8_t *frame, size_t len)
{
    uint16_t proto = nsGet16(frame + 12);

    if (proto == NS_ETH_P_ARP) {
        if (sw->ip4)
            nsGatewayToHost(sw, frame, len);
        return;
    }

    if (proto == NS_ETH_P_IP && sw->ip4 && len >= NS_ETH_HLEN + 20) {
        const uint8_t *ip = frame + NS_ETH_HLEN;
        size_t ihl = (ip[0] & 0x0f) * 4;
        size_t iplen = MIN(nsGet16(ip + 2), len - NS_ETH_HLEN);
        uint32_t dst;

        memcpy(&dst, ip + 16, 4);
        if ((ip[0] >> 4) != 4 || ihl < 20 || iplen < ihl)
            return;

        if (ip[9] == IPPROTO_UDP && iplen >= ihl + 8 &&
            (nsGet16(ip + 6) & 0x3fff) == 0) {
            const uint8_t *udp = ip + ihl;
            uint16_t dport = nsGet16(udp + 2);
            size_t ulen = MIN(nsGet16(udp + 4), iplen - ihl);

            if (ulen < 8)
                return;
            if (dport == 67) {
                nsDhcpInput(sw, udp + 8, ulen - 8);
                return;
            }
            if (dport == 53 && dst == sw->gw4) {
                nsDnsInput(sw, false, frame + 6, ip + 12, nsGet16(udp),
                           udp + 8, ulen - 8);
                return;
            }
        }

        /* nothing else goes to the broadcast addresses: libslirp would
         * send them to the network of the host */
        if (nsIsIPv4Broadcast(sw, dst))
            return;
        /* isolated: the guests only reach the host, by the gateway address */
        if (sw->isolated && dst != sw->gw4)
            return;
        nsGatewayToHost(sw, frame, len);
        return;
    }

    if (proto == NS_ETH_P_IPV6 && sw->ip6 && len >= NS_ETH_HLEN + 40) {
        const uint8_t *ip = frame + NS_ETH_HLEN;
        const uint8_t *dst = ip + 24;
        size_t plen = MIN(nsGet16(ip + 4), len - NS_ETH_HLEN - 40);

        if (ip[6] == IPPROTO_UDP && plen >= 8 &&
            memcmp(dst, &sw->gw6, 16) == 0 && nsGet16(ip + 40 + 2) == 53) {
            size_t ulen = MIN(nsGet16(ip + 40 + 4), plen);

            if (ulen >= 8)
                nsDnsInput(sw, true, frame + 6, ip + 8, nsGet16(ip + 40),
                           ip + 48, ulen - 8);
            return;
        }
        /* DHCPv6, to All_DHCP_Relay_Agents_and_Servers */
        if (ip[6] == IPPROTO_UDP && plen >= 8 && nsGet16(ip + 40 + 2) == 547) {
            size_t ulen = MIN(nsGet16(ip + 40 + 4), plen);

            if (ulen >= 8)
                nsDhcp6Input(sw, frame + 6, ip + 8, nsGet16(ip + 40),
                             ip + 48, ulen - 8);
            return;
        }
        /* multicast: only neighbour and router discovery */
        if (dst[0] == 0xff && ip[6] != IPPROTO_ICMPV6)
            return;
        if (sw->isolated && dst[0] != 0xff && memcmp(dst, &sw->gw6, 16) != 0)
            return;
        nsGatewayToHost(sw, frame, len);
    }
}


/*
 * libslirp's router advertisements, made those of dnsmasq for libvirt:
 * - an isolated network gives no IPv6 default route: a router lifetime
 *   of 0 (ra-param=*,0,0)
 * - with DHCPv6, the addresses are managed (M and O flags) and the prefix
 *   is not for SLAAC (A flag off), as for a dhcp-range without slaac
 */
static void
nsRewriteRouterAdvert(nsSwitch *sw, uint8_t *frame, size_t len)
{
    uint8_t *ip = frame + NS_ETH_HLEN;
    uint8_t *icmp = ip + 40;
    size_t plen;
    size_t off;
    uint32_t sum;

    if (len < NS_ETH_HLEN + 40 + 16 || nsGet16(frame + 12) != NS_ETH_P_IPV6 ||
        ip[6] != IPPROTO_ICMPV6 || icmp[0] != 134)
        return;
    plen = MIN(nsGet16(ip + 4), len - NS_ETH_HLEN - 40);

    if (sw->isolated)
        nsPut16(icmp + 6, 0);       /* router lifetime */
    if (sw->dhcp6) {
        icmp[5] |= 0xc0;            /* managed, other configuration */
        for (off = 16; off + 8 <= plen && icmp[off + 1];
             off += icmp[off + 1] * 8) {
            if (icmp[off] == 3 && icmp[off + 1] == 4 && off + 32 <= plen)
                icmp[off + 3] &= ~0x40; /* prefix information: autonomous */
        }
    }
    nsPut16(icmp + 2, 0);
    sum = nsChecksumAdd(0, ip + 8, 32);
    sum += plen + IPPROTO_ICMPV6;
    sum = nsChecksumAdd(sum, icmp, plen);
    nsPut16(icmp + 2, nsChecksumFold(sum));
}


static slirp_ssize_t
nsSlirpSend(const void *buf, size_t len, void *opaque)
{
    nsSwitch *sw = opaque;

    if ((sw->isolated || sw->dhcp6) && len >= NS_ETH_HLEN + 40 &&
        nsGet16((const uint8_t *)buf + 12) == NS_ETH_P_IPV6) {
        g_autofree uint8_t *copy = g_memdup2(buf, len);

        nsRewriteRouterAdvert(sw, copy, len);
        nsDeliver(sw, NULL, copy, len);
        return len;
    }
    nsDeliver(sw, NULL, buf, len);
    return len;
}


static void
nsSlirpGuestError(const char *msg, void *opaque G_GNUC_UNUSED)
{
    nsLog("slirp: guest error: %s", msg);
}


static int64_t
nsSlirpClock(void *opaque G_GNUC_UNUSED)
{
    return g_get_monotonic_time() * 1000;
}


static void *
nsSlirpTimerNewOpaque(SlirpTimerId id, void *cb_opaque, void *opaque)
{
    nsSwitch *sw = opaque;
    nsTimer *t = g_new0(nsTimer, 1);

    t->id = id;
    t->cb_opaque = cb_opaque;
    t->expire = -1;
    g_ptr_array_add(sw->timers, t);
    return t;
}


static void
nsSlirpTimerFree(void *timer, void *opaque)
{
    nsSwitch *sw = opaque;

    g_ptr_array_remove(sw->timers, timer);
    g_free(timer);
}


static void
nsSlirpTimerMod(void *timer, int64_t expire, void *opaque G_GNUC_UNUSED)
{
    ((nsTimer *)timer)->expire = expire;
}


static void
nsSlirpRegister(slirp_os_socket s G_GNUC_UNUSED, void *opaque G_GNUC_UNUSED)
{
}


static void
nsSlirpNotify(void *opaque G_GNUC_UNUSED)
{
}


static const SlirpCb nsSlirpCallbacks = {
    .send_packet = nsSlirpSend,
    .guest_error = nsSlirpGuestError,
    .clock_get_ns = nsSlirpClock,
    .timer_free = nsSlirpTimerFree,
    .timer_mod = nsSlirpTimerMod,
    .notify = nsSlirpNotify,
    .timer_new_opaque = nsSlirpTimerNewOpaque,
    .register_poll_socket = nsSlirpRegister,
    .unregister_poll_socket = nsSlirpRegister,
};


/* ---------------------------------------------------------------------
 * Configuration
 */

static int
nsLoadConfig(nsSwitch *sw)
{
    g_autoptr(virNetworkDef) def = NULL;
    size_t i;

    if (!(def = virNetworkDefParse(NULL, sw->configFile, NULL, false)))
        return -1;

    if (sw->def) {
        /* SIGHUP: only what net-update changes at run time is reloaded,
         * the addresses stay those of libslirp */
        virNetworkDefFree(sw->def);
        sw->def = g_steal_pointer(&def);
        sw->ip4 = sw->ip6 = sw->dhcp4 = sw->dhcp6 = NULL;
    } else {
        sw->def = g_steal_pointer(&def);
    }

    for (i = 0; i < sw->def->nips; i++) {
        virNetworkIPDef *ipdef = &sw->def->ips[i];

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            if (!sw->ip4)
                sw->ip4 = ipdef;
            if (!sw->dhcp4 && (ipdef->nranges || ipdef->nhosts))
                sw->dhcp4 = ipdef;
        } else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6)) {
            /* libslirp has one IPv6 prefix: that with DHCPv6 if any (one
             * only, as the network driver checks) */
            if (!sw->dhcp6 && (ipdef->nranges || ipdef->nhosts)) {
                sw->dhcp6 = ipdef;
                sw->ip6 = ipdef;
            }
            if (!sw->ip6)
                sw->ip6 = ipdef;
        }
    }
    if (sw->slirp && sw->ip6 &&
        memcmp(&sw->ip6->address.data.inet6.sin6_addr, &sw->gw6, 16) != 0) {
        nsLog("the IPv6 address of the gateway changes on restart only");
        sw->ip6 = sw->dhcp6 = NULL;
    }
    sw->isolated = sw->def->forward.type == VIR_NETWORK_FORWARD_NONE;
    sw->routed = sw->def->forward.type == VIR_NETWORK_FORWARD_ROUTE ||
                 sw->def->forward.type == VIR_NETWORK_FORWARD_OPEN;
    sw->wantDNS = sw->def->dns.enable != VIR_TRISTATE_BOOL_NO && sw->def->nips > 0;
    return 0;
}


static int
nsStartSlirp(nsSwitch *sw)
{
    SlirpConfig cfg = { 0 };
    g_autofree char *tftp = NULL;

    if (!sw->ip4 && !sw->ip6)
        return 0; /* a network without addresses is only a switch */

    cfg.version = 6;
    cfg.restricted = 0;
    if (sw->ip4) {
        virSocketAddr netmask;
        int prefix = virNetworkIPDefPrefix(sw->ip4);

        if (prefix < 0 ||
            virSocketAddrPrefixToNetmask(prefix, &netmask, AF_INET) < 0)
            return -1;
        cfg.in_enabled = true;
        sw->gw4 = nsAddr4(&sw->ip4->address);
        sw->mask4 = nsAddr4(&netmask);
        cfg.vnetwork.s_addr = sw->gw4 & sw->mask4;
        cfg.vnetmask.s_addr = sw->mask4;
        cfg.vhost.s_addr = sw->gw4;
        cfg.vnameserver.s_addr = sw->gw4;
        /* DHCP range start is required by libslirp even with its DHCP off */
        cfg.vdhcp_start.s_addr = htonl(ntohl(cfg.vnetwork.s_addr) + 15);
        sw->gwMac4[0] = 0x52;
        sw->gwMac4[1] = 0x55;
        memcpy(sw->gwMac4 + 2, &sw->gw4, 4);
        if (sw->ip4->tftproot) {
            tftp = g_strdup(sw->ip4->tftproot);
            cfg.tftp_path = tftp;
        }
    }
    if (sw->ip6) {
        int prefix = virNetworkIPDefPrefix(sw->ip6);
        virSocketAddr net;

        if (prefix < 0 || virSocketAddrMaskByPrefix(&sw->ip6->address, prefix, &net) < 0)
            return -1;
        cfg.in6_enabled = true;
        cfg.vprefix_addr6 = net.data.inet6.sin6_addr;
        cfg.vprefix_len = prefix;
        sw->gw6 = sw->ip6->address.data.inet6.sin6_addr;
        cfg.vhost6 = sw->gw6;
        cfg.vnameserver6 = sw->gw6;
        sw->gwMac6[0] = 0x52;
        sw->gwMac6[1] = 0x56;
        memcpy(sw->gwMac6 + 2, sw->gw6.s6_addr + 12, 4);

        /* DHCPv6: a DUID-LL from that address, and the link-local address
         * the replies come from (EUI-64 of the same address) */
        nsPut16(sw->duid, 3);
        nsPut16(sw->duid + 2, 1);
        memcpy(sw->duid + 4, sw->gwMac6, 6);
        sw->ll6.s6_addr[0] = 0xfe;
        sw->ll6.s6_addr[1] = 0x80;
        sw->ll6.s6_addr[8] = sw->gwMac6[0] ^ 0x02;
        sw->ll6.s6_addr[9] = sw->gwMac6[1];
        sw->ll6.s6_addr[10] = sw->gwMac6[2];
        sw->ll6.s6_addr[11] = 0xff;
        sw->ll6.s6_addr[12] = 0xfe;
        memcpy(sw->ll6.s6_addr + 13, sw->gwMac6 + 3, 3);
    }
    if (sw->def->mtu > 0) {
        cfg.if_mtu = sw->def->mtu;
        cfg.if_mru = sw->def->mtu;
    }
    cfg.vhostname = sw->def->name;
    cfg.vdomainname = sw->def->domain;
    cfg.disable_dns = true;
    cfg.disable_dhcp = true;

    /* route, open: the host itself is the gateway (nsStartRouted) */
    if (sw->routed)
        return 0;

    if (!(sw->slirp = slirp_new(&cfg, &nsSlirpCallbacks, sw))) {
        nsLog("cannot start libslirp");
        return -1;
    }
    nsLog("libslirp %s: %s gateway, forward mode %s", slirp_version_string(),
          sw->def->bridge, sw->isolated ? "none (isolated)" : "nat");
    return 0;
}


static int
nsOpenSockets(nsSwitch *sw)
{
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    u_long nonblock = 1;

    if (strlen(sw->socketPath) >= sizeof(un.sun_path)) {
        nsLog("socket path too long: %s", sw->socketPath);
        return -1;
    }
    g_strlcpy(un.sun_path, sw->socketPath, sizeof(un.sun_path));
    DeleteFileA(sw->socketPath);

    if ((sw->listener = socket(AF_UNIX, SOCK_STREAM, 0)) == INVALID_SOCKET ||
        bind(sw->listener, (struct sockaddr *)&un, sizeof(un)) == SOCKET_ERROR ||
        listen(sw->listener, 16) == SOCKET_ERROR) {
        nsLog("cannot listen on %s: error %d", sw->socketPath, WSAGetLastError());
        return -1;
    }
    ioctlsocket(sw->listener, FIONBIO, &nonblock);

    if ((sw->dns4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) != INVALID_SOCKET)
        ioctlsocket(sw->dns4, FIONBIO, &nonblock);
    if ((sw->dns6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) != INVALID_SOCKET)
        ioctlsocket(sw->dns6, FIONBIO, &nonblock);
    return 0;
}


static HANDLE
nsSignalEvent(int signum)
{
    g_autofree char *name = VIR_PROCESS_WIN32_SIGNAL_EVENT((long long)GetCurrentProcessId(),
                                                           signum);

    return CreateEventA(NULL, FALSE, FALSE, name);
}


/* ---------------------------------------------------------------------
 * Main loop
 */

typedef struct {
    GArray *fds;                /* WSAPOLLFD */
} nsPoll;


static int
nsPollAdd(slirp_os_socket fd, int events, void *opaque)
{
    nsPoll *p = opaque;
    WSAPOLLFD pfd = { .fd = fd };

    if (events & SLIRP_POLL_IN)
        pfd.events |= POLLRDNORM;
    if (events & SLIRP_POLL_PRI)
        pfd.events |= POLLRDBAND;
    if (events & SLIRP_POLL_OUT)
        pfd.events |= POLLWRNORM;
    g_array_append_val(p->fds, pfd);
    return p->fds->len - 1;
}


static int
nsPollGet(int idx, void *opaque)
{
    nsPoll *p = opaque;
    short r = g_array_index(p->fds, WSAPOLLFD, idx).revents;
    int ret = 0;

    if (r & POLLRDNORM)
        ret |= SLIRP_POLL_IN;
    if (r & POLLRDBAND)
        ret |= SLIRP_POLL_PRI;
    if (r & POLLWRNORM)
        ret |= SLIRP_POLL_OUT;
    if (r & POLLERR)
        ret |= SLIRP_POLL_ERR;
    if (r & POLLHUP)
        ret |= SLIRP_POLL_HUP;
    return ret;
}


/*
 * The QoS of the ports of this bridge (their port files), their floors
 * (the floor files the network driver writes) and the bandwidth of the
 * network itself
 */
static void
nsQosLoad(nsSwitch *sw)
{
    g_autofree char *rundir = g_path_get_dirname(sw->socketPath);
    g_autofree char *portdir = g_build_filename(rundir, "ports", NULL);
    g_autofree char *floordir = g_strdup_printf("%s/%s.floor", rundir, sw->def->bridge);
    virNetDevBandwidth *bw = sw->def->bandwidth;
    g_autoptr(GDir) dir = NULL;
    const char *name;
    size_t i;

    g_hash_table_remove_all(sw->qos);
    g_hash_table_remove_all(sw->floors);

    if ((dir = g_dir_open(portdir, 0, NULL))) {
        while ((name = g_dir_read_name(dir))) {
            g_autofree char *path = g_build_filename(portdir, name, NULL);
            g_autoptr(GKeyFile) kf = g_key_file_new();
            g_autofree char *bridge = NULL;
            g_autofree char *mac = NULL;
            virMacAddr m;
            uint64_t *key;

            if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL) ||
                !(bridge = g_key_file_get_string(kf, "port", "bridge", NULL)) ||
                STRNEQ(bridge, sw->def->bridge) ||
                !(mac = g_key_file_get_string(kf, "port", "mac", NULL)) ||
                virMacAddrParse(mac, &m) < 0)
                continue;
            key = g_new(uint64_t, 1);
            *key = nsMacKey(m.addr);
            g_hash_table_insert(sw->qos, key, g_steal_pointer(&kf));
        }
        g_clear_pointer(&dir, g_dir_close);
    }

    if ((dir = g_dir_open(floordir, 0, NULL))) {
        while ((name = g_dir_read_name(dir))) {
            g_autofree char *path = g_build_filename(floordir, name, NULL);
            g_autoptr(GKeyFile) kf = g_key_file_new();
            g_autofree char *mac = NULL;
            virMacAddr m;
            uint64_t *key;

            if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL) ||
                !(mac = g_key_file_get_string(kf, "floor", "mac", NULL)) ||
                virMacAddrParse(mac, &m) < 0)
                continue;
            key = g_new(uint64_t, 1);
            *key = nsMacKey(m.addr);
            g_hash_table_insert(sw->floors, key,
                                GSIZE_TO_POINTER(g_key_file_get_uint64(kf, "floor", "floor", NULL)));
        }
    }

    /* the bridge's bandwidth: inbound is what goes to the guests */
    nsBucketSet(&sw->netInAvg, bw && bw->in ? bw->in->average : 0,
                bw && bw->in ? bw->in->burst : 0,
                nsShapeSize(bw && bw->in ? bw->in->average : 0));
    nsBucketSet(&sw->netInPeak, bw && bw->in ? bw->in->peak : 0, 0,
                nsShapeSize(bw && bw->in ? bw->in->peak : 0));
    nsBucketSet(&sw->netOutAvg, bw && bw->out ? bw->out->average : 0,
                bw && bw->out ? bw->out->burst : 0,
                bw && bw->out ? bw->out->average * 1024.0 : 0);
    nsBucketSet(&sw->netOutPeak, bw && bw->out ? bw->out->peak : 0, 0,
                nsShapeSize(bw && bw->out ? bw->out->peak : 0));

    for (i = 0; i < sw->ports->len; i++)
        nsPortApplyQos(sw, g_ptr_array_index(sw->ports, i));
    nsLog("QoS: %u ports, %u floors, network %s", g_hash_table_size(sw->qos),
          g_hash_table_size(sw->floors), bw ? "limited" : "unlimited");
}


/* The counters of the ports, for domifstat (virNetDevTapInterfaceStats) */
static void
nsStatsWrite(nsSwitch *sw)
{
    g_autoptr(GKeyFile) kf = g_key_file_new();
    g_autofree char *data = NULL;
    size_t i;

    for (i = 0; i < sw->ports->len; i++) {
        nsPort *port = g_ptr_array_index(sw->ports, i);
        char mac[VIR_MAC_STRING_BUFLEN];

        if (!port->hasMac)
            continue;
        virMacAddrFormat(&port->mac, mac);
        g_key_file_set_int64(kf, mac, "rx_bytes", port->rxBytes);
        g_key_file_set_int64(kf, mac, "rx_packets", port->rxPackets);
        g_key_file_set_int64(kf, mac, "rx_drop", port->rxDrop);
        g_key_file_set_int64(kf, mac, "tx_bytes", port->txBytes);
        g_key_file_set_int64(kf, mac, "tx_packets", port->txPackets);
        g_key_file_set_int64(kf, mac, "tx_drop", port->txDrop);
    }
    data = g_key_file_to_data(kf, NULL, NULL);
    if (virFileRewriteStr(sw->statsFile, 0644, data) < 0)
        virResetLastError();
    sw->statsDirty = false;
}


static void
nsRun(nsSwitch *sw)
{
    nsPoll p = { .fds = g_array_new(FALSE, FALSE, sizeof(WSAPOLLFD)) };

    while (!sw->quit) {
        uint32_t timeout = 200;   /* the signal events are polled too */
        size_t nfixed;
        size_t i;
        int rc;
        gint64 now;

        g_array_set_size(p.fds, 0);
        nsPollAdd(sw->listener, SLIRP_POLL_IN, &p);
        if (sw->dns4 != INVALID_SOCKET)
            nsPollAdd(sw->dns4, SLIRP_POLL_IN, &p);
        if (sw->dns6 != INVALID_SOCKET)
            nsPollAdd(sw->dns6, SLIRP_POLL_IN, &p);
        if (sw->wake != INVALID_SOCKET)
            nsPollAdd(sw->wake, SLIRP_POLL_IN, &p);
        for (i = 0; i < sw->ports->len; i++) {
            nsPort *port = g_ptr_array_index(sw->ports, i);

            nsPollAdd(port->sock, SLIRP_POLL_IN | (port->wbuf->len ? SLIRP_POLL_OUT : 0), &p);
        }
        nfixed = p.fds->len;

        now = nsNowMs();
        for (i = 0; i < sw->timers->len; i++) {
            nsTimer *t = g_ptr_array_index(sw->timers, i);

            if (t->expire >= 0)
                timeout = MIN(timeout, MAX(t->expire - now, 0));
        }
        if (g_hash_table_size(sw->queries))
            timeout = MIN(timeout, 100);
        if (sw->qosWaitUs > 0)
            timeout = MIN(timeout, (sw->qosWaitUs + 999) / 1000);
        if (sw->slirp)
            slirp_pollfds_fill_socket(sw->slirp, &timeout, nsPollAdd, &p);

        rc = WSAPoll((WSAPOLLFD *)p.fds->data, p.fds->len, timeout);

        if (rc > 0) {
            size_t idx = 0;

            if (g_array_index(p.fds, WSAPOLLFD, idx++).revents)
                nsAccept(sw);
            if (sw->dns4 != INVALID_SOCKET &&
                g_array_index(p.fds, WSAPOLLFD, idx++).revents)
                nsDnsUpstreamInput(sw, sw->dns4);
            if (sw->dns6 != INVALID_SOCKET &&
                g_array_index(p.fds, WSAPOLLFD, idx++).revents)
                nsDnsUpstreamInput(sw, sw->dns6);
            if (sw->wake != INVALID_SOCKET &&
                g_array_index(p.fds, WSAPOLLFD, idx++).revents)
                nsRoutedDrain(sw);
            for (i = 0; i < sw->ports->len && idx < nfixed; i++, idx++) {
                nsPort *port = g_ptr_array_index(sw->ports, i);
                short r = g_array_index(p.fds, WSAPOLLFD, idx).revents;

                if (r & (POLLRDNORM | POLLHUP | POLLERR))
                    nsPortInput(sw, port);
            }
        }
        if (sw->slirp)
            slirp_pollfds_poll(sw->slirp, rc < 0, nsPollGet, &p);

        now = nsNowMs();
        for (i = 0; i < sw->timers->len; i++) {
            nsTimer *t = g_ptr_array_index(sw->timers, i);

            if (t->expire >= 0 && t->expire <= now) {
                t->expire = -1;
                slirp_handle_timer(sw->slirp, t->id, t->cb_opaque);
            }
        }
        nsDnsTimeouts(sw);
        if (sw->routed && sw->ip6 && sw->wintunSession &&
            nsNowMs() - sw->raTime >= NS_RA_INTERVAL_MS)
            nsRoutedAdvertiseAll(sw);

        /* send what the frames above queued, drop the gone guests */
        sw->qosWaitUs = 0;
        for (i = 0; i < sw->ports->len;) {
            nsPort *port = g_ptr_array_index(sw->ports, i);
            gint64 wait = nsPortDrain(sw, port, g_get_monotonic_time());

            if (wait > 0 && (sw->qosWaitUs == 0 || wait < sw->qosWaitUs))
                sw->qosWaitUs = wait;
            nsPortFlush(port);
            if (port->dead) {
                nsForgetPort(sw, port);
                g_ptr_array_remove_index(sw->ports, i);
                nsLog("guest port %p disconnected (%u ports)", (void *)port, sw->ports->len);
                nsPortFree(port);
                continue;
            }
            i++;
        }

        if (sw->statsDirty && nsNowMs() - sw->statsTime >= 1000) {
            sw->statsTime = nsNowMs();
            nsStatsWrite(sw);
        }

        if (WaitForSingleObject(sw->evTerm, 0) == WAIT_OBJECT_0)
            sw->quit = true;
        if (WaitForSingleObject(sw->evHup, 0) == WAIT_OBJECT_0) {
            nsLog("SIGHUP: reloading %s", sw->configFile);
            if (nsLoadConfig(sw) < 0)
                nsLog("cannot reload: %s", virGetLastErrorMessage());
            nsRefreshHostServers(sw);
            nsQosLoad(sw);
        }
        if (sw->evQos && WaitForSingleObject(sw->evQos, 0) == WAIT_OBJECT_0)
            nsQosLoad(sw);
    }
    g_array_free(p.fds, TRUE);
}


static BOOL WINAPI
nsCtrlHandler(DWORD type G_GNUC_UNUSED)
{
    return TRUE; /* the console of the parent is not ours to follow */
}


static void
nsUsage(const char *argv0)
{
    fprintf(stderr,
            _("Usage: %1$s --config FILE --socket PATH --leases FILE [--log FILE]\n"),
            argv0);
}


/* stderr to @path, appended to by Windows itself (FILE_APPEND_DATA), so
 * that a switch restarted while the old one still writes does not
 * overwrite its lines */
static int
nsOpenLog(const char *path)
{
    g_autofree wchar_t *wpath = g_utf8_to_utf16(path, -1, NULL, NULL, NULL);
    HANDLE h;
    int fd;

    if (!wpath)
        return -1;
    h = CreateFileW(wpath, FILE_APPEND_DATA | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    if ((fd = _open_osfhandle((intptr_t)h, _O_APPEND | _O_TEXT)) < 0) {
        CloseHandle(h);
        return -1;
    }
    if (dup2(fd, STDERR_FILENO) < 0)
        return -1;
    close(fd);
    return 0;
}


int
main(int argc, char **argv)
{
    nsSwitch sw = { .listener = INVALID_SOCKET,
                    .dns4 = INVALID_SOCKET,
                    .dns6 = INVALID_SOCKET };
    WSADATA wsa;
    const char *logFile = NULL;
    int i;

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);
    if (virGettextInitialize() < 0 || virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), argv[0]);
        return EXIT_FAILURE;
    }

    for (i = 1; i + 1 < argc; i += 2) {
        if (STREQ(argv[i], "--config"))
            sw.configFile = argv[i + 1];
        else if (STREQ(argv[i], "--socket"))
            sw.socketPath = argv[i + 1];
        else if (STREQ(argv[i], "--leases"))
            sw.leaseFile = argv[i + 1];
        else if (STREQ(argv[i], "--log"))
            logFile = argv[i + 1];
        else
            break;
    }
    if (i != argc || !sw.configFile || !sw.socketPath || !sw.leaseFile) {
        nsUsage(argv[0]);
        return EXIT_FAILURE;
    }

    if (logFile && nsOpenLog(logFile) < 0) {
        fprintf(stderr, "cannot open log file %s\n", logFile);
        return EXIT_FAILURE;
    }

    SetConsoleCtrlHandler(nsCtrlHandler, TRUE);
    sw.evHup = nsSignalEvent(SIGHUP);
    sw.evTerm = nsSignalEvent(SIGTERM);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        nsLog("WSAStartup failed");
        return EXIT_FAILURE;
    }

    sw.ports = g_ptr_array_new();
    sw.macs = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    sw.timers = g_ptr_array_new();
    sw.leases = g_ptr_array_new_with_free_func((GDestroyNotify)nsLeaseFree);
    sw.queries = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                       (GDestroyNotify)nsDnsQueryFree);
    sw.qos = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free,
                                   (GDestroyNotify)g_key_file_unref);
    sw.floors = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    if (nsLoadConfig(&sw) < 0) {
        nsLog("cannot load %s: %s", sw.configFile, virGetLastErrorMessage());
        return EXIT_FAILURE;
    }
    nsLeasesLoad(&sw);
    nsRefreshHostServers(&sw);

    /* QoS changes are told by virNetDevBridgeSwitchNotify() */
    {
        g_autofree char *rundir = g_path_get_dirname(sw.socketPath);
        g_autofree char *evname = g_strdup_printf("Local\\libvirt-netswitch-%s",
                                                  sw.def->bridge);

        sw.statsFile = g_strdup_printf("%s/%s.stats", rundir, sw.def->bridge);
        sw.evQos = CreateEventA(NULL, FALSE, FALSE, evname);
    }
    nsQosLoad(&sw);

    sw.neigh4 = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    sw.neigh6 = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    sw.wake = INVALID_SOCKET;
    if (nsStartSlirp(&sw) < 0 || nsOpenSockets(&sw) < 0 ||
        (sw.routed && nsStartRouted(&sw) < 0)) {
        nsStopRouted(&sw);
        DeleteFileA(sw.socketPath);
        return EXIT_FAILURE;
    }

    nsLog("network '%s' (%s) listening on %s, pid %lu", sw.def->name,
          sw.def->bridge, sw.socketPath, GetCurrentProcessId());
    nsRun(&sw);

    nsLog("SIGTERM: stopping");
    nsStopRouted(&sw);
    closesocket(sw.listener);
    DeleteFileA(sw.socketPath);
    if (sw.slirp)
        slirp_cleanup(sw.slirp);
    return EXIT_SUCCESS;
}
