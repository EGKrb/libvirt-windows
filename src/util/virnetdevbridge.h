/*
 * Copyright (C) 2007-2012, 2014 Red Hat, Inc.
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
#include "virmacaddr.h"
#include "virnetdevvlan.h"

#ifdef WIN32
/* Windows has no bridge device: a libvirt network's bridge is the switch
 * of libvirt_netswitch, reached by its UNIX socket */
char *virNetDevBridgeSwitchSocketPath(const char *brname)
    ATTRIBUTE_NONNULL(1);

/*
 * A guest interface on a switch has the name a TAP device would have
 * (vnetN): its port file (run/libvirt/network/ports/NAME) names its bridge
 * and MAC address, and holds its QoS, which the switch applies.
 */
char *virNetDevBridgeSwitchPortPath(const char *ifname)
    ATTRIBUTE_NONNULL(1);
/* The socket of the interface on its switch (ports/NAME.sock), made by the
 * switch for its port file: a guest connected there is that interface's */
char *virNetDevBridgeSwitchPortSocketPath(const char *ifname)
    ATTRIBUTE_NONNULL(1);
int virNetDevBridgeSwitchPortAdd(const char *brname,
                                 const char *ifname,
                                 const virMacAddr *mac)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virNetDevBridgeSwitchPortRemove(const char *ifname)
    ATTRIBUTE_NONNULL(1);
int virNetDevBridgeSwitchPortGet(const char *ifname,
                                 char **brname,
                                 virMacAddr *mac)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
/* Tell the switch of @brname that its ports or floors changed */
void virNetDevBridgeSwitchNotify(const char *brname)
    ATTRIBUTE_NONNULL(1);
#endif

int virNetDevBridgeCreate(const char *brname,
                          const virMacAddr *mac)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeDelete(const char *brname)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname,
                           const virNetDevVlan *virtVlan)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeSetSTP(const char *brname,
                          bool enable)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBridgeSetVlanFiltering(const char *brname,
                                    bool enable)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeGetVlanFiltering(const char *brname,
                                    bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBridgePortGetLearning(const char *brname,
                                   const char *ifname,
                                   bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgePortSetLearning(const char *brname,
                                   const char *ifname,
                                   bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgePortGetUnicastFlood(const char *brname,
                                       const char *ifname,
                                       bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgePortSetUnicastFlood(const char *brname,
                                       const char *ifname,
                                       bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgePortGetIsolated(const char *brname,
                                   const char *ifname,
                                   bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgePortSetIsolated(const char *brname,
                                   const char *ifname,
                                   bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

typedef enum {
    VIR_NETDEVBRIDGE_FDB_FLAG_ROUTER    = (1 << 0),
    VIR_NETDEVBRIDGE_FDB_FLAG_SELF      = (1 << 1),
    VIR_NETDEVBRIDGE_FDB_FLAG_MASTER    = (1 << 2),

    VIR_NETDEVBRIDGE_FDB_FLAG_PERMANENT = (1 << 3),
    VIR_NETDEVBRIDGE_FDB_FLAG_TEMP      = (1 << 4),
} virNetDevBridgeFDBFlags;

int virNetDevBridgeFDBAdd(const virMacAddr *mac, const char *ifname,
                          unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBridgeFDBDel(const virMacAddr *mac, const char *ifname,
                          unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
