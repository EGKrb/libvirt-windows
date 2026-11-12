/*
 * nwfilter_netswitch_driver.h: network filters applied by the switch of a
 * libvirt network on Windows (libvirt_netswitch)
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "nwfilter_tech_driver.h"

extern virNWFilterTechDriver netswitch_driver;

#define NETSWITCH_DRIVER_ID "netswitch"
