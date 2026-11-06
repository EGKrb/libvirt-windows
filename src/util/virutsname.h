/*
 * virutsname.h: uname() on every platform
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

#ifdef WIN32
/*
 * Windows has no uname(): sysname is "Windows", release the version of
 * the system (10.0.<build>), machine the architecture as Linux names it.
 */
# define VIR_UTSNAME_LEN 65

struct utsname {
    char sysname[VIR_UTSNAME_LEN];
    char nodename[VIR_UTSNAME_LEN];
    char release[VIR_UTSNAME_LEN];
    char version[VIR_UTSNAME_LEN];
    char machine[VIR_UTSNAME_LEN];
};

int virWin32Uname(struct utsname *buf);
# define uname(buf) virWin32Uname(buf)
#else
# include <sys/utsname.h>
#endif
