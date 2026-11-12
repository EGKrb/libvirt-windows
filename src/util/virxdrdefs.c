/*
 * virxdrdefs.c: fixes of the XDR implementation
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

#ifdef WIN32
# include <rpc/types.h>
# include <rpc/xdr.h>

# include "virxdrdefs.h"

/* The same bits on the wire as a signed 64-bit integer, which portablexdr
 * reads back right */
bool_t
virXDRUint64(XDR *xdrs, uint64_t *objp)
{
    return xdr_int64_t(xdrs, (int64_t *)objp);
}
#endif
