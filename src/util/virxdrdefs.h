/*
 * virxdrdefs.h
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

/* The portablexdr implementation lacks IXDR_PUT_U_INT32 and IXDR_GET_U_INT32
 */
#ifndef IXDR_PUT_U_INT32
# define IXDR_PUT_U_INT32 IXDR_PUT_U_LONG
#endif
#ifndef IXDR_GET_U_INT32
# define IXDR_GET_U_INT32 IXDR_GET_U_LONG
#endif

#ifdef WIN32
/* portablexdr's xdr_uint64_t sign-extends the low word it decodes
 * (0x80000000 reads back as 0xffffffff80000000): libvirt's own, see
 * virxdrdefs.c */
# include <stdint.h>
bool_t virXDRUint64(XDR *xdrs, uint64_t *objp);
# undef xdr_uint64_t
# define xdr_uint64_t virXDRUint64
#endif
