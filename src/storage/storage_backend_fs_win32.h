/*
 * storage_backend_fs_win32.h: mounts of the fs and netfs pools on Windows
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "storage_conf.h"
#include "virstorageobj.h"

int virStorageBackendFsWin32IsMounted(virStoragePoolObj *pool);
int virStorageBackendFsWin32Mount(virStoragePoolObj *pool);
int virStorageBackendFsWin32Unmount(virStoragePoolObj *pool);
int virStorageBackendFsWin32MakeFileSystem(virStoragePoolObj *pool,
                                           unsigned int flags);
int virStorageBackendFsWin32FindShares(const char *host,
                                       virStoragePoolSourceList *list);
