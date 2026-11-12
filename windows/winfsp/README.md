# WinFsp FUSE headers

The FUSE headers of [WinFsp](https://winfsp.dev) 2.1 (`inc/fuse` of
<https://github.com/winfsp/winfsp> at tag `v2.1`), which `libvirt_nfsmount`
(`src/storage/storage_nfsmount_win32.c`) is built with. WinFsp is under the
GPLv3 with a special exception for FLOSS software ([License.txt](License.txt)).

The helper loads `winfsp-x64.dll` when it runs: WinFsp is not needed to build
libvirt, only to mount NFS pools on a Windows without the Client for NFS.
