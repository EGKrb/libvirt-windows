/*
 * virgettext.c: gettext helper routines
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

#include <config.h>

#include <fcntl.h>
#include <locale.h>
#ifdef WITH_XLOCALE_H
# include <xlocale.h>
#endif

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

#include "configmake.h"
#include "internal.h"
#include "virgettext.h"


#ifdef WIN32
static UINT virGettextConsoleCP;

static void
virGettextRestoreConsole(void)
{
    SetConsoleOutputCP(virGettextConsoleCP);
}


/*
 * Messages are UTF-8 (see virGettextInitialize): have the console display
 * them as such while we run.  Pipes and files simply get UTF-8.
 */
static void
virGettextWin32Console(void)
{
    DWORD mode;

    if (!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) &&
        !GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode))
        return;

    virGettextConsoleCP = GetConsoleOutputCP();
    if (virGettextConsoleCP != CP_UTF8 && SetConsoleOutputCP(CP_UTF8))
        atexit(virGettextRestoreConsole);
}
#endif


/**
 * virGettextInitialize:
 *
 * Initialize standard gettext setup
 * Returns -1 on fatal error
 */
int
virGettextInitialize(void)
{
#if WITH_LIBINTL_H
    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }
# ifdef WIN32
    /* POSIX has no text mode: files must not have their line ends converted,
     * nor end at a ^Z byte (as images and disks can hold).  Done here, from
     * main(), as the C runtime start-up of the program resets the mode. */
    _set_fmode(_O_BINARY);

    /* strings are UTF-8 (see below): so are multibyte conversions */
    if (!setlocale(LC_CTYPE, ".UTF-8"))
        perror("setlocale");
# endif

    if (!bindtextdomain(PACKAGE, VIR_INSTALL_PATH(LOCALEDIR))) {
        perror("bindtextdomain");
        return -1;
    }

    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return -1;
    }

# ifdef WIN32
    /* not the ANSI code page of the locale, which cannot represent all text */
    if (!bind_textdomain_codeset(PACKAGE, "UTF-8")) {
        perror("bind_textdomain_codeset");
        return -1;
    }
    virGettextWin32Console();
# endif
#endif /* WITH_LIBINTL_H */
    return 0;
}
