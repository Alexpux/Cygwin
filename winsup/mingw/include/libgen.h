#ifndef _LIBGEN_H_
/* 
 * libgen.h
 *
 * $Id$
 *
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is a part of the mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within the package.
 *
 * Functions for splitting pathnames into dirname and basename components.
 *
 */
#define _LIBGEN_H_

/* All the headers include this file. */
#include <_mingw.h>

#ifdef __cplusplus
extern "C" {
#endif

extern __cdecl char *basename (char *);
extern __cdecl char *dirname  (char *);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBGEN_H_: end of file */

