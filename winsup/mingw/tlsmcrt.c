/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 *
 * Written by Kai Tietz  <kai.tietz@onevision.com>
 */

/* We support TLS cleanup code in any case. If shared version of libgcc is used _CRT_MT has value 1,
 otherwise
   we do tls cleanup in runtime and _CRT_MT has value 2.  */
int _CRT_MT = 2;

