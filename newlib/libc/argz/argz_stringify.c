/* Copyright (C) 2002 by  Red Hat, Incorporated. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * is freely granted, provided that this notice is preserved.
 */

#include <sys/types.h>

void
argz_stringify (char *argz, size_t argz_len, int sep)
{
  size_t i;

  /* len includes trailing \0, which we don't want to replace. */
  for (i = 0; i < argz_len - 1; i++)
    {
      if (argz[i] == '\0')
        argz[i] = sep;
    }
}
