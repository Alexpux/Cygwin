/* msys.cc

   Copyright (C) 2001 EarnieSystems

   This file is a copyrighted work licensed under the terms of the
   EarnieSystems license.  Please consult the EarnieSystems.license
   file for details of your rights and restrictions.

*/
   
#include "winsup.h"
#include "cygerrno.h"
#include "msys.h"
#include <sys/errno.h>

extern "C"
void
AbsDllPath (const char * DllName, char * AbsDllPath, int AbsDllPathLen)
{
    TRACE_IN;
    __AbsDllPath(DllName, AbsDllPath, AbsDllPathLen);
}

void
__AbsDllPath(const char * DllName, char * AbsDllPath, int AbsDllPathLen)
{
    TRACE_IN;
    HMODULE mn;
    mn = GetModuleHandle (DllName);
    if (GetModuleFileName (mn, AbsDllPath, AbsDllPathLen) == 0)
      {
	debug_printf("%s", AbsDllPath);
	set_errno(EINVAL);
      }
    else
      {
	debug_printf("%s", AbsDllPath);
	char *ptr = strrchr(AbsDllPath, '\\');
	if (ptr)
	  *ptr = '\0';
      }
}

extern "C"
void
AbsExeModPath (char * AbsExeModPath, int AbsExeModPathLen)
{
    __AbsExeModPath (AbsExeModPath, AbsExeModPathLen);
}

void
__AbsExeModPath (char * AbsExeModPath, int AbsExeModPathLen)
{
    if (GetModuleFileName (NULL, AbsExeModPath, AbsExeModPathLen) == 0)
      {
	set_errno(EACCES);
      }
    else
      {
	char *ptr = strrchr(AbsExeModPath, '\\');
	if (ptr)
	  *ptr = '\0';
      }
}
