/*
 * dllcrt1.c
 *
 * Initialization code for DLLs.
 *
 * This file is part of the Mingw32 package.
 *
 * Contributors:
 *  Created by Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
 *  DLL support adapted from Gunther Ebert <gunther.ebert@ixos-leipzig.de>
 *  Maintained by Mumit Khan <khan@xraylith.wisc.EDU>
 *
 *  THIS SOFTWARE IS NOT COPYRIGHTED
 *
 *  This source code is offered for use in the public domain. You may
 *  use, modify or distribute it freely.
 *
 *  This code is distributed in the hope that it will be useful but
 *  WITHOUT ANY WARRANTY. ALL WARRENTIES, EXPRESS OR IMPLIED ARE HEREBY
 *  DISCLAMED. This includes but is not limited to warrenties of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Revision$
 * $Author$
 * $Date$
 * 
 */

#include <stdio.h>
#include <io.h>
#include <process.h>
#include <windows.h>

/* Unlike normal crt1, I don't initialize the FPU, because the process
 * should have done that already. I also don't set the file handle modes,
 * because that would be rude. */

#ifdef	__GNUC__
extern void __main ();
extern void __do_global_dtors ();
#endif

extern BOOL WINAPI DllMain (HANDLE, DWORD, LPVOID);

BOOL WINAPI
DllMainCRTStartup (HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{
  BOOL bRet;

  if (dwReason == DLL_PROCESS_ATTACH)
    {
#ifdef	__GNUC__
      /* From libgcc.a, calls global class constructors. */
      __main ();
#endif
    }

  /*
   * Call the user-supplied DllMain subroutine
   * NOTE: DllMain is optional, so libmingw32.a includes a stub
   *       which will be used if the user does not supply one.
   */
  bRet = DllMain (hDll, dwReason, lpReserved);

#ifdef	__GNUC__
  if (dwReason == DLL_PROCESS_DETACH)
    {
      /* From libgcc.a, calls global class destructors. */
      __do_global_dtors ();
    }
#endif

  return bRet;
}

/*
 * For the moment a dummy atexit. Atexit causes problems in DLLs, especially
 * if they are dynamically loaded. For now atexit inside a DLL does nothing.
 * NOTE: We need this even if the DLL author never calls atexit because
 *       the global constructor function __do_global_ctors called from __main
 *       will attempt to register __do_global_dtors using atexit.
 *       Thanks to Andrey A. Smirnov for pointing this one out.
 */
int
atexit (void (*pfn) ())
{
  return 0;
}

