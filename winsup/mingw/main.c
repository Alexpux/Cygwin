/*
 * main.c
 *
 * Extra startup code for applications which do not have a main function
 * of their own (but do have a WinMain). Generally these are GUI
 * applications, but they don't *have* to be.
 *
 * This file is part of the Mingw32 package.
 *
 * Contributors:
 *  Created by Colin Peters <colin@bird.fu.is.saga-u.ac.jp>
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

#include <stdlib.h>
#include <process.h>
#include <windows.h>

#define ISSPACE(a)	(a == ' ' || a == '\t')

extern int PASCAL WinMain (HINSTANCE hInst, HINSTANCE hPrevInst, 
                           LPSTR szCmdLine, int nShow);

int
main (int argc, char *argv[], char *environ[])
{
  char *szCmd;
  STARTUPINFO startinfo;
  int nRet;

  /* Get the command line passed to the process. */
  szCmd = GetCommandLineA ();
  GetStartupInfoA (&startinfo);

  /* Strip off the name of the application and any leading
   * whitespace. */
  if (szCmd)
    {
      while (ISSPACE (*szCmd))
	{
	  szCmd++;
	}

      /* On my system I always get the app name enclosed
       * in quotes... */
      if (*szCmd == '\"')
	{
	  do
	    {
	      szCmd++;
	    }
	  while (*szCmd != '\"' && *szCmd != '\0');

	  if (*szCmd == '\"')
	    {
	      szCmd++;
	    }
	}
      else
	{
	  /* If no quotes then assume first token is program
	   * name. */
	  while (!ISSPACE (*szCmd) && *szCmd != '\0')
	    {
	      szCmd++;
	    }
	}

      while (ISSPACE (*szCmd))
	{
	  szCmd++;
	}
    }

  nRet = WinMain (GetModuleHandle (NULL), NULL, szCmd,
		  (startinfo.dwFlags & STARTF_USESHOWWINDOW) ?
		  startinfo.wShowWindow : SW_SHOWDEFAULT);

  return nRet;
}

