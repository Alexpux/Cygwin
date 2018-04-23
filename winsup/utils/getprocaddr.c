#include <stdio.h>
#include <windows.h>

/**
 * To determine the address of kernel32!CtrlRoutine, we need to use
 * dbghelp.dll. But we want to avoid linking statically to that library because
 * the normal operation of cygwin-console-helper.exe (i.e. to allocate a hidden
 * Console) does not need it.
 *
 * Therefore, we declare the SYMBOL_INFOW structure here, load the dbghelp
 * library via LoadLibraryExA() and obtain the SymInitialize(), SymFromAddrW()
 * and SymCleanup() functions via GetProcAddr().
 */

#include <dbghelp.h>

/* Avoid fprintf(), as it would try to reference '__getreent' */
static void
output (BOOL error, const char *fmt, ...)
{
  va_list ap;
  char buffer[1024];

  va_start (ap, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, ap);
  buffer[sizeof(buffer) - 1] = '\0';
  va_end (ap);
  WriteFile (GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE),
	     buffer, strlen (buffer), NULL, NULL);
}

static WINAPI BOOL
ctrl_handler(DWORD ctrl_type)
{
  unsigned short count;
  void *address;
  HANDLE process;
  PSYMBOL_INFOW info;
  DWORD64 displacement;

  count = CaptureStackBackTrace (1l /* skip this function */,
			         1l /* return only one trace item */,
				 &address, NULL);
  if (count != 1)
    {
      output (1, "Could not capture backtrace\n");
      return FALSE;
    }

  process = GetCurrentProcess ();
  if (!SymInitialize (process, NULL, TRUE))
    {
      output (1, "Could not initialize symbols\n");
      return FALSE;
    }

  info = (PSYMBOL_INFOW)
    malloc (sizeof(*info) + MAX_SYM_NAME * sizeof(wchar_t));
  if (!info)
    {
      output (1, "Could not allocate symbol info structure\n");
      return FALSE;
    }
  info->SizeOfStruct = sizeof(*info);
  info->MaxNameLen = MAX_SYM_NAME;

  if (!SymFromAddrW (process, (DWORD64)(intptr_t)address, &displacement, info))
    {
      output (1, "Could not get symbol info\n");
      SymCleanup(process);
      return FALSE;
    }
  output (0, "%p\n", (void *)(intptr_t)info->Address);
  CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
  SymCleanup(process);

  exit(0);
}

int
main (int argc, char **argv)
{
  char *end;

  if (argc < 2)
    {
      output (1, "Need a function name\n");
      return 1;
    }

  if (strcmp(argv[1], "CtrlRoutine"))
    {
      if (argc > 2)
        {
          output (1, "Unhandled option: %s\n", argv[2]);
          return 1;
        }

      HINSTANCE kernel32 = GetModuleHandle ("kernel32");
      if (!kernel32)
        return 1;
      void *address = (void *) GetProcAddress (kernel32, argv[1]);
      if (!address)
        return 1;
      output (0, "%p\n", address);
      return 0;
    }

  /* Special-case kernel32!CtrlRoutine */
  if (argc == 3 && !strcmp ("--alloc-console", argv[2]))
    {
      if (!FreeConsole () && GetLastError () != ERROR_INVALID_PARAMETER)
        {
	  output (1, "Could not detach from current Console: %d\n",
		  (int)GetLastError());
	  return 1;
	}
      if (!AllocConsole ())
        {
	  output (1, "Could not allocate a new Console\n");
	  return 1;
	}
    }
  else if (argc > 2)
    {
      output (1, "Unhandled option: %s\n", argv[2]);
      return 1;
    }

  if (!SetConsoleCtrlHandler (ctrl_handler, TRUE))
    {
      output (1, "Could not register Ctrl handler\n");
      return 1;
    }

  if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0))
    {
      output (1, "Could not simulate Ctrl+Break\n");
      return 1;
    }

  /* Give the event 1sec time to print out the address */
  Sleep(1000);
  return 1;
}

