#include "winsup.h"
#include "cygerrno.h"
#include "security.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include <stdlib.h>
#include <imagehlp.h>
#include <alloca.h>

#define rva(coerce, base, addr) (coerce) ((char *) (base) + (addr))
#define rvacyg(coerce, addr) rva (coerce, cygwin_hmodule, addr)

struct function_hook
{
  const char *name;	// Function name, e.g. "DirectDrawCreateEx".
  const void *hookfn;	// Address of your function.
  void *origfn;		// Stored by HookAPICalls, the address of the original function.
};

/* Given an HMODULE, returns a pointer to the PE header */
static PIMAGE_NT_HEADERS
PEHeaderFromHModule (HMODULE hModule)
{
  PIMAGE_NT_HEADERS pNTHeader;

  if (PIMAGE_DOS_HEADER(hModule) ->e_magic != IMAGE_DOS_SIGNATURE)
    pNTHeader = NULL;
  else
    {
      pNTHeader = PIMAGE_NT_HEADERS (PBYTE (hModule)
				     + PIMAGE_DOS_HEADER (hModule) ->e_lfanew);
      if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	pNTHeader = NULL;
    }

  return pNTHeader;
}

long
rvadelta (PIMAGE_NT_HEADERS pnt, long import_rva)
{
  PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER) (pnt + 1);
  for (int i = 0; i < pnt->FileHeader.NumberOfSections; i++)
    if (section[i].VirtualAddress <= import_rva
	&& (section[i].VirtualAddress + section[i].Misc.VirtualSize) >= import_rva)
    // if (strncasematch ((char *) section[i].Name, ".idata", IMAGE_SIZEOF_SHORT_NAME))
      return section[i].VirtualAddress - section[i].PointerToRawData;
  return -1;
}

void *
putmem (PIMAGE_THUNK_DATA pi, const void *hookfn)
{

  DWORD flOldProtect, flNewProtect, flDontCare;
  MEMORY_BASIC_INFORMATION mbi;

  /* Get the current protection attributes */
  VirtualQuery (pi, &mbi, sizeof (mbi));

  /* Remove ReadOnly and ExecuteRead attributes, add on ReadWrite flag */
  flNewProtect = mbi.Protect;
  flNewProtect &= ~(PAGE_READONLY | PAGE_EXECUTE_READ);
  flNewProtect |= PAGE_READWRITE;

  if (!VirtualProtect (pi, sizeof (PVOID), flNewProtect, &flOldProtect) )
    return NULL;

  void *origfn = (void *) pi->u1.Function;
  pi->u1.Function = (DWORD) hookfn;

  VirtualProtect (pi, sizeof (PVOID), flOldProtect, &flDontCare);
  return origfn;
}

/* Builds stubs for and redirects the IAT for one DLL (pImportDesc) */

static bool
RedirectIAT (function_hook& fh, PIMAGE_IMPORT_DESCRIPTOR pImportDesc,
	     HMODULE hm)
{
  // If no import names table, we can't redirect this, so bail
  if (pImportDesc->OriginalFirstThunk == 0)
      return false;

  /* import address table */
  PIMAGE_THUNK_DATA pt = rva (PIMAGE_THUNK_DATA, hm, pImportDesc->FirstThunk);
  /* import names table */
  PIMAGE_THUNK_DATA pn = rva (PIMAGE_THUNK_DATA, hm, pImportDesc->OriginalFirstThunk);

  /* Scan through the IAT, completing the stubs and redirecting the IAT
     entries to point to the stubs. */
  for (PIMAGE_THUNK_DATA pi = pt; pn->u1.Ordinal; pi++, pn++)
    {
      if (IMAGE_SNAP_BY_ORDINAL (pn->u1.Ordinal) )
	continue;

      /* import by name */
      PIMAGE_IMPORT_BY_NAME pimp = rva (PIMAGE_IMPORT_BY_NAME, hm, pn->u1.AddressOfData);

      if (strcmp (fh.name, (char *) pimp->Name) == 0)
	{
	  fh.origfn = putmem (pi, fh.hookfn);
	  if (!fh.origfn)
	    return false;
	  hook_chain *hc;
	  for (hc = &cygheap->hooks; hc->next; hc = hc->next)
	    continue;
	  hc->next = (hook_chain *) cmalloc (HEAP_1_HOOK, sizeof (hook_chain));
	  hc->next->loc = (void **) pi;
	  hc->next->func = fh.hookfn;
	  hc->next->next = NULL;
	  break;
      }
  }

  return true;
}

void
get_export (function_hook& fh)
{
  extern HMODULE cygwin_hmodule;
  PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER) cygwin_hmodule;
  if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
    return;
  PIMAGE_NT_HEADERS pnt = (PIMAGE_NT_HEADERS) ((char *) pdh + pdh->e_lfanew);
  if (pnt->Signature != IMAGE_NT_SIGNATURE || pnt->FileHeader.SizeOfOptionalHeader == 0)
    return;
  PIMAGE_EXPORT_DIRECTORY pexp =
    rvacyg (PIMAGE_EXPORT_DIRECTORY,
	 pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  if (!pexp)
    return;

  PDWORD pfuncs = rvacyg (PDWORD, pexp->AddressOfFunctions);
  PDWORD pnames = rvacyg (PDWORD, pexp->AddressOfNames);
  for (DWORD i = 0; i < pexp->NumberOfNames; i++)
    if (strcmp (fh.name, rvacyg (char *, pnames[i])) == 0)
      {
	fh.origfn = rvacyg (void *, pfuncs[i]);
	break;
      }
}

static const char *
makename (const char *name, char *&buf, int& i, int inc)
{
  i += inc;
  static const char *testers[] = {"NOTUSED", "64", "32"};
  if (i < 0 || i >= (int) (sizeof (testers) / sizeof (testers[0])))
    return NULL;
  if (i)
    {
      __small_sprintf (buf, "_%s%s", name, testers[i]);
      name = buf;
    }
  return name;
}

// Top level routine to find the EXE's imports, and redirect them
void *
hook_or_detect_cygwin (const char *name, const void *fn)
{
  HMODULE hm = fn ? GetModuleHandle (NULL) : (HMODULE) name;
  PIMAGE_NT_HEADERS pExeNTHdr = PEHeaderFromHModule (hm);

  if (!pExeNTHdr)
    return false;

  DWORD importRVA = pExeNTHdr->OptionalHeader.DataDirectory
		      [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if (!importRVA)
    return false;

  long delta = fn ? 0 : rvadelta (pExeNTHdr, importRVA);
  if (delta < 0)
    return false;

  // Convert imports RVA to a usable pointer
  PIMAGE_IMPORT_DESCRIPTOR pdfirst = rva (PIMAGE_IMPORT_DESCRIPTOR, hm, importRVA - delta);

  function_hook fh;
  fh.origfn = NULL;
  fh.hookfn = fn;
  char *buf = fn ? NULL : (char *) alloca (strlen (name) + strlen ("64") + sizeof ("_"));
  int i;
  // Iterate through each import descriptor, and redirect if appropriate
  for (PIMAGE_IMPORT_DESCRIPTOR pd = pdfirst; pd->FirstThunk; pd++)
    {
      if (!strcasematch (rva (PSTR, hm, pd->Name - delta), "cygwin1.dll"))
	continue;
      if (!fn)
	return (void *) "found it";	// just checking if executable used cygwin1.dll
      i = -1;
      while (!fh.origfn && (fh.name = makename (name, buf, i, 1)))
	RedirectIAT (fh, pd, hm);
      if (fh.origfn)
	break;
    }

  while (!fh.origfn && (fh.name = makename (name, buf, i, -1)))
    get_export (fh);

  return fh.origfn;
}

void
ld_preload ()
{
  char *p = getenv ("LD_PRELOAD");
  if (!p)
    return;
  char *s = (char *) alloca (strlen (p) + 1);
  strcpy (s, p);
  char *here = NULL;
  for (p = strtok_r (s, ":\t\n", &here); p; p = strtok_r (NULL, ":\t\n", &here))
    {
      path_conv lib (p);
      if (!LoadLibrary (lib))
	{
	  __seterrno ();
	  api_fatal ("error while loading shared libraries: %s: "
		     "cannot open shared object file: %s", p,
		     strerror (get_errno ()));
	}
    }
}

void
fixup_hooks_after_fork ()
{
  for (hook_chain *hc = &cygheap->hooks; (hc = hc->next); )
    putmem ((PIMAGE_THUNK_DATA) hc->loc, hc->func);
}
