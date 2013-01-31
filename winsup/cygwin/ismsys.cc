/*
 * Copyright (C) 2013  Earnie Boyd  <earnie@users.sf.net>
 * This file is a part of MSYS
 */

/*
 * bool IsMsys (const char * File)
 *
 * This function returns true or false based on the import section data of
 * the File containing the name msys-2.0.dll.
 */

#include <stdlib.h>
#include <stdio.h>
#include "winsup.h"

#define FILEERROR(A) fprintf (stderr, (A))

struct SectionData
{
    char SectionName[8];
    int VA_Size;
    int VA_Ptr;
    int RD_Size;
    int RD_Ptr;
};

typedef SectionData SD;

struct ImportData
{
    unsigned attr;
    unsigned ts;
    unsigned chain;
    unsigned name;
    unsigned iat;
};

typedef ImportData ID;

static int
GetFileData(HANDLE fh, int offset, short bytes2get)
{
    TRACE_IN;
    int FileData;
    unsigned bytesread;

    if (SetFilePointer (fh, offset, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER
	&& GetLastError () != NO_ERROR)
      {
	FILEERROR("int GetFileData: SetFilePointer");
	exit (1);
      }

    if (!ReadFile (fh, &FileData, bytes2get, (DWORD *) & bytesread, 0))
      {
	FILEERROR("int GetFileData: ReadFile");
	exit (1);
      }

    return FileData;
}

static char *
GetFileDataStr(HANDLE fh, int offset, unsigned long bytes2get)
{
    TRACE_IN;
    char *FileData = new char [bytes2get+1];
    unsigned bytesread;

    if (SetFilePointer (fh, offset, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER
	&& GetLastError () != NO_ERROR)
      {
	FILEERROR("GetFileData: SetFilePointer");
	exit (1);
      }

    if (!ReadFile (fh, FileData, bytes2get, (DWORD *) & bytesread, 0))
      {
	FILEERROR("GetFileData: ReadFile");
	exit (1);
      }

    FileData[bytes2get] = 0;
      
    return FileData;
}

bool
IsMsys (const char *File)
{
    TRACE_IN;
    debug_printf("%s", File);
    HANDLE fh =
      CreateFile (File
		 , GENERIC_READ
		 , wincap.shared ()    // host dependent flags
		 , NULL
		 , OPEN_EXISTING
		 , FILE_ATTRIBUTE_NORMAL
		 , NULL
		 );
    if (fh == INVALID_HANDLE_VALUE)
      {
	fprintf (stderr, " - Cannot open");
	exit (1);
      }
    bool retval = false;
    int PE_Offset = GetFileData (fh, 0x3c, 4);
    char *PE_Signature = GetFileDataStr (fh, PE_Offset, 4);
    if (memcmp (PE_Signature, "PE\0\0", 4) != 0)
      {
	TRACE_IN;
	delete[] PE_Signature;
	CloseHandle (fh);
	return false;
      }
    delete[] PE_Signature;
    int PE_Option = PE_Offset + 4 + 20;
    int PE_ImportRva = GetFileData (fh, PE_Option + 104, 4);
    int PE_ImportBase = 0;
    int PE_ImportDataSz = 0;
    short PE_SectionCnt = GetFileData (fh, PE_Offset + 4 + 2, 2);
    short PE_SectionOfs = GetFileData (fh, PE_Offset + 4 + 16, 2) + PE_Option;
    char * PE_Sections = GetFileDataStr (fh, PE_SectionOfs, PE_SectionCnt * 40);
    for (int I=0; I < PE_SectionCnt; I++)
      {
	SD *sec = (SD *) (PE_Sections + (I * 40));
	if (PE_ImportRva >= sec->VA_Ptr &&
	    PE_ImportRva < sec->VA_Ptr + sec->VA_Size)
	  {
	    PE_ImportBase = PE_ImportRva - sec->VA_Ptr + sec->RD_Ptr;
	    PE_ImportDataSz = sec->VA_Ptr + sec->VA_Size - PE_ImportRva;
	    break;
	  }
      }
    if (PE_ImportBase && PE_ImportDataSz)
      {
	unsigned char *PE_Import = 
	  (unsigned char *)GetFileDataStr (fh, PE_ImportBase, PE_ImportDataSz);
	ID *impdata = (ID *)PE_Import;
	for (int I=0; impdata[I].name; I++)
	  {
	    if (impdata[I].name < PE_ImportRva ||
	        impdata[I].name - PE_ImportRva >= PE_ImportDataSz)
	      {
		debug_printf("Unrecognized PE format");
		break;
	      }
	    if (!strcmp((char *) PE_Import + impdata[I].name - PE_ImportRva,
		  "msys-2.0.dll"))
	      {
		retval = true;
		break;
	      }
	  }
	delete[] PE_Import;
      }
    delete[] PE_Sections;
    CloseHandle (fh);
    debug_printf("%d", retval);
    return retval;
}
