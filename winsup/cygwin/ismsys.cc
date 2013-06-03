/*
 * Copyright (C) 2002  Earnie Boyd  <earnie@users.sf.net>
 * Copyright (C) 2013  niXman  <i.nixman@gmail.com>
 * Copyright (C) 2013  Alexey Pavlov  <alexey.pawlow@gmail.com>
 * This file is a part of MSYS
 */

/*
 * int is_msys_exec (const char * File)
 *
 * This function returns true or false based on the import section data of
 * the File containing the name msys-2.0.dll.
 */

#include "winsup.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define RETURN_FALSE_IF_EXPRESSION_IS_FALSE(expr, postop) \
	if ( !(expr) ) { \
		postop; \
		return 0; \
	}

#define NOOP_OP \
	do {} while(0)

/***************************************************************************/

typedef struct {
	char foo1[8];
	unsigned vasize;
	unsigned vaptr;
	unsigned foo2;
	unsigned rdptr;
} sections_t;

typedef struct {
	unsigned foo1;
	unsigned foo2;
	unsigned foo3;
	unsigned name;
	unsigned foo4;
} import_t;

/***************************************************************************/

template<typename T>
struct is_int_or_short {
	enum { value = 0 };
};

template<>
struct is_int_or_short<int> {
	enum { value = 1 };
};

template<>
struct is_int_or_short<unsigned int> {
	enum { value = 1 };
};

template<>
struct is_int_or_short<short> {
	enum { value = 1 };
};

/***************************************************************************/

template<typename T>
int read_integral(HANDLE fh, int offset, T *ptr) {
	DWORD rd;
	
	assert(0 != is_int_or_short<T>::value);
	
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 INVALID_SET_FILE_POINTER != SetFilePointer(fh, offset, 0, FILE_BEGIN)
		,NOOP_OP
	);
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 ReadFile(fh, ptr, sizeof(T), &rd, 0)
		,NOOP_OP
	);

	return 1;
}

static int
read_buffer(HANDLE fh, int offset, char *ptr, int size) {
	DWORD rd;
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 INVALID_SET_FILE_POINTER != SetFilePointer(fh, offset, 0, FILE_BEGIN)
		,NOOP_OP
	);
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 ReadFile(fh, ptr, size, &rd, 0)
		,NOOP_OP
	);

	return 1;
}

/***************************************************************************/

int
is_msys_exec(const char *filename) {
	HANDLE fh = CreateFile(
		 filename
		,GENERIC_READ
		,FILE_SHARE_READ
		,NULL
		,OPEN_EXISTING
		,FILE_ATTRIBUTE_NORMAL
		,NULL
	);
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 INVALID_HANDLE_VALUE != fh
		,debug_printf("file \"%s\" is not exists\n", filename);
	);
	
	int i, retval = 0;
	int pe_offset = 0;
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_integral(fh, 0x3c, &pe_offset)
		,CloseHandle(fh)
	);
	debug_printf("pe_offset: 0x%x\n", pe_offset);
	
	char pe_sig[4] = {0};
	char msys2_sig[] = "msys-2.0.dll";

	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_buffer(fh, pe_offset, pe_sig, sizeof(pe_sig))
		,CloseHandle(fh)
	);
	
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 0 == memcmp(pe_sig, "PE\0\0", sizeof(pe_sig))
		,CloseHandle(fh)
	);

	int optional = pe_offset+4+20;
	debug_printf("optional: 0x%x\n", optional);
	
	short magic = 0;
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_integral(fh, optional, &magic)
		,CloseHandle(fh)
	);
	debug_printf("magic: 0x%x\n", magic);
	
	unsigned int import_rva = 0;
	if ( IMAGE_NT_OPTIONAL_HDR32_MAGIC == magic ) {
		RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
			 read_integral(fh, optional+104, &import_rva)
			,CloseHandle(fh)
		);
	} else if ( IMAGE_NT_OPTIONAL_HDR64_MAGIC == magic ) {
		RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
			 read_integral(fh, optional+120, &import_rva)
			,CloseHandle(fh)
		);
	} else {
		debug_printf("is_msys(): unknown optional header: 0x%x\n", magic);
	}
	
	int import_base = 0;
	unsigned int import_data_size = 0;
	
	short section_count = 0;
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_integral(fh, pe_offset+4+2, &section_count)
		,CloseHandle(fh)
	);
	debug_printf("section_count: 0x%x\n", section_count);
	
	short section_offset = 0;
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_integral(fh, pe_offset+4+16, &section_offset)
		,CloseHandle(fh)
	)
	section_offset += optional;
	debug_printf("section_offset: 0x%x\n", section_offset);
	
	char *sections = (char*)malloc((section_count*40)+1);
	RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
		 read_buffer(fh, section_offset, sections, section_count*40)
		,free(sections);CloseHandle(fh)
	);
	
	for ( i = 0; i < section_count; ++i ) {
		sections_t *sec = (sections_t *)(sections + (i*40));
		if ( import_rva >= sec->vaptr && import_rva < sec->vaptr + sec->vasize ) {
			import_base = import_rva - sec->vaptr + sec->rdptr;
			import_data_size = sec->vaptr + sec->vasize - import_rva;
			break;
		}
	}
	if ( import_base && import_data_size ) {
		unsigned char *imports = (unsigned char*)malloc(import_data_size+1);
		RETURN_FALSE_IF_EXPRESSION_IS_FALSE(
			 read_buffer(fh, import_base, (char*)imports, import_data_size)
			,free(sections);free(imports);CloseHandle(fh)
		);
		imports[import_data_size] = 0;
		import_t *impdata = (import_t *)imports;
		for ( i = 0; impdata[i].name; ++i ) {
			if ( impdata[i].name < import_rva || impdata[i].name - import_rva >= import_data_size ) {
				debug_printf("Unrecognized PE format\n");
				break;
	      }
			const char *name = (const char*)imports + impdata[i].name - import_rva;
			debug_printf("name: %s\n", name);
			if ( 0 == strncmp(name, msys2_sig, sizeof(msys2_sig)) ) {
				retval = 1;
				break;
	      }
		}
		free(imports);
	}

	free(sections);
	CloseHandle(fh);
	
	debug_printf("progname:%s, is msys:%s\n", filename, "false\0true"+6*retval);
	return retval;
}
