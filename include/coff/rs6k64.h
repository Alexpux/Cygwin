/* IBM RS/6000 "XCOFF64" file definitions for BFD.

   Copyright 2000 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#define DO_NOT_DEFINE_AOUTHDR
#define DO_NOT_DEFINE_SCNHDR
#define DO_NOT_DEFINE_LINENO
#define DO_NOT_DEFINE_AUXENT
#include "coff/external.h"

        /* IBM RS/6000 */
#define U803XTOCMAGIC 0757	/* readonly text segments and TOC, XCOFF64 */

#define BADMAG(x) ((x).f_magic != U803XTOCMAGIC)

/********************** AOUT "OPTIONAL HEADER" **********************/

typedef struct 
{
  unsigned char	magic[2];	/* type of file			*/
  unsigned char	vstamp[2];	/* version stamp		*/
  unsigned char	o_debugger[4];	/* reserved 			*/
  unsigned char	text_start[8];	/* base of text used for this file */
  unsigned char	data_start[8];	/* base of data used for this file */
  unsigned char	o_toc[8];	/* address of TOC */
  unsigned char	o_snentry[2];	/* section number of entry point */
  unsigned char	o_sntext[2];	/* section number of .text section */
  unsigned char	o_sndata[2];	/* section number of .data section */
  unsigned char	o_sntoc[2];	/* section number of TOC */
  unsigned char	o_snloader[2];	/* section number of .loader section */
  unsigned char	o_snbss[2];	/* section number of .bss section */
  unsigned char	o_algntext[2];	/* .text alignment */
  unsigned char	o_algndata[2];	/* .data alignment */
  unsigned char	o_modtype[2];	/* module type (??) */
  unsigned char o_cputype[2];	/* cpu type */
  unsigned char	o_resv2[4];	/* reserved 			*/
  unsigned char	tsize[8];	/* text size bytes, padded to FW bdry */
  unsigned char	dsize[8];	/* initialized data "  "	*/
  unsigned char	bsize[8];	/* uninitialized data "   "	*/
  unsigned char	entry[8];	/* entry pt.			*/
  unsigned char	o_maxstack[8];	/* max stack size (??) 		*/
  unsigned char o_maxdata[8];	/* max data size (??) 		*/
  unsigned char	o_resv3[16];	/* reserved 			*/
}
AOUTHDR;

#define AOUTSZ 120
#define SMALL_AOUTSZ (0)
#define AOUTHDRSZ 72

#define	RS6K_AOUTHDR_OMAGIC	0x0107	/* old: text & data writeable */
#define	RS6K_AOUTHDR_NMAGIC	0x0108	/* new: text r/o, data r/w */
#define	RS6K_AOUTHDR_ZMAGIC	0x010B	/* paged: text r/o, both page-aligned */


/********************** SECTION HEADER **********************/
struct external_scnhdr
{
	char	s_name[8];	/* section name			*/
	char	s_paddr[8];	/* physical address, aliased s_nlib */
	char	s_vaddr[8];	/* virtual address		*/
	char	s_size[8];	/* section size			*/
	char	s_scnptr[8];	/* file ptr to raw data for section */
	char	s_relptr[8];	/* file ptr to relocation	*/
	char	s_lnnoptr[8];	/* file ptr to line numbers	*/
	char	s_nreloc[4];	/* number of relocation entries	*/
	char	s_nlnno[4];	/* number of line number entries*/
	char	s_flags[4];	/* flags			*/
	char    s_pad[4];	/* padding */  
};

/*
 * names of "special" sections
 */
#define _TEXT	".text"
#define _DATA	".data"
#define _BSS	".bss"
#define _PAD	".pad"
#define _LOADER	".loader"

#define	SCNHDR	struct external_scnhdr

#define	SCNHSZ	72

/* XCOFF uses a special .loader section with type STYP_LOADER.  */
#define STYP_LOADER 0x1000

/* XCOFF uses a special .debug section with type STYP_DEBUG.  */
#define STYP_DEBUG 0x2000

/* XCOFF handles line number or relocation overflow by creating
   another section header with STYP_OVRFLO set.  */
#define STYP_OVRFLO 0x8000

/********************** LINE NUMBERS **********************/

/* 1 line number entry for every "breakpointable" source line in a section.
   Line numbers are grouped on a per function basis; first entry in a function
   grouping will have l_lnno = 0 and in place of physical address will be the
   symbol table index of the function name.  */
struct external_lineno
{
  union
  {
    char l_symndx[8];/* function name symbol index, iff l_lnno == 0*/
    char l_paddr[8];	/* (physical) address of line number	*/
  } l_addr;

  char l_lnno[4];		/* line number		*/
};

#define	LINENO	struct external_lineno
#define	LINESZ	12


union external_auxent
{
  struct
  {
    union
    {
      struct
      {
	char x_lnno[4]; 	/* declaration line number */
	char x_size[2]; 	/* str/union/array size */
      } x_lnsz;
      
      struct
      {
	char x_lnnoptr[8];/* ptr to fcn line */
	char x_fsize[4];	 /* size of function */
	char x_endndx[4];	 /* entry ndx past block end */
      } x_fcn;

    } x_fcnary;

  } x_sym;
         
  union
  {
    char x_fname[E_FILNMLEN];
    
    struct
    {
      char x_zeroes[4];
      char x_offset[4];
      char          x_pad[6];
      unsigned char x_ftype[1];
      unsigned char x_resv[2];
    } x_n;

  } x_file;

  struct
  {
    char x_exptr[8];
    char x_fsize[4];
    char x_endndx[4];
    char x_pad[1];
  } x_except;

  struct
  {
    unsigned char x_scnlen_lo[4];
    unsigned char x_parmhash[4];
    unsigned char x_snhash[2];
    unsigned char x_smtyp[1];
    unsigned char x_smclas[1];
    unsigned char x_scnlen_hi[4];
    unsigned char x_pad[1];
  } x_csect;	

  struct
  {
    char x_pad[17];
    char x_auxtype[1];
  } x_auxtype;
};

#define	AUXENT	union external_auxent
#define	AUXESZ	18

#define DBXMASK 0x80		/* for dbx storage mask */
#define SYMNAME_IN_DEBUG(symptr) ((symptr)->n_sclass & DBXMASK)

/* Values for auxtype field in XCOFF64, taken from AIX 4.3 sym.h */
#define _AUX_EXCEPT     255
#define _AUX_FCN        254
#define _AUX_SYM        253
#define _AUX_FILE       252
#define _AUX_CSECT      251

/********************** RELOCATION DIRECTIVES **********************/

struct external_reloc
{
  char r_vaddr[8];
  char r_symndx[4];
  char r_size[1];
  char r_type[1];
};

#define RELOC struct external_reloc
#define RELSZ 14

#define DEFAULT_DATA_SECTION_ALIGNMENT 4
#define DEFAULT_BSS_SECTION_ALIGNMENT 4
#define DEFAULT_TEXT_SECTION_ALIGNMENT 4
/* For new sections we havn't heard of before */
#define DEFAULT_SECTION_ALIGNMENT 4
