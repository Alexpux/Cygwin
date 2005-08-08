/*-
 * Copyright (c) 1998 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/sys/elf_generic.h,v 1.6 2002/07/20 02:56:11 peter Exp $
 */

#ifndef _SYS_ELF_GENERIC_H_
#define _SYS_ELF_GENERIC_H_ 1

#include <sys/cdefs.h>

/*
 * Definitions of generic ELF names which relieve applications from
 * needing to know the word size.
 */

#ifndef __ELF_WORD_SIZE
# define __ELF_WORD_SIZE 32
#endif

#if __ELF_WORD_SIZE != 32 && __ELF_WORD_SIZE != 64
#error "__ELF_WORD_SIZE must be defined as 32 or 64"
#endif

#define ELF_CLASS	__CONCAT(ELFCLASS,__ELF_WORD_SIZE)

#if BYTE_ORDER == LITTLE_ENDIAN
#define ELF_DATA	ELFDATA2LSB
#elif BYTE_ORDER == BIG_ENDIAN
#define ELF_DATA	ELFDATA2MSB
#else
#error "Unknown byte order"
#endif

#if __ELF_WORD_SIZE == 32
#define __elfN(x)	elf32_##x
#define __ElfN(x)	Elf32_##x
#define __ELFN(x)	ELF32_##x
#else
#define __elfN(x)	elf364_##x
#define __ElfN(x)	Elf364_##x
#define __ELFN(x)	ELF364_##x
#endif
#define __ElfType(x)	typedef __ElfN(x) Elf_##x

#define FOO
__ElfType(Addr);
__ElfType(Half);
__ElfType(Off);
__ElfType(Sword);
__ElfType(Word);
__ElfType(Size);
__ElfType(Hashelt);
__ElfType(Ehdr);
__ElfType(Shdr);
__ElfType(Phdr);
__ElfType(Dyn);
__ElfType(Rel);
__ElfType(Rela);
__ElfType(Sym);

#define ELF_R_SYM	__ELFN(R_SYM)
#define ELF_R_TYPE	__ELFN(R_TYPE)
#define ELF_R_INFO	__ELFN(R_INFO)
#define ELF_ST_BIND	__ELFN(ST_BIND)
#define ELF_ST_TYPE	__ELFN(ST_TYPE)
#define ELF_ST_INFO	__ELFN(ST_INFO)

#endif /* !_SYS_ELF_GENERIC_H_ */
