# /* This is file LSEEK.S */
# /*
# ** Copyright (C) 1991 DJ Delorie
# **
# ** This file is distributed under the terms listed in the document
# ** "copying.dj".
# ** A copy of "copying.dj" should accompany this file; if not, a copy
# ** should be available from where this file was obtained.  This file
# ** may not be distributed without a verbatim copy of "copying.dj".
# **
# ** This file is distributed WITHOUT ANY WARRANTY; without even the implied
# ** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# */

	.text
	.globl _lseek
_lseek:
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	16(%esp),%ebx
	movl	20(%esp),%ecx
	shrl	$16,%ecx
	movl	20(%esp),%edx
	andl	$0xffff,%edx
	movb	24(%esp),%al
	movb	$0x42,%ah
	int	$0x21
	popl	%edi
	popl	%esi
	popl	%ebx
	jb	syscall_error
	shll	$16,%edx
	andl	$0xffff,%eax
	orl	%edx,%eax
	ret
