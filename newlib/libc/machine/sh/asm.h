#ifdef __STDC__
# define _C_LABEL(x)    _ ## x
#else
# define _C_LABEL(x)    _/**/x
#endif
#define _ASM_LABEL(x)   x

#if __SH5__
# if __SH5__ == 32 && __SHMEDIA__
#  define TEXT .section .text..SHmedia32, "ax"
# else
#  define TEXT .text
# endif

# define _ENTRY(name)	\
	TEXT; .align 4; .globl name; name:
#else
#define _ENTRY(name)	\
	.text; .align 2; .globl name; name:
#endif /* __SH5__ */

#define ENTRY(name)	\
	_ENTRY(_C_LABEL(name))

#if (defined (__sh2__) || defined (__sh3__) || defined (__SH3E__) \
     || defined (__SH4_SINGLE__) || defined (__SH4__)) || defined(__SH4_SINGLE_ONLY__)
#define DELAYED_BRANCHES
#define SL(branch, dest, in_slot, in_slot_arg2) \
	branch##.s dest; in_slot, in_slot_arg2
#else
#define SL(branch, dest, in_slot, in_slot_arg2) \
	in_slot, in_slot_arg2; branch dest
#endif
