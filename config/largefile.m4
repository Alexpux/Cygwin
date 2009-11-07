# This macro wraps AC_SYS_LARGEFILE with one exception for Solaris.
# PR 9992/binutils: We have to replicate everywhere the behaviour of
# bfd's configure script so that all the directories agree on the size
# of structures used to describe files.

AC_DEFUN([ACX_LARGEFILE],[dnl
case "${host}" in
changequote(,)dnl
  sparc-*-solaris*|i[3-7]86-*-solaris*)
changequote([,])dnl
    # On native 32bit sparc and ia32 solaris, large-file and procfs support
    # are mutually exclusive; and without procfs support, the bfd/ elf module
    # cannot provide certain routines such as elfcore_write_prpsinfo
    # or elfcore_write_prstatus.  So unless the user explicitly requested
    # large-file support through the --enable-largefile switch, disable
    # large-file support in favor of procfs support.
    test "${target}" = "${host}" -a "x$plugins" = xno \
      && : ${enable_largefile="no"}
    ;;
esac

AC_SYS_LARGEFILE
])
