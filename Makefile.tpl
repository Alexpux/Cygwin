[+ AutoGen5 template
in
+]

# Makefile.in is generated from Makefile.tpl by 'autogen Makefile.def'.
#
# Makefile for directory with subdirs to build.
#   Copyright (C) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998,
#   1999, 2000, 2001, 2002 Free Software Foundation
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

# Tell GNU make 3.79 not to run the top level in parallel.  This 
# prevents contention for $builddir/$target/config.cache, as well
# as minimizing scatter in file system caches.
NOTPARALLEL = .NOTPARALLEL
$(NOTPARALLEL):

srcdir = @srcdir@

prefix = @prefix@
exec_prefix = @exec_prefix@

bindir = @bindir@
sbindir = @sbindir@
libexecdir = @libexecdir@
datadir = @datadir@
sysconfdir = @sysconfdir@
sharedstatedir = @sharedstatedir@
localstatedir = @localstatedir@
libdir = @libdir@
includedir = @includedir@
oldincludedir = @oldincludedir@
infodir = @infodir@
mandir = @mandir@
gxx_include_dir=@gxx_include_dir@

tooldir = @tooldir@
build_tooldir = @build_tooldir@

program_transform_name = @program_transform_name@

man1dir = $(mandir)/man1
man2dir = $(mandir)/man2
man3dir = $(mandir)/man3
man4dir = $(mandir)/man4
man5dir = $(mandir)/man5
man6dir = $(mandir)/man6
man7dir = $(mandir)/man7
man8dir = $(mandir)/man8
man9dir = $(mandir)/man9
# Directory in which the compiler finds executables, libraries, etc.
libsubdir = $(libdir)/gcc-lib/$(target_alias)/$(gcc_version)
GDB_NLM_DEPS = 

SHELL = @config_shell@

# pwd command to use.  Allow user to override default by setting PWDCMD in
# the environment to account for automounters.  The make variable must not
# be called PWDCMD, otherwise the value set here is passed to make
# subprocesses and overrides the setting from the user's environment.
PWD = $${PWDCMD-pwd}

# INSTALL_PROGRAM_ARGS is changed by configure.in to use -x for a
# cygwin host.
INSTALL_PROGRAM_ARGS =

INSTALL = $(SHELL) $$s/install-sh -c
INSTALL_PROGRAM = $(INSTALL) $(INSTALL_PROGRAM_ARGS)
INSTALL_SCRIPT = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

INSTALL_DOSREL = install-dosrel-fake

AS = as
AR = ar
AR_FLAGS = rc
CC = cc

# Special variables passed down in EXTRA_GCC_FLAGS.  They are defined
# here so that they can be overridden by Makefile fragments.
HOST_CC = $(CC_FOR_BUILD)
BUILD_PREFIX = 
BUILD_PREFIX_1 = loser-

# These flag values are normally overridden by the configure script.
CFLAGS = -g
CXXFLAGS = -g -O2

LDFLAGS = 
LIBCFLAGS = $(CFLAGS)
CFLAGS_FOR_BUILD = $(CFLAGS)
# During gcc bootstrap, if we use some random cc for stage1 then
# CFLAGS will be just -g.  We want to ensure that TARGET libraries
# (which we know are built with gcc) are built with optimizations so
# prepend -O2 when setting CFLAGS_FOR_TARGET.
CFLAGS_FOR_TARGET = -O2 $(CFLAGS)
LDFLAGS_FOR_TARGET = 
LIBCFLAGS_FOR_TARGET = $(CFLAGS_FOR_TARGET)
PICFLAG = 
PICFLAG_FOR_TARGET = 

CXX = c++

# Use -O2 to stress test the compiler.
LIBCXXFLAGS = $(CXXFLAGS) -fno-implicit-templates
CXXFLAGS_FOR_TARGET = $(CXXFLAGS)
LIBCXXFLAGS_FOR_TARGET = $(CXXFLAGS_FOR_TARGET) -fno-implicit-templates

DLLTOOL = dlltool
WINDRES = windres

NM = nm

LD = ld

# These values are substituted by configure.
DEFAULT_YACC = @DEFAULT_YACC@
DEFAULT_LEX = @DEFAULT_LEX@
DEFAULT_M4 = @DEFAULT_M4@

BISON = `if [ -f $$r/bison/bison ] ; then \
	    echo $$r/bison/bison -L $$s/bison/ ; \
	 else \
	    echo bison ; \
	 fi`

YACC = `if [ -f $$r/bison/bison ] ; then \
	    echo $$r/bison/bison -y -L $$s/bison/ ; \
	elif [ -f $$r/byacc/byacc ] ; then \
	    echo $$r/byacc/byacc ; \
	else \
	    echo ${DEFAULT_YACC} ; \
	fi`

LEX = `if [ -f $$r/flex/flex ] ; \
	then echo $$r/flex/flex ; \
	else echo ${DEFAULT_LEX} ; fi`

M4 = `if [ -f $$r/m4/m4 ] ; \
	then echo $$r/m4/m4 ; \
	else echo ${DEFAULT_M4} ; fi`

# For an installed makeinfo, we require it to be from texinfo 4 or
# higher, else we use the "missing" dummy.
MAKEINFO = `if [ -f $$r/texinfo/makeinfo/makeinfo ] ; \
	then echo $$r/texinfo/makeinfo/makeinfo ; \
	else if (makeinfo --version \
	  | egrep 'texinfo[^0-9]*([1-3][0-9]|[4-9])') >/dev/null 2>&1; \
        then echo makeinfo; else echo $$s/missing makeinfo; fi; fi`

# This just becomes part of the MAKEINFO definition passed down to
# sub-makes.  It lets flags be given on the command line while still
# using the makeinfo from the object tree.
MAKEINFOFLAGS =

EXPECT = `if [ -f $$r/expect/expect ] ; \
	then echo $$r/expect/expect ; \
	else echo expect ; fi`

RUNTEST = `if [ -f $$s/dejagnu/runtest ] ; \
	then echo $$s/dejagnu/runtest ; \
	else echo runtest ; fi`


# compilers to use to create programs which must be run in the build
# environment.
CC_FOR_BUILD = $(CC)
CXX_FOR_BUILD = $(CXX)

SUBDIRS = @configdirs@

# This is set by the configure script to the list of directories which
# should be built using the target tools.
TARGET_CONFIGDIRS = @target_configdirs@

# Target libraries are put under this directory:
# Changed by configure to $(target_alias) if cross.
TARGET_SUBDIR = @target_subdir@

BUILD_CONFIGDIRS = libiberty
BUILD_SUBDIR = @build_subdir@

# This is set by the configure script to the arguments to use when configuring
# directories built for the target.
TARGET_CONFIGARGS = @target_configargs@

# This is set by the configure script to the arguments to use when configuring
# directories built for the build system.
BUILD_CONFIGARGS = @build_configargs@

# This is set by configure to REALLY_SET_LIB_PATH if --enable-shared
# was used.
SET_LIB_PATH = @SET_LIB_PATH@

# This is the name of the environment variable used for the path to
# the libraries.  This may be changed by configure.in.
RPATH_ENVVAR = @RPATH_ENVVAR@

# This is the list of directories that may be needed in RPATH_ENVVAR
# so that programs built for the host machine work.
HOST_LIB_PATH = $$r/bfd:$$r/opcodes

# This is the list of directories that may be needed in RPATH_ENVVAR
# so that prorgams built for the target machine work.
TARGET_LIB_PATH = $$r/$(TARGET_SUBDIR)/libstdc++-v3/src/.libs:

# configure.in sets SET_LIB_PATH to this if --enable-shared was used.
# Some platforms don't like blank entries, so we remove duplicate,
# leading and trailing colons.
REALLY_SET_LIB_PATH = \
  $(RPATH_ENVVAR)=`echo "$(HOST_LIB_PATH):$(TARGET_LIB_PATH):$$$(RPATH_ENVVAR)" | sed 's,::*,:,g;s,^:*,,;s,:*$$,,'`; export $(RPATH_ENVVAR);

ALL = all.normal
INSTALL_TARGET = installdirs \
	install-gcc \
	$(INSTALL_MODULES) \
	$(INSTALL_TARGET_MODULES) \
	$(INSTALL_X11_MODULES) \
	$(INSTALL_DOSREL)

INSTALL_TARGET_CROSS = installdirs \
	install-gcc-cross \
	$(INSTALL_MODULES) \
	$(INSTALL_TARGET_MODULES) \
	$(INSTALL_X11_MODULES) \
	$(INSTALL_DOSREL)

# Should be substed by configure.in
FLAGS_FOR_TARGET = @FLAGS_FOR_TARGET@
CC_FOR_TARGET = @CC_FOR_TARGET@
CXX_FOR_TARGET = @CXX_FOR_TARGET@
CXX_FOR_TARGET_FOR_RECURSIVE_MAKE = @CXX_FOR_TARGET_FOR_RECURSIVE_MAKE@
GCJ_FOR_TARGET = @GCJ_FOR_TARGET@

# If GCC_FOR_TARGET is not overriden on the command line, then this
# variable is passed down to the gcc Makefile, where it is used to
# build libgcc2.a.  We define it here so that it can itself be
# overridden on the command line.
GCC_FOR_TARGET = $(STAGE_CC_WRAPPER) $$r/gcc/xgcc -B$$r/gcc/ $(FLAGS_FOR_TARGET)

AS_FOR_TARGET = ` \
  if [ -f $$r/gas/as-new ] ; then \
    echo $$r/gas/as-new ; \
  elif [ -f $$r/gcc/xgcc ]; then \
    $(CC_FOR_TARGET) -print-prog-name=as ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(AS); \
    else \
       t='$(program_transform_name)'; echo as | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

LD_FOR_TARGET = ` \
  if [ -f $$r/ld/ld-new ] ; then \
    echo $$r/ld/ld-new ; \
  elif [ -f $$r/gcc/xgcc ]; then \
    $(CC_FOR_TARGET) -print-prog-name=ld ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(LD); \
    else \
       t='$(program_transform_name)'; echo ld | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

DLLTOOL_FOR_TARGET = ` \
  if [ -f $$r/binutils/dlltool ] ; then \
    echo $$r/binutils/dlltool ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(DLLTOOL); \
    else \
       t='$(program_transform_name)'; echo dlltool | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

WINDRES_FOR_TARGET = ` \
  if [ -f $$r/binutils/windres ] ; then \
    echo $$r/binutils/windres ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(WINDRES); \
    else \
       t='$(program_transform_name)'; echo windres | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

AR_FOR_TARGET = ` \
  if [ -f $$r/binutils/ar ] ; then \
    echo $$r/binutils/ar ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(AR); \
    else \
       t='$(program_transform_name)'; echo ar | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

RANLIB_FOR_TARGET = ` \
  if [ -f $$r/binutils/ranlib ] ; then \
    echo $$r/binutils/ranlib ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      if [ x'$(RANLIB)' != x ]; then \
         echo $(RANLIB); \
      else \
         echo ranlib; \
      fi; \
    else \
       t='$(program_transform_name)'; echo ranlib | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

NM_FOR_TARGET = ` \
  if [ -f $$r/binutils/nm-new ] ; then \
    echo $$r/binutils/nm-new ; \
  elif [ -f $$r/gcc/xgcc ]; then \
    $(CC_FOR_TARGET) -print-prog-name=nm ; \
  else \
    if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
      echo $(NM); \
    else \
       t='$(program_transform_name)'; echo nm | sed -e 's/x/x/' $$t ; \
    fi; \
  fi`

# The first rule in the file had better be this one.  Don't put any above it.
# This lives here to allow makefile fragments to contain dependencies.
all: all.normal
.PHONY: all

# These can be overridden by config/mt-*.
# The _TARGET_ is because they're specified in mt-foo.
# The _HOST_ is because they're programs that run on the host.
EXTRA_TARGET_HOST_ALL_MODULES =
EXTRA_TARGET_HOST_INSTALL_MODULES =
EXTRA_TARGET_HOST_CHECK_MODULES =

#### host and target specific makefile fragments come in here.
###

# Flags to pass down to all sub-makes.
# Please keep these in alphabetical order.
BASE_FLAGS_TO_PASS = \
	"AR_FLAGS=$(AR_FLAGS)" \
	"AR_FOR_TARGET=$(AR_FOR_TARGET)" \
	"AS_FOR_TARGET=$(AS_FOR_TARGET)" \
	"BISON=$(BISON)" \
	"CC_FOR_BUILD=$(CC_FOR_BUILD)" \
	"CC_FOR_TARGET=$(CC_FOR_TARGET)" \
	"CFLAGS=$(CFLAGS)" \
	"CFLAGS_FOR_TARGET=$(CFLAGS_FOR_TARGET)" \
	"GCJ_FOR_TARGET=$(GCJ_FOR_TARGET)" \
	"CXX_FOR_BUILD=$(CXX_FOR_BUILD)" \
	"CXXFLAGS=$(CXXFLAGS)" \
	"CXXFLAGS_FOR_TARGET=$(CXXFLAGS_FOR_TARGET)" \
	"CXX_FOR_TARGET=$(CXX_FOR_TARGET)" \
	"DLLTOOL_FOR_TARGET=$(DLLTOOL_FOR_TARGET)" \
	"INSTALL=$(INSTALL)" \
	"INSTALL_DATA=$(INSTALL_DATA)" \
	"INSTALL_PROGRAM=$(INSTALL_PROGRAM)" \
	"INSTALL_SCRIPT=$(INSTALL_SCRIPT)" \
	"LDFLAGS=$(LDFLAGS)" \
	"LEX=$(LEX)" \
	"LD_FOR_TARGET=$(LD_FOR_TARGET)" \
	"LIBCFLAGS=$(LIBCFLAGS)" \
	"LIBCFLAGS_FOR_TARGET=$(LIBCFLAGS_FOR_TARGET)" \
	"LIBCXXFLAGS=$(LIBCXXFLAGS)" \
	"LIBCXXFLAGS_FOR_TARGET=$(LIBCXXFLAGS_FOR_TARGET)" \
	"M4=$(M4)" \
	"MAKE=$(MAKE)" \
	"MAKEINFO=$(MAKEINFO) $(MAKEINFOFLAGS)" \
	"NM_FOR_TARGET=$(NM_FOR_TARGET)" \
	"RANLIB_FOR_TARGET=$(RANLIB_FOR_TARGET)" \
	"RPATH_ENVVAR=$(RPATH_ENVVAR)" \
	"SHELL=$(SHELL)" \
	"EXPECT=$(EXPECT)" \
	"RUNTEST=$(RUNTEST)" \
	"RUNTESTFLAGS=$(RUNTESTFLAGS)" \
	"TARGET_SUBDIR=$(TARGET_SUBDIR)" \
	"WINDRES_FOR_TARGET=$(WINDRES_FOR_TARGET)" \
	"YACC=$(YACC)" \
	"bindir=$(bindir)" \
	"datadir=$(datadir)" \
	"exec_prefix=$(exec_prefix)" \
	"includedir=$(includedir)" \
	"infodir=$(infodir)" \
	"libdir=$(libdir)" \
	"libexecdir=$(libexecdir)" \
	"lispdir=$(lispdir)" \
	"libstdcxx_incdir=$(libstdcxx_incdir)" \
	"libsubdir=$(libsubdir)" \
	"localstatedir=$(localstatedir)" \
	"mandir=$(mandir)" \
	"oldincludedir=$(oldincludedir)" \
	"prefix=$(prefix)" \
	"sbindir=$(sbindir)" \
	"sharedstatedir=$(sharedstatedir)" \
	"sysconfdir=$(sysconfdir)" \
	"tooldir=$(tooldir)" \
	"build_tooldir=$(build_tooldir)" \
	"gxx_include_dir=$(gxx_include_dir)" \
	"gcc_version=$(gcc_version)" \
	"gcc_version_trigger=$(gcc_version_trigger)" \
	"target_alias=$(target_alias)" 

# For any flags above that may contain shell code that varies from one
# target library to another.  When doing recursive invocations of the
# top-level Makefile, we don't want the outer make to evaluate them,
# so we pass these variables down unchanged.  They must not contain
# single nor double quotes.
RECURSE_FLAGS = \
	CXX_FOR_TARGET='$(CXX_FOR_TARGET_FOR_RECURSIVE_MAKE)'

# Flags to pass down to most sub-makes, in which we're building with
# the host environment.
# If any variables are added here, they must be added to do-*, below.
EXTRA_HOST_FLAGS = \
	'AR=$(AR)' \
	'AS=$(AS)' \
	'CC=$(CC)' \
	'CXX=$(CXX)' \
	'DLLTOOL=$(DLLTOOL)' \
	'LD=$(LD)' \
	'NM=$(NM)' \
	"`echo 'RANLIB=$(RANLIB)' | sed -e s/.*=$$/XFOO=/`" \
	'WINDRES=$(WINDRES)'

FLAGS_TO_PASS = $(BASE_FLAGS_TO_PASS) $(EXTRA_HOST_FLAGS)

# Flags that are concerned with the location of the X11 include files
# and library files
#
# NOTE: until the top-level is getting the values via autoconf, it only
# causes problems to have this top-level Makefile overriding the autoconf-set
# values in child directories.  Only variables that don't conflict with
# autoconf'ed ones should be passed by X11_FLAGS_TO_PASS for now.
#
X11_FLAGS_TO_PASS = \
	'X11_EXTRA_CFLAGS=$(X11_EXTRA_CFLAGS)' \
	'X11_EXTRA_LIBS=$(X11_EXTRA_LIBS)'

# Flags to pass down to makes which are built with the target environment.
# The double $ decreases the length of the command line; the variables
# are set in BASE_FLAGS_TO_PASS, and the sub-make will expand them.
# If any variables are added here, they must be added to do-*, below.
EXTRA_TARGET_FLAGS = \
	'AR=$$(AR_FOR_TARGET)' \
	'AS=$$(AS_FOR_TARGET)' \
	'CC=$$(CC_FOR_TARGET)' \
	'CFLAGS=$$(CFLAGS_FOR_TARGET)' \
	'CXX=$$(CXX_FOR_TARGET)' \
	'CXXFLAGS=$$(CXXFLAGS_FOR_TARGET)' \
	'DLLTOOL=$$(DLLTOOL_FOR_TARGET)' \
	'LD=$$(LD_FOR_TARGET)' \
	'LIBCFLAGS=$$(LIBCFLAGS_FOR_TARGET)' \
	'LIBCXXFLAGS=$$(LIBCXXFLAGS_FOR_TARGET)' \
	'NM=$$(NM_FOR_TARGET)' \
	'RANLIB=$$(RANLIB_FOR_TARGET)' \
	'WINDRES=$$(WINDRES_FOR_TARGET)'

TARGET_FLAGS_TO_PASS = $(BASE_FLAGS_TO_PASS) $(EXTRA_TARGET_FLAGS)

# Flags to pass down to gcc.  gcc builds a library, libgcc.a, so it
# unfortunately needs the native compiler and the target ar and
# ranlib.
# If any variables are added here, they must be added to do-*, below.
# The HOST_* variables are a special case, which are used for the gcc
# cross-building scheme.
EXTRA_GCC_FLAGS = \
	'AR=$(AR)' \
	'AS=$(AS)' \
	'CC=$(CC)' \
	'CXX=$(CXX)' \
	'DLLTOOL=$$(DLLTOOL_FOR_TARGET)' \
	'HOST_CC=$(CC_FOR_BUILD)' \
	'BUILD_PREFIX=$(BUILD_PREFIX)' \
	'BUILD_PREFIX_1=$(BUILD_PREFIX_1)' \
	'NM=$(NM)' \
	"`echo 'RANLIB=$(RANLIB)' | sed -e s/.*=$$/XFOO=/`" \
	'WINDRES=$$(WINDRES_FOR_TARGET)' \
	"GCC_FOR_TARGET=$(GCC_FOR_TARGET)" \
	"CFLAGS_FOR_BUILD=$(CFLAGS_FOR_BUILD)" \
	"`echo 'LANGUAGES=$(LANGUAGES)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'STMP_FIXPROTO=$(STMP_FIXPROTO)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'LIMITS_H_TEST=$(LIMITS_H_TEST)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'LIBGCC2_CFLAGS=$(LIBGCC2_CFLAGS)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'LIBGCC2_DEBUG_CFLAGS=$(LIBGCC2_DEBUG_CFLAGS)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'LIBGCC2_INCLUDES=$(LIBGCC2_INCLUDES)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'ENQUIRE=$(ENQUIRE)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'STAGE1_CFLAGS=$(STAGE1_CFLAGS)' | sed -e s/.*=$$/XFOO=/`" \
	"`echo 'BOOT_CFLAGS=$(BOOT_CFLAGS)' | sed -e s/.*=$$/XFOO=/`"

GCC_FLAGS_TO_PASS = $(BASE_FLAGS_TO_PASS) $(EXTRA_GCC_FLAGS)

# This is a list of the targets for all of the modules which are compiled
# using the build machine's native compiler.  Configure edits the second
# macro for build!=host builds.
ALL_BUILD_MODULES_LIST = \
	all-build-libiberty
ALL_BUILD_MODULES = @all_build_modules@

# This is a list of the configure targets for all of the modules which
# are compiled using the native tools.
CONFIGURE_BUILD_MODULES = \
	configure-build-libiberty

# This is a list of the targets for all of the modules which are compiled
# using $(FLAGS_TO_PASS).
ALL_MODULES = [+ FOR host_modules +]\
	all-[+module+] [+ ENDFOR host_modules +]\
	$(EXTRA_TARGET_HOST_ALL_MODULES)

# This is a list of the check targets for all of the modules which are
# compiled using $(FLAGS_TO_PASS).
#
# The list is in two parts.  The first lists those tools which
# are tested as part of the host's native tool-chain, and not
# tested in a cross configuration.
NATIVE_CHECK_MODULES = \
	check-bison \
	check-byacc \
	check-fastjar \
	check-flex \
	check-zip

CROSS_CHECK_MODULES = [+ FOR host_modules +][+ IF no_check  +][+ ELIF no_check_cross +][+ ELSE x +]\
	check-[+module+] [+ ENDIF no_check +][+ ENDFOR host_modules +]\
	$(EXTRA_TARGET_HOST_CHECK_MODULES)

CHECK_MODULES=$(NATIVE_CHECK_MODULES) $(CROSS_CHECK_MODULES)

# This is a list of the install targets for all of the modules which are
# compiled using $(FLAGS_TO_PASS).
INSTALL_MODULES = [+ FOR host_modules+][+ IF no_install +][+ ELSE no_install +]\
	install-[+module+] [+ ENDIF no_install +][+ ENDFOR host_modules +]\
	$(EXTRA_TARGET_HOST_INSTALL_MODULES)

# This is a list of the targets for all of the modules which are compiled
# using $(X11_FLAGS_TO_PASS).
ALL_X11_MODULES = \
	all-gdb \
	all-expect \
	all-guile \
	all-tclX \
	all-tk \
	all-tix

# This is a list of the check targets for all of the modules which are
# compiled using $(X11_FLAGS_TO_PASS).
CHECK_X11_MODULES = \
	check-gdb \
	check-guile \
	check-expect \
	check-tclX \
	check-tk \
	check-tix

# This is a list of the install targets for all the modules which are
# compiled using $(X11_FLAGS_TO_PASS).
INSTALL_X11_MODULES = \
	install-gdb \
	install-guile \
	install-expect \
	install-tclX \
	install-tk \
	install-tix

# This is a list of the targets for all of the modules which are compiled
# using $(TARGET_FLAGS_TO_PASS).
ALL_TARGET_MODULES = [+ FOR target_modules +]\
	all-target-[+module+] [+ ENDFOR target_modules +]

# This is a list of the configure targets for all of the modules which
# are compiled using the target tools.
CONFIGURE_TARGET_MODULES = [+ FOR target_modules +]\
	configure-target-[+module+] [+ ENDFOR target_modules +]

# This is a list of the check targets for all of the modules which are
# compiled using $(TARGET_FLAGS_TO_PASS).
CHECK_TARGET_MODULES = [+ FOR target_modules +][+ IF no_check +][+ ELSE check +]\
	check-target-[+module+] [+ ENDIF no_check +][+ ENDFOR target_modules +]

# This is a list of the install targets for all of the modules which are
# compiled using $(TARGET_FLAGS_TO_PASS).
INSTALL_TARGET_MODULES = [+ FOR target_modules +][+ IF no_install +][+ ELSE install +]\
	install-target-[+module+] [+ ENDIF no_install +][+ ENDFOR target_modules +]

# This is a list of the targets for which we can do a clean-{target}.
CLEAN_MODULES = [+ FOR host_modules +][+ IF no_clean +][+ ELSE no_clean +]\
	clean-[+module+] [+ ENDIF no_clean +][+ ENDFOR host_modules +]

# All of the target modules that can be cleaned
CLEAN_TARGET_MODULES = [+ FOR target_modules +][+ IF no_clean +][+ ELSE clean +]\
	clean-target-[+module+] [+ ENDIF no_clean +][+ ENDFOR target_modules +]

# All of the x11 modules that can be cleaned
CLEAN_X11_MODULES = \
	clean-gdb \
	clean-expect \
	clean-guile \
	clean-tclX \
	clean-tk \
	clean-tix

# The target built for a native build.
.PHONY: all.normal
all.normal: \
	$(ALL_BUILD_MODULES) \
	$(ALL_MODULES) \
	$(ALL_X11_MODULES) \
	$(ALL_TARGET_MODULES) \
	all-gcc

# Do a target for all the subdirectories.  A ``make do-X'' will do a
# ``make X'' in all subdirectories (because, in general, there is a
# dependency (below) of X upon do-X, a ``make X'' will also do this,
# but it may do additional work as well).
# This target ensures that $(BASE_FLAGS_TO_PASS) appears only once,
# because it is so large that it can easily overflow the command line
# length limit on some systems.
DO_X = \
	do-clean \
	do-distclean \
	do-dvi \
	do-info \
	do-install-info \
	do-installcheck \
	do-mostlyclean \
	do-maintainer-clean \
	do-TAGS
.PHONY: $(DO_X)
$(DO_X):
	@target=`echo $@ | sed -e 's/^do-//'`; \
	r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}`; export s; \
	$(SET_LIB_PATH) \
	for i in $(SUBDIRS) -dummy-; do \
	  if [ -f ./$$i/Makefile ]; then \
	    case $$i in \
	    gcc) \
	      for flag in $(EXTRA_GCC_FLAGS); do \
		eval `echo "$$flag" | sed -e "s|^\([^=]*\)=\(.*\)|\1='\2'; export \1|"`; \
	      done; \
	      ;; \
	    *) \
	      for flag in $(EXTRA_HOST_FLAGS); do \
		eval `echo "$$flag" | sed -e "s|^\([^=]*\)=\(.*\)|\1='\2'; export \1|"`; \
	      done; \
	      ;; \
	    esac ; \
	    if (cd ./$$i; \
	        $(MAKE) $(BASE_FLAGS_TO_PASS) "AR=$${AR}" "AS=$${AS}" \
			"CC=$${CC}" "CXX=$${CXX}" "LD=$${LD}" "NM=$${NM}" \
	                "`echo \"RANLIB=$${RANLIB}\" | sed -e 's/.*=$$/XFOO=/'`" \
			"DLLTOOL=$${DLLTOOL}" "WINDRES=$${WINDRES}" \
			$${target}); \
	    then true; else exit 1; fi; \
	  else true; fi; \
	done
	@target=`echo $@ | sed -e 's/^do-//'`; \
	r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}`; export s; \
	$(SET_LIB_PATH) \
	for i in $(TARGET_CONFIGDIRS) -dummy-; do \
	  if [ -f $(TARGET_SUBDIR)/$$i/Makefile ]; then \
	    for flag in $(EXTRA_TARGET_FLAGS); do \
		eval `echo "$$flag" | sed -e "s|^\([^=]*\)=\(.*\)|\1='\2'; export \1|"`; \
	    done; \
	    if (cd $(TARGET_SUBDIR)/$$i; \
	        $(MAKE) $(BASE_FLAGS_TO_PASS) "AR=$${AR}" "AS=$${AS}" \
			"CC=$${CC}" "CXX=$${CXX}" "LD=$${LD}" "NM=$${NM}" \
	                "`echo \"RANLIB=$${RANLIB}\" | sed -e 's/.*=$$/XFOO=/'`" \
			"DLLTOOL=$${DLLTOOL}" "WINDRES=$${WINDRES}" \
			$${target}); \
	    then true; else exit 1; fi; \
	  else true; fi; \
	done

# Here are the targets which correspond to the do-X targets.

.PHONY: info installcheck dvi install-info
.PHONY: clean distclean mostlyclean maintainer-clean realclean
.PHONY: local-clean local-distclean local-maintainer-clean
info: do-info
installcheck: do-installcheck
dvi: do-dvi

# Make sure makeinfo is built before we do a `make info'.
do-info: all-texinfo

install-info: do-install-info dir.info
	s=`cd $(srcdir); ${PWD}`; export s; \
	if [ -f dir.info ] ; then \
	  $(INSTALL_DATA) dir.info $(infodir)/dir.info ; \
	else true ; fi

local-clean:
	-rm -f *.a TEMP errs core *.o *~ \#* TAGS *.E *.log

local-distclean:
	-rm -f Makefile config.status config.cache mh-frag mt-frag
	-if [ "$(TARGET_SUBDIR)" != "." ]; then \
	  rm -rf $(TARGET_SUBDIR); \
	else true; fi
	-rm -f texinfo/po/Makefile texinfo/po/Makefile.in texinfo/info/Makefile
	-rm -f texinfo/doc/Makefile texinfo/po/POTFILES
	-rmdir texinfo/doc texinfo/info texinfo/intl texinfo/lib 2>/dev/null
	-rmdir texinfo/makeinfo texinfo/po texinfo/util 2>/dev/null
	-rmdir fastjar gcc libiberty texinfo zlib 2>/dev/null

local-maintainer-clean:
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

clean: do-clean local-clean
mostlyclean: do-mostlyclean local-clean
distclean: do-distclean local-clean local-distclean
maintainer-clean: local-maintainer-clean do-maintainer-clean local-clean 
maintainer-clean: local-distclean
realclean: maintainer-clean

# This rule is used to clean specific modules.
.PHONY: $(CLEAN_MODULES) $(CLEAN_X11_MODULES) clean-gcc
$(CLEAN_MODULES) $(CLEAN_X11_MODULES) clean-gcc:
	@dir=`echo $@ | sed -e 's/clean-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) clean); \
	else \
	  true; \
	fi

.PHONY: $(CLEAN_TARGET_MODULES)
$(CLEAN_TARGET_MODULES):
	@dir=`echo $@ | sed -e 's/clean-target-//'`; \
	rm -f $(TARGET_SUBDIR)/$${dir}/multilib.out $(TARGET_SUBDIR)/$${dir}/tmpmulti.out; \
	if [ -f $(TARGET_SUBDIR)/$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $(TARGET_SUBDIR)/$${dir}; $(MAKE) $(TARGET_FLAGS_TO_PASS) clean); \
	else \
	  true; \
	fi

clean-target: $(CLEAN_TARGET_MODULES) clean-target-libgcc
clean-target-libgcc:
	test ! -d gcc/libgcc || \
	(cd gcc/libgcc && find . -type d -print) | \
	while read d; do rm -f gcc/$$d/libgcc.a || : ; done
	-rm -rf gcc/libgcc

# Check target.

.PHONY: check do-check
check:
	$(MAKE) do-check NOTPARALLEL=parallel-ok

do-check: $(CHECK_MODULES) \
	$(CHECK_TARGET_MODULES) \
	$(CHECK_X11_MODULES) \
	check-gcc

# Automated reporting of test results.

warning.log: build.log
	$(srcdir)/contrib/warn_summary build.log > $@

mail-report.log:
	if test x'$(BOOT_CFLAGS)' != x''; then \
	    BOOT_CFLAGS='$(BOOT_CFLAGS)'; export BOOT_CFLAGS; \
	fi; \
	$(srcdir)/contrib/test_summary -t >$@
	chmod +x $@
	echo If you really want to send e-mail, run ./$@ now

mail-report-with-warnings.log: warning.log
	if test x'$(BOOT_CFLAGS)' != x''; then \
	    BOOT_CFLAGS='$(BOOT_CFLAGS)'; export BOOT_CFLAGS; \
	fi; \
	$(srcdir)/contrib/test_summary -t -i warning.log >$@
	chmod +x $@
	echo If you really want to send e-mail, run ./$@ now

# Installation targets.

.PHONY: install install-cross uninstall source-vault binary-vault vault-install
install: $(INSTALL_TARGET) 
install-cross: $(INSTALL_TARGET_CROSS) 

uninstall:
	@echo "the uninstall target is not supported in this tree"

source-vault:
	$(MAKE) -f ./release/Build-A-Release \
		host=$(host_alias) source-vault

binary-vault:
	$(MAKE) -f ./release/Build-A-Release \
		host=$(host_alias) target=$(target_alias)

vault-install:
	@if [ -f ./release/vault-install ] ; then \
	  ./release/vault-install $(host_alias) $(target_alias) ; \
	else \
	  true ; \
	fi

.PHONY: install.all
install.all: install-no-fixedincludes
	@if [ -f ./gcc/Makefile ] ; then \
		r=`${PWD}` ; export r ; \
		$(SET_LIB_PATH) \
		(cd ./gcc; \
		$(MAKE) $(FLAGS_TO_PASS) install-headers) ; \
	else \
		true ; \
	fi

# install-no-fixedincludes is used because Cygnus can not distribute
# the fixed header files.
.PHONY: install-no-fixedincludes
install-no-fixedincludes: \
	installdirs \
	$(INSTALL_MODULES) \
	$(INSTALL_TARGET_MODULES) \
	$(INSTALL_X11_MODULES) \
	gcc-no-fixedincludes 

# Install the gcc headers files, but not the fixed include files,
# which Cygnus is not allowed to distribute.  This rule is very
# dependent on the workings of the gcc Makefile.in.
.PHONY: gcc-no-fixedincludes
gcc-no-fixedincludes:
	@if [ -f ./gcc/Makefile ]; then \
	  rm -rf gcc/tmp-include; \
	  mv gcc/include gcc/tmp-include 2>/dev/null; \
	  mkdir gcc/include; \
	  cp $(srcdir)/gcc/gsyslimits.h gcc/include/syslimits.h; \
	  touch gcc/stmp-fixinc gcc/include/fixed; \
	  rm -f gcc/stmp-headers gcc/stmp-int-hdrs; \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}` ; export s; \
	  $(SET_LIB_PATH) \
	  (cd ./gcc; \
	   $(MAKE) $(GCC_FLAGS_TO_PASS) install); \
	  rm -rf gcc/include; \
	  mv gcc/tmp-include gcc/include 2>/dev/null; \
	else true; fi

# This rule is used to build the modules which are built with the
# build machine's native compiler.
.PHONY: $(ALL_BUILD_MODULES)
$(ALL_BUILD_MODULES):
	dir=`echo $@ | sed -e 's/all-build-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  (cd $(BUILD_SUBDIR)/$${dir} && $(MAKE) all); \
	else \
	  true; \
	fi

# This rule is used to configure the modules which are built with the
# native tools.
.PHONY: $(CONFIGURE_BUILD_MODULES)
$(CONFIGURE_BUILD_MODULES):
	@dir=`echo $@ | sed -e 's/configure-build-//'`; \
	if [ ! -d $(BUILD_SUBDIR) ]; then \
	  true; \
	elif [ -f $(BUILD_SUBDIR)/$${dir}/Makefile ] ; then \
	  true; \
	elif echo " $(BUILD_CONFIGDIRS) " | grep " $${dir} " >/dev/null 2>&1; then \
	  if [ -d $(srcdir)/$${dir} ]; then \
	    [ -d $(BUILD_SUBDIR)/$${dir} ] || mkdir $(BUILD_SUBDIR)/$${dir};\
	    r=`${PWD}`; export r; \
	    s=`cd $(srcdir); ${PWD}`; export s; \
	    AR="$(AR_FOR_BUILD)"; export AR; \
	    AS="$(AS_FOR_BUILD)"; export AS; \
	    CC="$(CC_FOR_BUILD)"; export CC; \
	    CFLAGS="$(CFLAGS_FOR_BUILD)"; export CFLAGS; \
	    CXX="$(CXX_FOR_BUILD)"; export CXX; \
	    CXXFLAGS="$(CXXFLAGS_FOR_BUILD)"; export CXXFLAGS; \
	    GCJ="$(GCJ_FOR_BUILD)"; export GCJ; \
	    DLLTOOL="$(DLLTOOL_FOR_BUILD)"; export DLLTOOL; \
	    LD="$(LD_FOR_BUILD)"; export LD; \
            LDFLAGS="$(LDFLAGS_FOR_BUILD)"; export LDFLAGS; \
	    NM="$(NM_FOR_BUILD)"; export NM; \
	    RANLIB="$(RANLIB_FOR_BUILD)"; export RANLIB; \
	    WINDRES="$(WINDRES_FOR_BUILD)"; export WINDRES; \
	    echo Configuring in $(BUILD_SUBDIR)/$${dir}; \
	    cd "$(BUILD_SUBDIR)/$${dir}" || exit 1; \
	    case $(srcdir) in \
	    /* | [A-Za-z]:[\\/]*) \
	      topdir=$(srcdir) ;; \
	    *) \
	      case "$(BUILD_SUBDIR)" in \
	      .) topdir="../$(srcdir)" ;; \
	      *) topdir="../../$(srcdir)" ;; \
	      esac ;; \
	    esac; \
	    if [ "$(srcdir)" = "." ] ; then \
	      if [ "$(BUILD_SUBDIR)" != "." ] ; then \
		if $(SHELL) $$s/symlink-tree $${topdir}/$${dir} "no-such-file" ; then \
		  if [ -f Makefile ]; then \
		    if $(MAKE) distclean; then \
		      true; \
		    else \
		      exit 1; \
		    fi; \
		  else \
		    true; \
		  fi; \
		else \
		  exit 1; \
		fi; \
	      else \
		true; \
	      fi; \
	      srcdiroption="--srcdir=."; \
	      libsrcdir="."; \
	    else \
	      srcdiroption="--srcdir=$${topdir}/$${dir}"; \
	      libsrcdir="$$s/$${dir}"; \
	    fi; \
	    if [ -f $${libsrcdir}/configure ] ; then \
	      rm -f no-such-file skip-this-dir; \
	      CONFIG_SITE=no-such-file $(SHELL) $${libsrcdir}/configure \
		$(BUILD_CONFIGARGS) $${srcdiroption} \
		--with-build-subdir="$(BUILD_SUBDIR)"; \
	    else \
	      rm -f no-such-file skip-this-dir; \
	      CONFIG_SITE=no-such-file $(SHELL) $$s/configure \
		$(BUILD_CONFIGARGS) $${srcdiroption} \
		--with-build-subdir="$(BUILD_SUBDIR)"; \
	    fi || exit 1; \
	    if [ -f skip-this-dir ] ; then \
	      sh skip-this-dir; \
	      rm -f skip-this-dir; \
	      cd ..; rmdir $${dir} || true; \
	    else \
	      true; \
	    fi; \
	  else \
	    true; \
	  fi; \
	else \
	  true; \
	fi

# This rule is used to build the modules which use FLAGS_TO_PASS.  To
# build a target all-X means to cd to X and make all.
.PHONY: $(ALL_MODULES)
$(ALL_MODULES):
	@dir=`echo $@ | sed -e 's/all-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) all); \
	else \
	  true; \
	fi

# These rules are used to check the modules which use FLAGS_TO_PASS.
# To build a target check-X means to cd to X and make check.  Some
# modules are only tested in a native toolchain.

.PHONY: $(CHECK_MODULES) $(NATIVE_CHECK_MODULES) $(CROSS_CHECK_MODULES)
$(NATIVE_CHECK_MODULES):
	@if [ '$(host_canonical)' = '$(target_canonical)' ] ; then \
	  dir=`echo $@ | sed -e 's/check-//'`; \
	  if [ -f ./$${dir}/Makefile ] ; then \
	    r=`${PWD}`; export r; \
	    s=`cd $(srcdir); ${PWD}`; export s; \
	    $(SET_LIB_PATH) \
	    (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) check); \
	  else \
	    true; \
	  fi; \
	fi

$(CROSS_CHECK_MODULES):
	@dir=`echo $@ | sed -e 's/check-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) check); \
	else \
	  true; \
	fi

# This rule is used to install the modules which use FLAGS_TO_PASS.
# To build a target install-X means to cd to X and make install.
.PHONY: $(INSTALL_MODULES)
$(INSTALL_MODULES): installdirs
	@dir=`echo $@ | sed -e 's/install-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) install); \
	else \
	  true; \
	fi

# This rule is used to configure the modules which are built with the
# target tools.
.PHONY: $(CONFIGURE_TARGET_MODULES)
$(CONFIGURE_TARGET_MODULES):
	@dir=`echo $@ | sed -e 's/configure-target-//'`; \
	if [ -d $(TARGET_SUBDIR)/$${dir} ]; then \
	  r=`${PWD}`; export r; \
	  $(CC_FOR_TARGET) --print-multi-lib > $(TARGET_SUBDIR)/$${dir}/tmpmulti.out 2> /dev/null; \
	  if [ -s $(TARGET_SUBDIR)/$${dir}/tmpmulti.out ]; then \
	    if [ -f $(TARGET_SUBDIR)/$${dir}/multilib.out ]; then \
	      if cmp $(TARGET_SUBDIR)/$${dir}/multilib.out $(TARGET_SUBDIR)/$${dir}/tmpmulti.out > /dev/null; then \
		rm -f $(TARGET_SUBDIR)/$${dir}/tmpmulti.out; \
	      else \
		echo "Multilibs changed for $${dir}, reconfiguring"; \
		rm -f $(TARGET_SUBDIR)/$${dir}/multilib.out $(TARGET_SUBDIR)/$${dir}/Makefile; \
		mv $(TARGET_SUBDIR)/$${dir}/tmpmulti.out $(TARGET_SUBDIR)/$${dir}/multilib.out; \
	      fi; \
	    else \
	      mv $(TARGET_SUBDIR)/$${dir}/tmpmulti.out $(TARGET_SUBDIR)/$${dir}/multilib.out; \
	    fi; \
	  fi; \
	fi; exit 0	# break command into two pieces
	@dir=`echo $@ | sed -e 's/configure-target-//'`; \
	if [ ! -d $(TARGET_SUBDIR) ]; then \
	  true; \
	elif [ -f $(TARGET_SUBDIR)/$${dir}/Makefile ] ; then \
	  true; \
	elif echo " $(TARGET_CONFIGDIRS) " | grep " $${dir} " >/dev/null 2>&1; then \
	  if [ -d $(srcdir)/$${dir} ]; then \
	    [ -d $(TARGET_SUBDIR)/$${dir} ] || mkdir $(TARGET_SUBDIR)/$${dir};\
	    r=`${PWD}`; export r; \
	    s=`cd $(srcdir); ${PWD}`; export s; \
	    $(SET_LIB_PATH) \
	    AR="$(AR_FOR_TARGET)"; export AR; \
	    AS="$(AS_FOR_TARGET)"; export AS; \
	    CC="$(CC_FOR_TARGET)"; export CC; \
	    CFLAGS="$(CFLAGS_FOR_TARGET)"; export CFLAGS; \
	    CXX="$(CXX_FOR_TARGET)"; export CXX; \
	    CXXFLAGS="$(CXXFLAGS_FOR_TARGET)"; export CXXFLAGS; \
	    GCJ="$(GCJ_FOR_TARGET)"; export GCJ; \
	    DLLTOOL="$(DLLTOOL_FOR_TARGET)"; export DLLTOOL; \
	    LD="$(LD_FOR_TARGET)"; export LD; \
            LDFLAGS="$(LDFLAGS_FOR_TARGET)"; export LDFLAGS; \
	    NM="$(NM_FOR_TARGET)"; export NM; \
	    RANLIB="$(RANLIB_FOR_TARGET)"; export RANLIB; \
	    WINDRES="$(WINDRES_FOR_TARGET)"; export WINDRES; \
	    echo Configuring in $(TARGET_SUBDIR)/$${dir}; \
	    cd "$(TARGET_SUBDIR)/$${dir}" || exit 1; \
	    case $(srcdir) in \
	    /* | [A-Za-z]:[\\/]*) \
	      topdir=$(srcdir) ;; \
	    *) \
	      case "$(TARGET_SUBDIR)" in \
	      .) topdir="../$(srcdir)" ;; \
	      *) topdir="../../$(srcdir)" ;; \
	      esac ;; \
	    esac; \
	    if [ "$(srcdir)" = "." ] ; then \
	      if [ "$(TARGET_SUBDIR)" != "." ] ; then \
		if $(SHELL) $$s/symlink-tree $${topdir}/$${dir} "no-such-file" ; then \
		  if [ -f Makefile ]; then \
		    if $(MAKE) distclean; then \
		      true; \
		    else \
		      exit 1; \
		    fi; \
		  else \
		    true; \
		  fi; \
		else \
		  exit 1; \
		fi; \
	      else \
		true; \
	      fi; \
	      srcdiroption="--srcdir=."; \
	      libsrcdir="."; \
	    else \
	      srcdiroption="--srcdir=$${topdir}/$${dir}"; \
	      libsrcdir="$$s/$${dir}"; \
	    fi; \
	    if [ -f $${libsrcdir}/configure ] ; then \
	      rm -f no-such-file skip-this-dir; \
	      CONFIG_SITE=no-such-file $(SHELL) $${libsrcdir}/configure \
		$(TARGET_CONFIGARGS) $${srcdiroption} \
		--with-target-subdir="$(TARGET_SUBDIR)"; \
	    else \
	      rm -f no-such-file skip-this-dir; \
	      CONFIG_SITE=no-such-file $(SHELL) $$s/configure \
		$(TARGET_CONFIGARGS) $${srcdiroption} \
		--with-target-subdir="$(TARGET_SUBDIR)"; \
	    fi || exit 1; \
	    if [ -f skip-this-dir ] ; then \
	      sh skip-this-dir; \
	      rm -f skip-this-dir; \
	      cd ..; rmdir $${dir} || true; \
	    else \
	      true; \
	    fi; \
	  else \
	    true; \
	  fi; \
	else \
	  true; \
	fi

# This rule is used to build the modules which use TARGET_FLAGS_TO_PASS.
# To build a target all-X means to cd to X and make all.
.PHONY: $(ALL_TARGET_MODULES)
$(ALL_TARGET_MODULES):
	@dir=`echo $@ | sed -e 's/all-target-//'`; \
	if [ -f $(TARGET_SUBDIR)/$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $(TARGET_SUBDIR)/$${dir}; \
	    $(MAKE) $(TARGET_FLAGS_TO_PASS) all); \
	else \
	  true; \
	fi

# This rule is used to check the modules which use TARGET_FLAGS_TO_PASS.
# To build a target install-X means to cd to X and make install.
.PHONY: $(CHECK_TARGET_MODULES)
$(CHECK_TARGET_MODULES):
	@dir=`echo $@ | sed -e 's/check-target-//'`; \
	if [ -f $(TARGET_SUBDIR)/$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $(TARGET_SUBDIR)/$${dir}; \
	    $(MAKE) $(TARGET_FLAGS_TO_PASS) check);\
	else \
	  true; \
	fi

# This rule is used to install the modules which use
# TARGET_FLAGS_TO_PASS.  To build a target install-X means to cd to X
# and make install.
.PHONY: $(INSTALL_TARGET_MODULES)
$(INSTALL_TARGET_MODULES): installdirs
	@dir=`echo $@ | sed -e 's/install-target-//'`; \
	if [ -f $(TARGET_SUBDIR)/$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $(TARGET_SUBDIR)/$${dir}; \
	    $(MAKE) $(TARGET_FLAGS_TO_PASS) install); \
	else \
	  true; \
	fi

# This rule is used to build the modules which use X11_FLAGS_TO_PASS.
# To build a target all-X means to cd to X and make all.
.PHONY: $(ALL_X11_MODULES)
$(ALL_X11_MODULES):
	@dir=`echo $@ | sed -e 's/all-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; \
	   $(MAKE) $(FLAGS_TO_PASS) $(X11_FLAGS_TO_PASS) all); \
	else \
	  true; \
	fi

# This rule is used to check the modules which use X11_FLAGS_TO_PASS.
# To build a target check-X means to cd to X and make all.
.PHONY: $(CHECK_X11_MODULES)
$(CHECK_X11_MODULES):
	@dir=`echo $@ | sed -e 's/check-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; \
	   $(MAKE) $(FLAGS_TO_PASS) $(X11_FLAGS_TO_PASS) check); \
	else \
	  true; \
	fi

# This rule is used to install the modules which use X11_FLAGS_TO_PASS.
# To build a target install-X means to cd to X and make install.
.PHONY: $(INSTALL_X11_MODULES)
$(INSTALL_X11_MODULES): installdirs
	@dir=`echo $@ | sed -e 's/install-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; \
	   $(MAKE) $(FLAGS_TO_PASS) $(X11_FLAGS_TO_PASS) install); \
	else \
	  true; \
	fi

# gcc is the only module which uses GCC_FLAGS_TO_PASS.
.PHONY: all-gcc
all-gcc:
	@if [ -f ./gcc/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd gcc; $(MAKE) $(GCC_FLAGS_TO_PASS) all); \
	else \
	  true; \
	fi

# Building GCC uses some tools for rebuilding "source" files
# like texinfo, bison/byacc, etc.  So we must depend on those.
#
# While building GCC, it may be necessary to run various target
# programs like the assembler, linker, etc.  So we depend on
# those too.
#
# In theory, on an SMP all those dependencies can be resolved
# in parallel.
#
.PHONY: bootstrap bootstrap-lean bootstrap2 bootstrap2-lean bootstrap3 bootstrap3-lean bootstrap4 bootstrap4-lean bubblestrap quickstrap cleanstrap restrap
bootstrap bootstrap-lean bootstrap2 bootstrap2-lean bootstrap3 bootstrap3-lean bootstrap4 bootstrap4-lean bubblestrap quickstrap cleanstrap restrap: all-bootstrap
	@r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}`; export s; \
	$(SET_LIB_PATH) \
	echo "Bootstrapping the compiler"; \
	cd gcc && $(MAKE) $(GCC_FLAGS_TO_PASS) $@
	@r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}`; export s; \
	case "$@" in \
	  *bootstrap4-lean ) \
			msg="Comparing stage3 and stage4 of the compiler"; \
	  		compare=compare3-lean ;; \
	  *bootstrap4 ) msg="Comparing stage3 and stage4 of the compiler"; \
	  		compare=compare3 ;; \
	  *-lean )	msg="Comparing stage2 and stage3 of the compiler"; \
	  		compare=compare-lean ;; \
	  * )		msg="Comparing stage2 and stage3 of the compiler"; \
	  		compare=compare ;; \
	esac; \
	$(SET_LIB_PATH) \
	echo "$$msg"; \
	cd gcc && $(MAKE) $(GCC_FLAGS_TO_PASS) $$compare
	@r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}` ; export s; \
	$(SET_LIB_PATH) \
	echo "Building runtime libraries"; \
	$(MAKE) $(BASE_FLAGS_TO_PASS) $(RECURSE_FLAGS) all

.PHONY: cross
cross: all-texinfo all-bison all-byacc all-binutils all-gas all-ld
	@r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}`; export s; \
	$(SET_LIB_PATH) \
	echo "Building the C and C++ compiler"; \
	cd gcc && $(MAKE) $(GCC_FLAGS_TO_PASS) LANGUAGES="c c++"
	@r=`${PWD}`; export r; \
	s=`cd $(srcdir); ${PWD}` ; export s; \
	$(SET_LIB_PATH) \
	echo "Building runtime libraries"; \
	$(MAKE) $(BASE_FLAGS_TO_PASS) $(RECURSE_FLAGS) \
	  LANGUAGES="c c++" all

.PHONY: check-gcc
check-gcc:
	@if [ -f ./gcc/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd gcc; $(MAKE) $(GCC_FLAGS_TO_PASS) check); \
	else \
	  true; \
	fi

.PHONY: check-c++
check-c++:
	@if [ -f ./gcc/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd gcc; $(MAKE) $(GCC_FLAGS_TO_PASS) check-c++); \
	  $(MAKE) check-target-libstdc++-v3; \
	else \
	  true; \
	fi 

.PHONY: install-gcc
install-gcc:
	@if [ -f ./gcc/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd gcc; $(MAKE) $(GCC_FLAGS_TO_PASS) install); \
	else \
	  true; \
	fi

.PHONY: install-gcc-cross
install-gcc-cross:
	@if [ -f ./gcc/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd gcc; $(MAKE) $(GCC_FLAGS_TO_PASS) LANGUAGES="c c++" install); \
	else \
	  true; \
	fi
# EXPERIMENTAL STUFF
# This rule is used to install the modules which use FLAGS_TO_PASS.
# To build a target install-X means to cd to X and make install.
.PHONY: install-dosrel
install-dosrel: installdirs info
	@dir=`echo $@ | sed -e 's/install-//'`; \
	if [ -f ./$${dir}/Makefile ] ; then \
	  r=`${PWD}`; export r; \
	  s=`cd $(srcdir); ${PWD}`; export s; \
	  $(SET_LIB_PATH) \
	  (cd $${dir}; $(MAKE) $(FLAGS_TO_PASS) install); \
	else \
	  true; \
	fi

install-dosrel-fake:

ALL_GCC = all-gcc
ALL_GCC_C = $(ALL_GCC) all-target-newlib all-target-libgloss
ALL_GCC_CXX = $(ALL_GCC_C) all-target-libstdc++-v3

# This is a list of inter-dependencies among modules.
all-ash:
all-autoconf: all-m4 all-texinfo
all-automake: all-m4 all-texinfo
all-bash:
all-bfd: all-libiberty all-intl
all-binutils: all-libiberty all-opcodes all-bfd all-flex all-bison all-byacc all-intl
all-bison: all-texinfo
configure-target-boehm-gc: $(ALL_GCC_C) configure-target-qthreads
all-byacc:
all-bzip2:
all-db:
all-dejagnu: all-tcl all-expect all-tk
all-diff: all-libiberty
all-etc:
configure-target-examples: $(ALL_GCC_C)
all-expect: all-tcl all-tk
all-fileutils: all-libiberty
all-findutils:
all-find:
all-flex: all-libiberty all-bison all-byacc
all-gas: all-libiberty all-opcodes all-bfd all-intl
all-gawk:
all-gcc: all-bison all-byacc all-binutils all-gas all-ld all-zlib
all-bootstrap: all-libiberty all-texinfo all-bison all-byacc all-binutils all-gas all-ld all-zlib
GDB_TK = @GDB_TK@
all-gdb: all-libiberty all-opcodes all-bfd all-mmalloc all-readline all-bison all-byacc all-sim $(gdbnlmrequirements) $(GDB_TK)
all-gettext:
all-gnuserv:
configure-target-gperf: $(ALL_GCC_CXX)
all-target-gperf: all-target-libiberty all-target-libstdc++-v3
all-gprof: all-libiberty all-bfd all-opcodes all-intl
all-grep: all-libiberty
all-guile:
all-gzip: all-libiberty
all-hello: all-libiberty
all-indent:
all-intl:
all-itcl: all-tcl all-tk
all-ld: all-libiberty all-bfd all-opcodes all-bison all-byacc all-flex all-intl
configure-target-libgloss: $(ALL_GCC)
all-target-libgloss: configure-target-newlib
all-libgui: all-tcl all-tk all-itcl
all-libiberty:

all-build-libiberty: configure-build-libiberty

configure-target-libffi: $(ALL_GCC_C) 
configure-target-libjava: $(ALL_GCC_C) configure-target-zlib configure-target-boehm-gc configure-target-qthreads configure-target-libffi
all-target-libjava: all-fastjar all-target-zlib all-target-boehm-gc all-target-qthreads all-target-libffi
configure-target-libstdc++-v3: $(ALL_GCC_C)
all-target-libstdc++-v3: all-target-libiberty
all-libtool:
configure-target-libf2c: $(ALL_GCC_C)
all-target-libf2c: all-target-libiberty
configure-target-libobjc: $(ALL_GCC_C)
all-target-libobjc: all-target-libiberty
all-m4: all-libiberty all-texinfo
all-make: all-libiberty
all-mmalloc:
configure-target-newlib: $(ALL_GCC)
configure-target-libtermcap: $(ALL_GCC_C)
all-opcodes: all-bfd all-libiberty
all-patch: all-libiberty
all-perl:
all-prms: all-libiberty
configure-target-qthreads: $(ALL_GCC_C)
all-rcs:
all-readline:
all-recode: all-libiberty
all-sed: all-libiberty
all-send-pr: all-prms
all-shellutils:
all-sid: all-tcl all-tk
all-sim: all-libiberty all-bfd all-opcodes all-readline
all-snavigator: all-tcl all-tk all-itcl all-tix all-db all-grep all-libgui
all-tar: all-libiberty
all-tcl:
all-tclX: all-tcl all-tk
all-tk: all-tcl
all-texinfo: all-libiberty
all-textutils:
all-time:
all-tix: all-tcl all-tk
all-wdiff:
configure-target-winsup: $(ALL_GCC_C)
all-target-winsup: all-target-libiberty all-target-libtermcap
all-uudecode: all-libiberty
all-zip:
all-zlib:
configure-target-zlib: $(ALL_GCC_C)
all-fastjar: all-zlib all-libiberty
configure-target-fastjar: configure-target-zlib
all-target-fastjar: configure-target-fastjar all-target-zlib all-target-libiberty
configure-target-libiberty: $(ALL_GCC_C)
configure-target: $(CONFIGURE_TARGET_MODULES)
all-target: $(ALL_TARGET_MODULES)
install-target: $(INSTALL_TARGET_MODULES)
install-gdb: install-tcl install-tk install-itcl install-tix install-libgui
install-sid: install-tcl install-tk

# We put install-opcodes before install-binutils because the installed
# binutils might be on PATH, and they might need the shared opcodes
# library.
install-binutils: install-opcodes

# We put install-tcl before install-itcl because itcl wants to run a
# program on installation which uses the Tcl libraries.
install-itcl: install-tcl


# Dependencies of all-target-foo on configure-target-foo.
[+ FOR target_modules +]all-target-[+module+]: configure-target-[+module+]
[+ ENDFOR target_modules +]

### other supporting targets

MAKEDIRS= \
	$(DESTDIR)$(prefix) \
	$(DESTDIR)$(exec_prefix)
.PHONY: installdirs
installdirs: mkinstalldirs
	$(SHELL) $(srcdir)/mkinstalldirs $(MAKEDIRS)

dir.info: do-install-info
	if [ -f $(srcdir)/texinfo/gen-info-dir ] ; then \
	  $(srcdir)/texinfo/gen-info-dir $(infodir) $(srcdir)/texinfo/dir.info-template > dir.info.new ; \
	  mv -f dir.info.new dir.info ; \
	else true ; \
	fi

dist:
	@echo "Building a full distribution of this tree isn't done"
	@echo "via 'make dist'.  Check out the etc/ subdirectory" 

etags tags: TAGS

# Right now this just builds TAGS in each subdirectory.  emacs19 has the
# ability to use several tags files at once, so there is probably no need
# to combine them into one big TAGS file (like CVS 1.3 does).  We could
# (if we felt like it) have this Makefile write a piece of elisp which
# the user could load to tell emacs19 where all the TAGS files we just
# built are.
TAGS: do-TAGS

# Rebuilding Makefile.in, using autogen.
$(srcdir)/Makefile.in: # $(srcdir)/Makefile.tpl $(srcdir)/Makefile.def
	cd $(srcdir) && autogen Makefile.def

# with the gnu make, this is done automatically.

Makefile: Makefile.in configure.in $(host_makefile_frag) $(target_makefile_frag) $(gcc_version_trigger)
	$(SHELL) ./config.status

#

.NOEXPORT:
MAKEOVERRIDES=

# end of Makefile.in
