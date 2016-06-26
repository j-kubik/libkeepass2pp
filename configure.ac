#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
define(PACKAGE_VERSION_FILE, [m4_esyscmd([tr -d '\n' < VERSION])])

AC_INIT([keepass2pp], [PACKAGE_VERSION_FILE])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER(src/config.h)
AX_PREFIX_CONFIG_H([include/libkeepass2pp/keepass2pp_config.h], [KEEPASS2PP])

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile include/Makefile tests/Makefile keepass2pp.pc])

AC_ARG_ENABLE([assert],
  AS_HELP_STRING([--enable-assert],
    [enable assertions [default="no"]])
)

AC_ARG_ENABLE([verbose-xml-errors],
  AS_HELP_STRING([--enable-verbose-xml-errors],
    [enable verbose descriptions of libxml2 errors. [default="no"]])
)

AC_ARG_WITH([buffer-size],
        [AS_HELP_STRING([--with-buffer-size=size],
            [size of processing pipeline buffer in kB [default=4]])],
        [BUFFER_SIZE=$withval],
        [BUFFER_SIZE=4])

AS_IF([test "x$enable_assert" != "xyes"], [
  AC_DEFINE([NDEBUG], [1], [Disable assert() calls.])
])

AS_IF([test "x$enable_verbose_xml_errors" != "xyes"], [
  AC_DEFINE([VERBOSE_XML_ERRORS], [1], [Enable verbose xml error descriptions.])
])


if @<:@ "$BUFFER_SIZE" -eq "$BUFFER_SIZE" @:>@ 2>/dev/null
then
    :
else
    AC_MSG_ERROR([--with-buffer-size argument must be an integer.], [1])
fi

if @<:@ "$BUFFER_SIZE" -le "0" @:>@
then
    AC_MSG_ERROR([--with-buffer-size argument must equal at least 1.], [1])
fi

if @<:@ "$BUFFER_SIZE" -gt "100" @:>@
then
    AC_MSG_ERROR([--with-buffer-size argument must equal at most 100.], [1])
fi

AC_DEFINE_UNQUOTED([PIPELINE_BUFFER_SIZE], [$BUFFER_SIZE], [Pipeline buffer maximum size.])

VERSION=PACKAGE_VERSION_FILE
VERSION=${VERSION//./:}
AC_SUBST([VERSION])

LT_INIT

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

AX_CXX_COMPILE_STDCXX_14

# Checks for libraries.
PKG_CHECK_MODULES(openssl, openssl >= 1.0)
PKG_CHECK_MODULES(libxml2, libxml-2.0 >= 2.4)
PKG_CHECK_MODULES(zlib, zlib >= 1.2)

# Checks for header files.
AC_HEADER_ASSERT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE



#
# Platform specific setup
#
#############################
AC_CANONICAL_HOST


# Make a conditional for automake.
# There must a better way to do this...
#AM_CONDITIONAL([IS_WIN32], test "x$host_os" = "xmingw32")


# Check for which host we are on and setup a few things
# specifically based on the host
case $host_os in
  mingw32*)
        # Windows compilers should use Winapi. ToDo: maybe a windows API version check?
        # WinAPI is a platform with relatively good compatibility. If version is high enough
        # to support all required functionality, no further checks should be required.
        ;;
  *)
        # Rest of the world uses open source ;)
        
        # optional functions
#        AC_CHECK_FUNCS([mlock munlock])
        AC_CHECK_FUNCS([strptime gmtime_r])
        AC_CHECK_FUNCS([vsprintf])

        # required functions
        AC_CHECK_FUNCS([memset open close fsync timegm gmtime], ,[ AC_MSG_ERROR([Your platform doesn't provide ${ac_func} function.]) ] )
        
        PKG_CHECK_MODULES(libuuid, uuid >= 2.10)
        ;;
esac

AC_OUTPUT
