m4_ifndef([PKG_PROG_PKG_CONFIG],
[AC_DEFUN([PKG_PROG_PKG_CONFIG],
[  AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
  if test -z "$PKG_CONFIG"; then
    PKG_CONFIG=false
  fi
])])

m4_ifndef([PKG_CHECK_MODULES],
[AC_DEFUN([PKG_CHECK_MODULES],
[  PKG_PROG_PKG_CONFIG
  if test "x$PKG_CONFIG" = "xfalse"; then
    m4_ifval([$4], [$4], [AC_MSG_WARN([pkg-config not found, skipping $1 checks])])
  elif $PKG_CONFIG --exists "$2"; then
    $1_CFLAGS=`$PKG_CONFIG --cflags "$2"`
    $1_LIBS=`$PKG_CONFIG --libs "$2"`
    AC_SUBST([$1_CFLAGS])
    AC_SUBST([$1_LIBS])
    m4_ifval([$3], [$3])
  else
    m4_ifval([$4], [$4], [AC_MSG_WARN([$2 not found via pkg-config])])
  fi
])])
