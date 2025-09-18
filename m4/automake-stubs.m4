m4_ifndef([AM_INIT_AUTOMAKE],
[AC_DEFUN([AM_INIT_AUTOMAKE],
[  AC_REQUIRE([AC_PROG_INSTALL])
])])

m4_ifndef([AM_CONDITIONAL],
[AC_DEFUN([AM_CONDITIONAL],
[  AC_SUBST([$1_TRUE])
  AC_SUBST([$1_FALSE])
  if $2; then
    $1_TRUE=
    $1_FALSE='#'
  else
    $1_TRUE='#'
    $1_FALSE=
  fi
])])
