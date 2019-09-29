#!/bin/sh
set -e

test -z "$SRCDIR" && SRCDIR=`dirname "$0"`
test -z "$SRCDIR" && SRCDIR=.

autoreconf --install

if test -z "$NOCONFIGURE"; then
  echo "Running $SRCDIR/configure $@"
  "$SRCDIR/configure" $@
fi

