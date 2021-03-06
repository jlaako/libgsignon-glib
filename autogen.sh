#!/bin/sh -e

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

(test -f $srcdir/libgsignon-glib.pc.in ) || {
	echo -n "Error: Directory "\`$srcdir\`" does not look like the "
        echo "top-level libgsignon-glib directory."
	exit 1
}

cd "$srcdir"
gtkdocize --copy --flavour no-tmpl
cd "$OLDPWD"
autoreconf --install --force --verbose --warnings=all "$srcdir"
test -n "$NOCONFIGURE" || "$srcdir/configure" "$@"
