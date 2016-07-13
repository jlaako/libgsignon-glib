#!/bin/sh

exec "$(pwd)/../libtool" --mode=execute $WRAPPER ./signon-glib-testsuite
