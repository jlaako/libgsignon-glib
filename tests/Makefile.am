## Process this file with automake to produce Makefile.in

TESTS_ENVIRONMENT=TESTDIR=$(top_srcdir)/tests/; export TESTDIR;\
SSO_LOGGING_LEVEL=2 SSO_STORAGE_PATH=/tmp/gsignond \
SSO_SECRET_PATH=/tmp/gsignond SSO_DAEMON_TIMEOUT=5 SSO_IDENTITY_TIMEOUT=5 \
SSO_AUTHSESSION_TIMEOUT=5 G_MESSAGES_DEBUG=all G_SLICE=debug-blocks

VALGRIND_TESTS_DISABLE=

if HAVE_GTESTDBUS
TESTS = signon-glib-testsuite
else
TESTS = signon-glib-test.sh
endif

check_PROGRAMS = signon-glib-testsuite
include $(top_srcdir)/tests/valgrind_common.mk

dist_check_SCRIPTS = signon-glib-test.sh

signon_glib_testsuite_SOURCES = check_signon.c
signon_glib_testsuite_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(DEPS_CFLAGS) \
	$(CHECK_FLAGS)
signon_glib_testsuite_LDADD = \
	$(CHECK_LIBS) \
	$(DEPS_LIBS) \
	$(top_builddir)/libgsignon-glib/libgsignon-glib.la
