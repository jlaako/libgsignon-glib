ACLOCAL_AMFLAGS = -I m4
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--enable-introspection=yes
SUBDIRS = libgsignon-glib docs examples

if ENABLE_PYTHON
SUBDIRS += pygobject
endif

if ENABLE_TESTS
SUBDIRS += tests
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_in_files = libgsignon-glib.pc.in
pkgconfig_DATA = $(pkgconfig_in_files:.pc.in=.pc)

dist_noinst_DATA = \
	$(libgsignondoc_DATA) \
	m4/introspection.m4

dist-hook: git-changelog-hook

git-changelog-hook: Makefile
	$(AM_V_at)if $(top_srcdir)/build-aux/missing --run git \
		--git-dir=$(top_srcdir)/.git --work-tree=$(top_srcdir) log \
		--no-merges --date=short --pretty='tformat:%cd  %an  <%ae>%n%n%s%n%n%b' | \
		$(SED) -e '/[^  ]/,/^[  ]*$$/ !d' > .ChangeLog.tmp; \
	then mv -f .ChangeLog.tmp "$(top_distdir)/ChangeLog"; \
	else rm -f .ChangeLog.tmp; exit 1; fi

DISTCLEANFILES = \
	$(pkgconfig_DATA)

valgrind:
	cd tests; make valgrind

EXTRA_DIST = dists tools

.PHONY:  git-changelog-hook

lcov: check
	@rm -rf lcov-report
	@lcov -c --directory libgsignon-glib/ --output-file lcov.output
	@genhtml lcov.output --output-directory lcov-report
	@rm lcov.output
	@echo "Coverage report is in file://$(abs_srcdir)/lcov-report/index.html"
