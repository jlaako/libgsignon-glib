lib_LTLIBRARIES = \
	libgsignon-glib.la

libgsignon_glib_la_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(srcdir) \
	-I$(top_builddir) \
	-I$(builddir) \
	$(DEPS_CFLAGS) \
	-Wall -Werror
libgsignon_glib_la_LIBADD = $(DEPS_LIBS)
libgsignon_glib_la_LDFLAGS = \
	-version-info 1:0:0 \
	-export-symbols-regex '^signon_'

nodist_libgsignon_glib_la_SOURCES = \
	signon-marshal.c \
	signon-marshal.h \
	signon-enum-types.h \
	signon-enum-types.c \
	signon-errors-enum.c \
	sso-auth-service-gen.c \
	sso-auth-service-gen.h \
	sso-auth-session-gen.c \
	sso-auth-session-gen.h \
	sso-identity-gen.c \
	sso-identity-gen.h \
	stamp-signon-enum-types.h

BUILT_SOURCES = \
	$(nodist_libgsignon_glib_la_SOURCES) \
	signon-errors-map.c

CLEANFILES = \
	$(BUILT_SOURCES) \
	sso-auth-service-gen-doc-com.google.code.AccountsSSO.gSingleSignOn.AuthService.xml \
	sso-auth-session-gen-doc-com.google.code.AccountsSSO.gSingleSignOn.AuthSession.xml \
	sso-identity-gen-doc-com.google.code.AccountsSSO.gSingleSignOn.Identity.xml

libgsignon_glib_la_SOURCES = \
	signon-auth-service.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-dbus-queue.h \
	signon-auth-session.h \
	signon-internals.h \
	signon-auth-service.c \
	signon-identity-info.c \
	signon-identity.c \
	signon-dbus-queue.c \
	signon-auth-session.c \
	signon-errors.h \
	signon-errors.c \
	signon-utils.h \
	signon-utils.c \
	signon-types.h \
	signon-security-context.h \
	signon-security-context.c \
	sso-auth-service.c \
	sso-auth-service.h

libgsignon_glib_includedir = $(includedir)/libgsignon-glib
libgsignon_glib_include_HEADERS = \
	signon-auth-service.h \
	signon-auth-session.h \
	signon-identity-info.h \
	signon-identity.h \
	signon-security-context.h \
	signon-errors.h \
	signon-enum-types.h \
	signon-glib.h \
	signon-types.h \
	signon-utils.h \
	$(signon_headers)

# Headers with enums to be parsed with glib-mkenums;
# signon-errors.h is handled separately
libgsignon_glib_headers_with_enums = \
	signon-auth-session.h \
	signon-identity-info.h

# This should come from `pkg-config --variable=interfaces_dir dbus-1`
# default is /usr/share/dbus-1/interfaces
INTERFACES_DIR = $(top_srcdir)/libgsignon-glib/interfaces

sso-auth-service-gen.h sso-auth-service-gen.c: $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.AuthService.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-auth-service-gen \
		--generate-docbook sso-auth-service-gen-doc \
		--annotate "com.google.code.AccountsSSO.gSingleSignOn.AuthService" org.gtk.GDBus.C.Name SsoAuthService \
		$<

sso-auth-session-gen.h sso-auth-session-gen.c: $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.AuthSession.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-auth-session-gen \
		--generate-docbook sso-auth-session-gen-doc \
		--annotate "com.google.code.AccountsSSO.gSingleSignOn.AuthSession" org.gtk.GDBus.C.Name SsoAuthSession \
		$<

sso-identity-gen.h sso-identity-gen.c: $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.Identity.xml
	$(AM_V_GEN)gdbus-codegen \
		--generate-c-code sso-identity-gen \
		--generate-docbook sso-identity-gen-doc \
		--annotate "com.google.code.AccountsSSO.gSingleSignOn.Identity" org.gtk.GDBus.C.Name SsoIdentity \
		$<

signon-marshal.h: signon-marshal.list Makefile
	$(AM_V_GEN)glib-genmarshal --header --prefix=_signon_marshal $< > $@

signon-marshal.c: signon-marshal.list Makefile
	$(AM_V_GEN)glib-genmarshal --body --prefix=_signon_marshal $< > $@

signon-enum-types.h: stamp-signon-enum-types.h
	$(AM_V_at)true

stamp-signon-enum-types.h: Makefile \
	$(libgsignon_glib_headers_with_enums) signon-errors.h
	$(AM_V_GEN)( cd $(srcdir) &&  glib-mkenums \
	    --fhead "#ifndef __SIGNON_ENUM_TYPES_H__\n#define __SIGNON_ENUM_TYPES_H__\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
	    --fprod "/* enumerations from \"@filename@\" */\n" \
	    --vhead "GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define SIGNON_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n" \
	    --ftail "G_END_DECLS\n\n#endif /* __SIGNON_ENUM_TYPES_H__ */" \
	    $(libgsignon_glib_headers_with_enums) signon-errors.h ) >> stamp-xgen-geth \
	    && (cmp -s stamp-xgen-geth signon-enum-types.h || cp stamp-xgen-geth signon-enum-types.h ) \
	    && rm -f stamp-xgen-geth \
	    && echo timestamp > $(@F)

signon-enum-types.c: Makefile $(libgsignon_glib_headers_with_enums)
	$(AM_V_GEN)( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n" \
	    --fhead "#include \"signon-identity-info.h\"\n" \
			--fhead "#include \"signon-auth-session.h\"\n" \
			--fhead "#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    $(libgsignon_glib_headers_with_enums) ) > enum-xgen-getc \
	    && cp enum-xgen-getc signon-enum-types.c  \
	    && rm -f enum-xgen-getc

signon-errors-enum.c: Makefile signon-errors.h
	$(AM_V_GEN)( cd $(srcdir) && glib-mkenums \
	    --fhead "#include \"signon-enum-types.h\"\n#include \"signon-errors.h\"\n#include \"signon-internals.h\"\n#define g_intern_static_string(s) (s)\n" \
	    --fprod "\n/* enumerations from \"@filename@\" */" \
	    --ftail "\n#define __SIGNON_ENUM_TYPES_C__\n" \
	    --vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType etype = 0;\n  if (etype == 0) {\n    static const G@Type@Value values[] = {" \
	    --vprod "      { @VALUENAME@, SED@VALUENAME@, \"@valuenick@\" }," \
	    --vtail "      { 0, NULL, NULL }\n    };\n    etype = g_@type@_register_static (g_intern_static_string (\"@EnumName@\"), values);\n  }\n  return etype;\n}\n" \
	    signon-errors.h ) | \
	    $(SED) -e 's/SEDSIGNON_ERROR_\([^,]*\)/SIGNOND_\1_ERR_NAME/' \
	    > errors-xgen-getc \
	    && cp errors-xgen-getc signon-errors-enum.c  \
	    && rm -f errors-xgen-getc

signon-errors-map.c: Makefile signon-errors.h
	$(AM_V_GEN)( cd $(srcdir) && \
	  echo "static const GDBusErrorEntry signon_error_entries[] = {" && \
	  grep "^ *SIGNON_ERROR_" signon-errors.h | \
	    $(SED) -e 's/SIGNON_ERROR_\([A-Z_0-9]*\).*/{ SIGNON_ERROR_\1, SIGNOND_\1_ERR_NAME },/' && \
	  echo -e "};\n" ) > signon-errors-map.c

dist_noinst_DATA = \
	signon-marshal.list \
	stamp-signon-enum-types.h

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
introspection_sources = \
	signon-security-context.c \
	signon-security-context.h \
	signon-auth-service.c \
	signon-auth-service.h \
	signon-auth-session.c \
	signon-auth-session.h \
	signon-enum-types.h \
	signon-enum-types.c \
	signon-errors.c \
	signon-errors.h \
	signon-identity-info.c \
	signon-identity-info.h \
	signon-identity.c \
	signon-identity.h

gSignon-1.0.gir: libgsignon-glib.la
gSignon_1_0_gir_INCLUDES = GObject-2.0 Gio-2.0
gSignon_1_0_gir_SCANNERFLAGS = \
	--identifier-prefix=Signon \
	--symbol-prefix=signon \
	--c-include="libgsignon-glib/signon-glib.h" \
	--warn-all
gSignon_1_0_gir_CFLAGS = \
	-I$(top_srcdir) \
	$(DEPS_CFLAGS)
gSignon_1_0_gir_LIBS = libgsignon-glib.la
gSignon_1_0_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += gSignon-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

EXTRA_DIST =
# Vala bindings
if ENABLE_VAPIGEN
-include $(VAPIGEN_MAKEFILE)
libgsignon-glib.vapi: gSignon-1.0.gir libgsignon-glib.deps

VAPIGEN_VAPIS = libgsignon-glib.vapi

libgsignon_glib_vapi_DEPS = gio-2.0 glib-2.0
libgsignon_glib_vapi_METADATADIRS = $(srcdir)
libgsignon_glib_vapi_FILES = gSignon-1.0.gir

vapidir = $(datadir)/vala/vapi
vapi_DATA = $(VAPIGEN_VAPIS) $(VAPIGEN_VAPIS:.vapi=.deps)

CLEANFILES += $(VAPIGEN_VAPIS)
EXTRA_DIST += libgsignon-glib.deps gSignon-1.0.metadata
endif

dbusinterfacesdir = $(DBUS_INTERFACES_DIR)
dbusinterfaces_DATA = \
    $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.AuthService.xml\
    $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.AuthSession.xml\
    $(INTERFACES_DIR)/com.google.code.AccountsSSO.gSingleSignOn.Identity.xml

EXTRA_DIST += interfaces

