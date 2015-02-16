#define dbus bus type to use [p2p, session, system]
%define dbus_type session

Name:       libgsignon-glib
Summary:    GLib API for the SSO framework
Version:    2.4.0
Release:    1
Group:      System/Libraries
License:    LGPL-2.1
Source:	    %{name}-%{version}.tar.gz
URL: https://01.org/gsso
Requires: dbus-1
Requires: gsignon
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(check)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  gobject-introspection

%description
%{summary}.


%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.


%debug_package


%prep
%setup -q -n %{name}-%{version}
#gtkdocize
#autoreconf -f -i


%build
%configure \
	--enable-python \
	--enable-dbus-type=%{dbus_type}
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING ChangeLog INSTALL NEWS README
%{_libdir}/%{name}.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/%{name}/*.h
%{_libdir}/%{name}.so
%{_libdir}/%{name}.la
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/girepository-1.0/gSignon-1.0.typelib
%{_datadir}/gir-1.0/gSignon-1.0.gir
#%{_datadir}/vala/vapi/gsignon.vapi
%{_datadir}/gtk-doc/html/%{name}/*
%{_bindir}/gsso-example


%changelog
* Thu Feb 12 2015 Imran Zaman <imran.zaman@intel.com>
- Corrected and updated widl file along with web SSO API extension
- Fix typo in reading identity type from variant and updated tests
- Fixed issues found by coverity

* Tue Jul 01 2014 Imran Zaman <imran.zaman@intel.com>
- Release 2.3.0 added reference API implementation

* Thu Mar 06 2014 Jussi Laako <jussi.laako@linux.intel.com>
- Release 2.1.0 including API alignment with libsignon-glib

* Mon Nov 25 2013 Imran Zaman <imran.zaman@intel.com>
- Release 2.0.3 that fixes unit test and spec file bugs 

* Fri Nov 22 2013 Imran Zaman <imran.zaman@intel.com>
- Release 2.0.2 that fixes package licensing info and added docs 

* Mon Jun 24 2013 Imran Zaman <imran.zaman@intel.com>
- Release 2.0.1 that comprises of bug fixes

* Mon Feb 11 2013 Jussi Laako <jussi.laako@linux.intel.com> - 2.0
- Refresh for the libgsignon-glib

