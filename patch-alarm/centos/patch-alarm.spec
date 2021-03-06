Summary: Patch alarm management
Name: patch-alarm
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

%define debug_package %{nil}

BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel
Requires: python-devel
Requires: /bin/bash

%description
StarlingX Platform Patching Alarm Manager

%prep
%setup -n %{name}-%{version}/%{name}

%build
%{__python} setup.py build
%py2_build_wheel

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{python2_sitearch} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

install -m 755 -d %{buildroot}%{_bindir}
install -m 755 -d %{buildroot}%{_sysconfdir}/init.d

install -m 700 ${RPM_BUILD_DIR}/%{name}-%{version}/scripts/bin/patch-alarm-manager \
        %{buildroot}%{_bindir}/patch-alarm-manager

install -m 700 ${RPM_BUILD_DIR}/%{name}-%{version}/scripts/init.d/patch-alarm-manager \
        %{buildroot}%{_sysconfdir}/init.d/patch-alarm-manager

%clean
rm -rf $RPM_BUILD_ROOT 


%files
%defattr(-,root,root,-)
%doc LICENSE
%{python2_sitearch}/patch_alarm
%{python2_sitearch}/patch_alarm-*.egg-info
"%{_bindir}/patch-alarm-manager"
"%{_sysconfdir}/init.d/patch-alarm-manager"

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
