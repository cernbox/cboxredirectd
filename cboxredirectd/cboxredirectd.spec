# 
# cboxredirectd spec file
#

Name: cboxredirectd
Summary: Redirection daemon for CERNBox 
Version: 1.0.6
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides a golang webserver that provides an authentication service for web clients.

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/cboxredirectd
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/cboxredirectd
install -m 755 cboxredirectd	     %buildroot/usr/local/bin/cboxredirectd
install -m 644 cboxredirectd.service    %buildroot/usr/lib/systemd/system/cboxredirectd.service
install -m 644 cboxredirectd.yaml       %buildroot/etc/cboxredirectd/cboxredirectd.yaml
install -m 644 cboxredirectd.logrotate  %buildroot/etc/logrotate.d/cboxredirectd

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/cboxredirectd
/etc/logrotate.d/cboxredirectd
/var/log/cboxredirectd
/usr/lib/systemd/system/cboxredirectd.service
/usr/local/bin/*
%config(noreplace) /etc/cboxredirectd/cboxredirectd.yaml


%changelog
* Mon Jun 28 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.6
* Mon Jun 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.5
* Mon Jun 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.4
* Mon Jun 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.3
* Mon Jun 25 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.2
* Mon Apr 16 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.1
* Thu Apr 12 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 1.0.0
- v1.0.0

