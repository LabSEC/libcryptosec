Summary: libcryptosec
Name: libcryptosec
Version: 2.3.0
Release: 1
Source0: %{name}-%{version}.zip
License: GPL
Group: Development/Tools
BuildArch: x86_64
Requires: libp11
BuildRoot: %{_tmppath}/%{name}-%{version}
AutoReqProv: no

%description
libcryptosec is an OpenSSL c++ wrapper with extra features

%prep
%setup -q
%build
make
strip libcryptosec.so

%install
#Copy executables
mkdir -p %{buildroot}%{_libdir}
cp libcryptosec.so %{buildroot}%{_libdir}
mkdir -m 0755 -p %{buildroot}%{_includedir}/libcryptosec
mkdir -m 0755 -p %{buildroot}%{_includedir}/libcryptosec/exception
mkdir -m 0755 -p %{buildroot}%{_includedir}/libcryptosec/certificate
mkdir -m 0755 -p %{buildroot}%{_includedir}/libcryptosec/ec
cp -f include/libcryptosec/*.h %{buildroot}%{_includedir}/libcryptosec/
cp -f include/libcryptosec/exception/* %{buildroot}%{_includedir}/libcryptosec/exception
cp -f include/libcryptosec/certificate/* %{buildroot}%{_includedir}/libcryptosec/certificate
cp -f include/libcryptosec/ec/* %{buildroot}%{_includedir}/libcryptosec/ec

%files
#arquivos contidos no pacote
%defattr(-,root,root)
%{_libdir}/libcryptosec.so
%{_includedir}/libcryptosec/

%changelog

* Wed Dec 19 2018 Lucas Palma <lucas.palma@posgrad.ufsc.br> - 2.3.0
- Adds EdDSA support with custom engine, that registers the NIDs 'ED25519', 'ED448' and 'ED521'. 
- Contributions by Kryptus-sa.

* Tue Dec 07 2018 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.10
- Minor test changes and static compilation option on Makefile.

* Tue Nov 29 2016 Pablo Montezano <pablo.montezano@grad.ufsc.br> - 2.2.9
- Added support to native openssl brainpool curves;
- Must use OpenSSl-1.0.2j with if using Brainpool curves.

* Mon Sep 19 2016 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.8
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Fixes bug with empty DN when using alterSubject.
- Automated test cases for altersubject. 

* Fri Jun 17 2016 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.7
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Add backward compability with previous openssl version  in alterSubject. 

* Wed May 11 2016 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.6
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Fixed bug introduced last update in the alterSubject function.

* Mon Apr 18 2016 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.5
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Fixed bug where it was not possible to use alterSubject to change Name Entries values.

* Mon Aug 17 2015 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.4
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Added functions to Certificate Builder that keep the subject's string format field when building from a RDNSequence.

* Wed Aug 05 2015 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.3
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Added functions to Certificate Builder that keep the subject's string format field when building from a CSR.

* Wed Jul 22 2015 Lucas Perin <lucas.perin@posgrad.ufsc.br> - 2.2.2
- Must use OpenSSL 1.0.1h with Brainpool patch if using Brainpool curves;
- Added functions to Certificate and CRL Builder that keep the subject's string format in the Issuer field.  

* Wed Apr 15 2015 Lucas Petry
- Version 2.2.1 RHEL5.5 (OpenSSL 1.0.2.a)
* Wed Dec 17 2014 Lucas Petry
- Version 2.2.0 RHEL5.5 (OpenSSL 1.0.1.h com patch Brainpool)
* Wed Nov 19 2014 Lucas Petry
- Version 2.1.2 RHEL5.5 (OpenSSL 1.0.1.h)
* Tue Sep 02 2014 Lucas Perin
- Version 2.1.1 RHEL5.5 (OpenSSL 1.0.1.h)
* Mon May 24 2010 Cristian Thiago Moecke
- Version 2.0.1 RHEL5.5 (OpenSSL 1.0.0)
* Thu Dec 08 2009 Cristian Thiago Moecke
- Version 1.5.0
* Wed Jun 17 2009 Cristian Thiago Moecke
- Version 1.3.7
* Thu Mar 31 2008 Marcelo Carlomagno Carlos
- Version 1.3.1
* Thu Mar 01 2007 Marcelo Carlomagno Carlos
- Version 1.2.0
* Tue Nov 11 2006 Marcelo Carlomagno Carlos
- Beta version 1.1.0
