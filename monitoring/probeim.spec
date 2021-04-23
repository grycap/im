%define dir /usr/libexec/argo-monitoring/probes/es.upv.grycap.im

Summary: Nagios monitoring tool IM probe.
Name: nagios-plugins-grycap-im
Version: 0.1.0 
Release: 1 
License: GPL version 3, http://www.gnu.org/licenses/gpl-3.0.txt
BuildArch: noarch
Vendor: GRyCAP - Universitat Politecnica de Valencia <micafer1@upv.es>
Requires: python3
Requires: python3-requests
Url: https://github.com/grycap/im/tree/master/monitoring

%description
Nagios monitoring tool IM probe.

%install
install -d -m 0755 $RPM_BUILD_ROOT%{dir}
install -m 0755  %(echo $PWD)/probeim.py $RPM_BUILD_ROOT%{dir}/probeim.py

%files

%defattr(-,root,root,-)
%{dir}/probeim.py
