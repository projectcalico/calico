%global pypi_name etcd3gw
%global srcname etcd3gw

%if 0%{?fedora}
%global with_python3 1
%endif

Name:           python-%{pypi_name}
Version:        0.2.4.1.5a3157a
Release:        1%{?dist}
Summary:        A python client for etcd3 grpc-gateway

License:        ASL 2.0
URL:            https://github.com/dims/etcd3-gateway
Source0:        https://files.pythonhosted.org/packages/source/e/%{srcname}/%{srcname}-%{version}.tar.gz
BuildArch:      noarch

%description
A python client for etcd3 grpc-gateway. You will need one of the
centos-release-openstack-<version> package to install python dependencies.

%package -n python2-%{pypi_name}
Summary:        A python client for etcd3 grpc-gateway
%{?python_provide:%python_provide python2-%{pypi_name}}

BuildRequires:       python-chardet
BuildRequires:       python2-devel
BuildRequires:       python2-pbr
BuildRequires:       python-setuptools
BuildRequires:       python-urllib3

Requires:       python-chardet
Requires:       python2-devel
Requires:       python2-certifi
Requires:       python2-futures
Requires:       python2-futurist
Requires:       python2-idna
Requires:       python-monotonic
Requires:       python2-pbr
Requires:       python2-requests
Requires:       python2-six
Requires:       python-setuptools
Requires:       python-urllib3

%description -n python2-%{pypi_name}
A python client for etcd3 grpc-gateway


%files -n python2-%{pypi_name}
%license LICENSE
%doc README.md CONTRIBUTING.rst HACKING.rst
%defattr(-,root,root,-)
%{python_sitelib}/%{pypi_name}*


%if 0%{?with_python3}
%package -n python3-%{pypi_name}
Summary:        A python client for etcd3 grpc-gateway
%{?python_provide:%python_provide python3-%{pypi_name}}

BuildRequires:       python3-devel
BuildRequires:       python3-urllib3
BuildRequires:       python3-six
BuildRequires:       python3-setuptools

Requires:    python3-idna
Requires:    python3-urllib3

%description -n python3-%{pypi_name}
A python client for etcd3 grpc-gateway. You'll need one of the
centos-release-openstack-<version> package to install python dependencies.

%endif

%prep
%autosetup -n %{pypi_name}-%{version}

%build
%py2_build

%if 0%{?with_python3}
%py3_build
%endif

%install
%py2_install
