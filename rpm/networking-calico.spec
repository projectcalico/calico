%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           networking-calico
Summary:        Project Calico networking for OpenStack/Neutron
Epoch:          1
Version:        3.6.0
Release:        1%{?dist}
License:        Apache-2
URL:            http://docs.openstack.org/developer/networking-calico/
Source0:        networking-calico-%{version}.tar.gz
Source45:	calico-dhcp-agent.service
BuildArch:	noarch
Group:          Applications/Engineering
Requires:       python-pbr, python2-etcd3gw


%description
Project Calico is an open source solution for virtual networking in
cloud data centers. It uses IP routing to provide connectivity
between the workloads in a data center that provide or use IP-based
services - whether VMs, containers or bare metal appliances; and
iptables, to impose any desired fine-grained security policy between
those workloads.


%package -n calico-compute
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
%if 0%{?el6}
Requires:       calico-felix, networking-calico, openstack-neutron, iptables, python-argparse
%else
Requires:       calico-felix, networking-calico, openstack-neutron, iptables
%endif


%description -n calico-compute
This package provides the pieces needed on a compute node.

%files -n calico-compute

%post -n calico-compute
if [ $1 -eq 1 ] ; then
    # Initial installation

    # Enable checksum calculation on DHCP responses.  This is needed
    # when sending DHCP responses over the TAP interfaces to guest
    # VMs, as apparently Linux doesn't itself do the checksum
    # calculation in that case.
    iptables -D POSTROUTING -t mangle -p udp --dport 68 -j CHECKSUM --checksum-fill >/dev/null 2>&1 || true
    iptables -A POSTROUTING -t mangle -p udp --dport 68 -j CHECKSUM --checksum-fill

    # Don't reject INPUT and FORWARD packets by default on the compute host.
    iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited >/dev/null 2>&1 || true
    iptables -D FORWARD -j REJECT --reject-with icmp-host-prohibited >/dev/null 2>&1 || true

    # Save current iptables for subsequent reboots.
    iptables-save > /etc/sysconfig/iptables

    # Enable IP forwarding.
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
fi

%preun -n calico-compute
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    :
fi

%postun -n calico-compute
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    :
fi


%package -n calico-dhcp-agent
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
Requires:       networking-calico

%description -n calico-dhcp-agent
This package provides the Calico DHCP agent.

%files -n calico-dhcp-agent
%defattr(-,root,root,-)
/usr/bin/calico-dhcp-agent
%{_unitdir}/calico-dhcp-agent.service

%post -n calico-dhcp-agent
%if 0%{?el7}
if [ $1 -eq 1 ] ; then
    # Initial installation
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl enable calico-dhcp-agent
    /usr/bin/systemctl start calico-dhcp-agent
fi
%endif

%preun -n calico-dhcp-agent
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
%if 0%{?el7}
    /usr/bin/systemctl disable calico-dhcp-agent
    /usr/bin/systemctl stop calico-dhcp-agent
%endif
fi

%postun -n calico-dhcp-agent
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
%if 0%{?el7}
    /usr/bin/systemctl condrestart calico-dhcp-agent >/dev/null 2>&1 || :
%endif
fi


%package -n calico-control
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
Requires:       networking-calico

%description -n calico-control
This package provides the pieces needed on a controller node.

%files -n calico-control


%description
This package installs the networking-calico Calico/Neutron
integration code.

%files
%defattr(-,root,root,-)
%{python_sitelib}/networking_calico*
%doc


%prep
%setup -q


%build
%{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT

# For EL7, install systemd service files
%if 0%{?el7}
    install -d -m 755 %{buildroot}%{_unitdir}
    install -p -D -m 755 %{SOURCE45} %{buildroot}%{_unitdir}/calico-dhcp-agent.service
%endif


%clean
rm -rf $RPM_BUILD_ROOT


%changelog
* Sat Mar 09 2019 Neil Jerram <neil@tigera.io> 1:3.6.0-1
  - networking-calico version 3.6.0 release
    - Streamline datamodel v1 code
    - Adapt frozen DHCP agent code to support Pike
    - Enable native handlers for neutron API operations
    - Add region config, use for status reporting
    - DHCP agent reads subnet info from both old and new paths
    - Write v3 resources with region-dependent namespace
    - Write subnet data with region-aware etcd path
    - Do leader election with region-aware etcd path
    - Validate openstack_region value as a DNS label
    - Generate label with the OpenStack parent project ID for each VM

* Mon Dec 10 2018 Neil Jerram <neil@tigera.io> 1:3.4.0-1
  - networking-calico version 3.4.0 release
    - Rev version number to match current Calico release.

* Fri Oct 26 2018 Neil Jerram <neil@tigera.io> 1:3.3.0-1
  - networking-calico version 3.3.0 release
    - Make client auth setup compatible with mitaka and earlier

* Fri Aug 10 2018 Neil Jerram <neil@tigera.io> 1:3.2.0-1
  - networking-calico version 3.2.0 release
    - Update requirements handling
    - Fix DHCP UT so that it works locally as well as in Zuul CI
    - Handle connectivity loss when reading etcd snapshot
    - Add endpoint labels for project ID and name, and for SG names

* Wed May 30 2018 Neil Jerram <neil@tigera.io> 1:3.1.3-1
  - networking-calico version 3.1.3 release
    - No changes

* Fri May 18 2018 Neil Jerram <neil@tigera.io> 1:3.1.2-1
  - networking-calico version 3.1.2 release
    - Always send high-priority port statuses to Neutron.

* Mon Apr 23 2018 Neil Jerram <neil@tigera.io> 1:3.1.1-1
  - networking-calico version 3.1.1 release
    - Ignore tox/env directories when building debs.
    - Stop updating port status when Felix times out.
    - Improve logs around resyncs.
    - Use a priority queue for port status reports.

* Fri Apr 06 2018 Neil Jerram <neil@tigera.io> 1:3.1.0-1
  - networking-calico version 3.1.0 release
    - Try to trigger compaction during OpenStack CI run
    - Don't log warnings when it is expected for watch to timeout
    - DHCP agent: watch endpoints for this host only
    - Monkey-patch etcd3gw's Watcher to avoid socket leak
    - Chunk up etcd prefix reads into batches.
    - Set default etcd port to 2379
    - DHCP agent: take hostname from Neutron 'host' config

* Tue Mar 20 2018 Neil Jerram <neil@tigera.io> 1:2.0.0-1
  - networking-calico version 2.0.0 release
    - Adapt for new Calico data model (v3)
    - Transition remaining uses of etcdv2 to etcdv3
    - Disambiguate DHCP agent's subnet lookup for an endpoint
    - Model security groups as NetworkPolicy instead of Profiles
    - Ensure that all Calico driver/plugin code logs consistently
    - Change Calico policy and labels prefix
    - Initialize privsep infrastructure for Calico DHCP agent
    - DHCP agent: Handle endpoint with no ipNetworks
    - Fix watch loops to handle compaction

* Fri Oct 06 2017 Neil Jerram <neil@tigera.io> 1:1.4.3-1
  - networking-calico version 1.4.3 release
    - Change _log.warn (now somewhat deprecated) to _log.warning
    - Handle FloatingIP move to neutron.db.models.l3
    - Handle neutron.context move to neutron-lib
    - Fix Neutron common config import error
    - DevStack plugin: fix for recent neutron and devstack changes
    - Fix networking-calico CI (against master OpenStack)
    - Fix networking-calico CI (interface.OPTS move)

* Mon Feb 20 2017 Neil Jerram <neil@tigera.io> 1:1.4.2-1
  - networking-calico version 1.4.2 release
    - Retry fill_dhcp_udp_checksums() on failure
    - For the DevStack plugin, get latest Felix code from Calico 'master' PPA
    - Stop testing with Python 3.4 as well as Python 3.5
    - Replace basestring with six.string_types

* Wed Feb 08 2017 Neil Jerram <neil@tigera.io> 1:1.4.1-1
  - networking-calico version 1.4.1 release
    - Revert setup.py >=1.8 constraint for pbr

* Tue Feb 07 2017 Neil Jerram <neil@tigera.io> 1:1.4.0-1
  - networking-calico version 1.4.0 release
    - Python 3 support
    - Revert "DHCP agent: don't directly connect different subnets"
    - Update DevStack plugin:
      - so that it can be used in OpenStack CI
      - to get Calico agent from PPA instead of building from source (which allows
        using Calico 2.0)
      - for Xenial
    - Get OpenStack CI DevStack/Tempest scenario test passing
    - Use neutron-lib imports where possible instead of neutron
    - Documentation improvements:
      - on Calico semantics
      - on floating IP support
      - on service IPs
      - correct enable_plugin call in DevStack README
      - then move all user-facing docs to http://docs.projectcalico.org/master/ (as
        networking-calico docs have now stopped being published to
        docs.openstack.org)
    - Support and document using Calico with Kuryr
    - Update requirements to match OpenStack global requirements
    - Refactoring to organize imports and clarify compatibility code
    - Show team and repo badges on README
    - Handle recent removal of NeutronManager.get_plugin()
    - Monkey-patch eventlet before importing urllib3
    - Intercept floating IP creation (as well as update) so that floating IPs are
      effective immediately after creation on the Neutron API

* Mon Oct 03 2016 Neil Jerram <neil@tigera.io> 1:1.3.1-1
  - networking-calico version 1.3.1 release
    - Allow Calico with OpenStack to coexist with other orchestrators using Calico.
    - Import utility code from core Calico repo, so that networking-calico becomes
      independent of that repo.
    - Fix Neutron driver to correctly handle etcd connection being temporarily
      stopped or unavailable.

* Wed Sep 21 2016 Neil Jerram <neil@tigera.io> 1:1.3.0-1
  - networking-calico version 1.3.0 release
    - Host routes support
    - Enable DeprecationWarning in test environments
    - Avoid 'No handlers found' warnings in test run output
    - Support providing custom etcd connection parameters for DHCP agent
    - Fix order of arguments in assertEqual
    - DHCP agent log to /var/log/neutron instead of .../calico
    - Enable usage reporting for Calico/OpenStack deployments
    - DevStack bootstrap: Provide Git user name/email config
    - Fix IPv6 router advertisements with multiple networks

* Thu Jul 28 2016 Neil Jerram <neil@tigera.io> 1:1.2.2-1
  - networking-calico version 1.2.2 release
    - Ensure that DHCP agent log file directory exists
    - DHCP agent: don't directly connect different subnets

* Thu Jul 21 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.2.0-1
  - networking-calico version 1.2.0 release
    - py26/py33 are no longer supported by Infra's CI
    - remove python 2.6 trove classifier
    - (beta) Add floating IP support in OpenStack plugin.
    - Update DevStack plugin settings for new Calico core plugin
    - Adapt test code for recent change in common Calico code
    - DevStack plugin: complete IPv6 support
    - DevStack script: better commenting of supported env. variables
    - Support master Neutron code (Mitaka) as well as previous releases
    - Use Neutron master for DevStack and testing, instead of Liberty
    - Improve urllib3/requests unvendoring fix
    - DevStack: Don't run calico-dhcp-agent with sudo
    - Rewrap all docs to 79 columns
    - Add systemd packaging for Calico DHCP agent on Ubuntu/Debian
    - Prefix the profile IDs that we program into etcd
    - Remove dependency on removed neutron.i18n module
    - Debian package version pinning
    - Use proper interface of endpoint class from calico package
    - Fix NAT internal/external IP naming scheme
    - Use network MTU if network_device_mtu not set
    - Gracefully handle absence of network_device_mtu option
    - Add file handler for dhcp-agent log

* Wed Mar 02 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.3-1
  - Change default host for etcd connections from localhost to 127.0.0.1

* Tue Mar 01 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.2-2
  - Make networking-calico package depend on python-pbr

* Mon Feb 29 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.2-1
  - Improve workaround for requests/urllib3 vendoring issue

* Fri Feb 26 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.0-1
  - Doc: explain networking-calico, to an OpenStack-savvy audience
  - Doc: add some implementation notes
  - Move Calico's mechanism driver to networking-calico
  - devstack/bootstrap.sh: Don't set SERVICE_HOST
  - Various leader election improvements:
  - Remove 'sqlalchemy' from requirements.txt
  - Handle EtcdKeyNotFound in addition to EtcdCompareFailed.
  - Reduce election refresh interval, handle EtcdEventIndexCleared.
  - Fix deadlock in status reporting.
  - Adjust tox and testr config to print coverage.
  - Add TLS support to the Neutron driver's etcd connection.
  - Skip all ports in DHCP agents on different hosts
  - Use standard logging in test code, instead of print
  - Decouple status reporting from etcd polling.
  - Prevent concurrent initialisation of the mechanism driver.
  - Update pbr requirement to match global-requirements
  - New DHCP agent driven by etcd data instead of by Neutron RPC
  - Pass a string to delete_onlink_route instead of an IPNetwork
  - Fix handling of endpoint directory deletion
  - Update test-requirements.txt to fix CI.
  - Add service framework around Calico DHCP agent
  - Don't automatically install and use Calico DHCP agent

* Tue Feb 02 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.7.pre7
  - Add service framework around Calico DHCP agent

* Thu Jan 21 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.6.pre1
  - devstack/bootstrap.sh: Don't set SERVICE_HOST
  - Various leader election improvements
  - Remove 'sqlalchemy' from requirements.txt
  - Handle EtcdKeyNotFound in addition to EtcdCompareFailed
  - Fix deadlock in status reporting
  - Reduce election refresh interval, handle EtcdEventIndexCleared
  - Add TLS support to the Neutron driver's etcd connection
  - Skip all ports in DHCP agents on different hosts
  - Decouple status reporting from etcd polling
  - Use standard logging in test code, instead of print
  - New DHCP agent driven by etcd data instead of by Neutron RPC

* Thu Nov 19 2015 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.5.pre1
  - First release of RPM packaging for networking-calico.
