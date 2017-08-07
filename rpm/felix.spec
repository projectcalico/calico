%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           felix
Summary:        Project Calico virtual networking for cloud data centers
Version:        2.4.0
Release:        1%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        felix-%{version}.tar.gz
Source1:        calico-felix.logrotate
Source35:       calico-felix.init
Source45:       calico-felix.service
BuildArch:      x86_64


%define _unpackaged_files_terminate_build 0


%description
Project Calico is an open source solution for virtual networking in
cloud data centers. Its IP-centric architecture offers numerous
advantages over other cloud networking approaches such as VLANs and
overlays, including scalability, efficiency, and simplicity. It is
designed for a wide range of environments including OpenStack,
lightweight Linux containers (LXCs), bare metal, and Network Functions
Virtualization (NFV).


%package -n calico-common
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers

%description -n calico-common
This package provides common files.


%package -n calico-felix
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
%if 0%{?el7}
Requires:       calico-common, conntrack-tools, ipset, iptables, iptables-utils, net-tools, iproute, which
%else
Requires:       calico-common, conntrack-tools, ipset, iptables, net-tools, iproute, which
%endif


%description -n calico-felix
This package provides the Felix component.

%post -n calico-felix
if [ $1 -eq 1 ] ; then
    # Initial installation
%if 0%{?el7}
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl enable calico-felix
    /usr/bin/systemctl start calico-felix
%else
    /sbin/chkconfig -add calico-felix >/dev/null 2>&1 || :
    /etc/init.d/calico-felix start >/dev/null 2>&1 || :
%endif
fi

%preun -n calico-felix
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
%if 0%{?el7}
    /usr/bin/systemctl disable calico-felix
    /usr/bin/systemctl stop calico-felix
%else
    /etc/init.d/calico-felix stop >/dev/null 2>&1 || :
    /sbin/chkconfig -del calico-felix >/dev/null 2>&1 || :
%endif
fi

%postun -n calico-felix
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
%if 0%{?el7}
    /usr/bin/systemctl condrestart calico-felix >/dev/null 2>&1 || :
%else
    /etc/init.d/calico-felix condrestart >/dev/null 2>&1 || :
%endif
fi

%prep
%setup -q

%build

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/usr/bin/
install -m 755 bin/* $RPM_BUILD_ROOT/usr/bin/

# Setup directories
install -d -m 755 %{buildroot}%{_datadir}/calico
install -d -m 755 %{buildroot}%{_sysconfdir}
%if 0%{?el7}
    install -d -m 755 %{buildroot}%{_unitdir}
%else
    install -d -m 755 %{buildroot}%{_sysconfdir}/init.d
%endif

# For EL6, install init script
%if 0%{?el6}
    install -p -m 755 %{SOURCE35} %{buildroot}%{_sysconfdir}/init.d/calico-felix
%endif

# For EL7, install systemd service files
%if 0%{?el7}
    install -p -D -m 755 %{SOURCE45} %{buildroot}%{_unitdir}/calico-felix.service
%endif

# Install config and other non-Python files
install -d %{buildroot}%{_sysconfdir}/calico
install etc/*.cfg.example %{buildroot}%{_sysconfdir}/calico
install -d %{buildroot}%{_datadir}/calico/bird
install etc/bird/*.template %{buildroot}%{_datadir}/calico/bird
install -d %{buildroot}%{_bindir}
install -m 755 etc/*.sh %{buildroot}%{_bindir}

install -d -m 755 %{buildroot}/%{_sysconfdir}/logrotate.d
install    -m 644 %_sourcedir/calico-felix.logrotate    %{buildroot}/%{_sysconfdir}/logrotate.d/calico-felix


%clean
rm -rf $RPM_BUILD_ROOT


%files -n calico-common
%defattr(-,root,root,-)
/usr/bin/calico-diags
/usr/bin/calico-gen-bird-conf.sh
/usr/bin/calico-gen-bird6-conf.sh
/usr/bin/calico-gen-bird-mesh-conf.sh
/usr/bin/calico-gen-bird6-mesh-conf.sh
/usr/share/calico/bird/*
%doc

%files -n calico-felix
%defattr(-,root,root,-)
/usr/bin/calico-felix
/etc/calico/felix.cfg.example
%if 0%{?el7}
    %{_unitdir}/calico-felix.service
%else
    %{_sysconfdir}/init.d/calico-felix
%endif
%{_sysconfdir}/logrotate.d/calico-felix
%doc



%changelog
* Fri Aug 04 2017 Neil Jerram <neil@tigera.io> 2.4.0-1
  - Felix 2.4.0 (from Git commit b891ac5).

    A fully tested and production-ready Felix release, including the
    changes from the following release candidates: 2.4.0-rc1, 2.4.0-rc2.

    A summary of changes since Felix 2.3.0:

    - Skip recalculation of selector matches if selector hasn't changed (#1482).
    - Use updated Typha client API (#1484).
    - Improve testing and test coverage (#1486, #1494, #1496, #1497).
    - Make test suites produce junit reports (#1488).
    - Allow selection of policy allow action (#1492).
    - Implement liveness and readiness endpoints for Felix (#1489).
    - Improve Calico version reporting (#1499).
    - Streamline conntrack state deletions (#1500, #1498).
    - Add release note to PR template (#1502).
    - Add support for multiple CIDRs in a match rule (#1483, #1505).
    - Support using a lock to coordinate iptables programming with other
      software (#1491, #1504).
    - Move logutils functionality to libcalico-go (#1503).
    - Add pre-DNAT policy support (#1506).
    - Update glide pin for logrus (#1509).
    - Allow for time fuzziness in route table UT (#1510).
    - Update to Typha v0.3.0 (#1512).
    - Only report ready after first apply() completes (#1514).
    - Add a grace period before deleting routes (#1518).

* Fri Aug 04 2017 Neil Jerram <neil@tigera.io> 2.3.0-1
  - Felix 2.3.0 (from Git commit 85f9fff).
    [Changes recorded in 2.3.0 tag]
    This is a feature release of Felix, Calico's per-host agent.

    The headline feature in this release is a significant increase in scale when using the
    Kubernetes datastore driver by introducing support for a new daemon, Typha. Typha
    connects to the Kubernetes API server and fans out updates to a number of Felixes.
    By having only a handful of Typha instances connected to the API server instead of
    many Felixes, we place a lot less load on the API server.  In addition, Typha is able
    to squash unimportant updates form the API server, significantly reducing the
    number of mesages each Felix has to handle.

    Typha is disabled by default. The documentation for how to configure Typha and Felix
    together will follow as part of the wider Calico 2.3.0 meta-release.

    This release also contains a number of minor enhancements:

    - Performance: Scan iptables-save output incrementally when calculating hashes.
    - Performance: Disable WithFields logging in the ipsets resync parse loop.
    - Performance: Disable some WithField calls in the inner iptables resync loop.
    - Allow the iptables post-write check interval to be set.
    - Improve diagnostics around ipset restore failures
    - Log ip6tables-save stderr if it fails
    - Convert interval config parameters to time.Duration for increased precision.
    - Rev libcalico-go to v1.4.4 and Typha to v0.2.2.
    - Make JUST_A_MINUTE the default, as it's more useful for devs

    The k8sfv functional tests also got a number of enhancements:

    - Update imports for recent client-go/apimachinery moves
    - Check Felix does not die before end of test
    - mechanism for only running quick tests
    - fix client authorization to API server 1.6
    - Ensure that ip6_tables module is loaded
    - put Typha in the loop.

    The DockerHub and Quay.io `calico/felix` images have been updated.  The `calico/node` image
    based on this release will follow shortly.

    Since we're targetting Kubernetes for this release, we haven't yet updated the OpenStack
    debs and RPMs, those should follow in a few days.
    [Changes recorded in 2.3.0-rc3 tag]
    - Rev libcalico-go and typha to pick up fixes.
    [Changes recorded in 2.3.0-rc2 tag]
    - Update libcalico to v1.4.0
    [Changes recorded in 2.3.0-rc1 tag]
    [Changes recorded in 2.2.2 tag]
    - Pin libcalico-go to v1.2.2 to pick up memory leak fix (#1457).

* Thu May 11 2017 Neil Jerram <neil@tigera.io> 2.2.1-1
  - Felix 2.2.1 (from Git commit b04446b).
    [Changes recorded in 2.2.1 tag]
    - Fix that Felix didn't respect IpInIpEnabled flag (#1452).

* Tue May 09 2017 Neil Jerram <neil@tigera.io> 2.2.0-1
  - Felix 2.2.0 (from Git commit bc4d54d).
    [Changes recorded in 2.2.0 tag]
    - Rev libcalico-go to v1.2.1 for occupancy reduction and bug fixes.
    - Buffer the signal channel. (#1416)
    - Dump memory profile on receipt of SIGUSR1 (#1415)
    - Add support for failsafe UDP ports and allow DNS/DHCP by default. (#1412)
    - Felix is now built with Go v1.8.1 (#1446).
    - Move log writing to background threads to improve robustness if stdout/stderr blocks. (#1389)
    - Move conntrack rules to per-interface chains to avoid matching
      non-Calico packets. (#1424)
    - Squash duplicate host IP updates to avoid churning dataplane (#1445).
    - Disable node polling if IPIP is disabled (#1448).
    - Improvements to Kubernetes-based FV framework.
    - Add option to disable ctstate=INVALID rules for some corner cases/experiments.
    - Fix for spurious ERRORs around missing interfaces.
    - Fix felix_cluster_* metrics not being updated.
    [Changes recorded in 2.2.0-rc4 tag]
    - Rev go-build to v0.6 to pick up go 1.8.1 (#1446).
    - Squash duplicate host IP updates to avoid churning dataplane (#1445).
    - Disable node polling if IPIP is disabled (#1448).
    - Improvements to Kubernetes-based FV framework.
    [Changes recorded in 2.2.0-rc3 tag]
    - Rev libcalico-go to v1.2.1-rc3 (fixes selector validation issue in k8s)
    [Changes recorded in 2.2.0-rc2 tag]
    - Run `docker build` with `--pull`.
    - Bumping libcalico-go to rev with KDD updatest
    [Changes recorded in 2.2.0-rc1 tag]
    - Fix felix_cluster_* metrics not being updated.
    - Buffer the signal channel. (#1416)
    - Dump memory profile on receipt of SIGUSR1 (#1415)
    - Add support for failsafe UDP ports and allow DNS/DHCP by default. (#1412)
    - Rev libcalico-go to v1.2.0 for occupancy reduction. (#1419)
    - Move log writing to background threads to improve robustness if
      stdout/stderr blocks. (#1389)
    - Felix is now built with Go v1.8.1 (#1417).
    - Move conntrack rules to per-interface chains to avoid matching
      non-Calico packets. (#1424)
    - Add option to disable ctstate=INVALID rules for some corner cases/experiments.
    - Fix for spurious ERRORs around missing interfaces.
    [Changes recorded in 2.2.0-pre1 tag]
    - Generalize and explain datastore config construction
    - Allow FELIX_DATASTORETYPE to fully control datastore type
    - Ignore empty configuration values.
    - Various performance and occupancy imporvements
    - Ensure the IP forwarding is enabled on the interfaces we control.
    - Reduce log spam from unconditional rewriting of dispatch chains.
    - Improve stats: add route table stats, swap histograms for summaries.
    - Switch to monotime package.  Remove need for time jump checks.
    - Add more comments to inheritance index.
    - Add FV test for Felix with k8s datastore driver
    - Squash warnings about missing profiles during resync.
    - Add GINKGO_OPTIONS variable to Makefile.

* Wed Mar 29 2017 Neil Jerram <neil@tigera.io> 2.1.1-1
  - Felix 2.1.1 (from Git commit ff29d69).
    [Changes recorded in 2.1.1 tag]
    - Seed Go's RNG.
    - Fix felix.go imports.
    - Rev libcalico-go to 1.1.4, to pick up pod deletion fix (libcalico-go
      #375) when using the Kubernetes datastore driver.
    - Ensure IP forwarding is enabled on the interfaces we control.

* Fri Mar 17 2017 Neil Jerram <neil@tigera.io> 2.1.0-1
  - Felix 2.1.0 (from Git commit fb5b330).
    [Changes recorded in 2.1.0 tag]
    - Port dataplane driver to Golang and move in-process (#1202).
      This has a number of benefits and allowed for a number of
      bugfixes and enhancements to be worked in:

      - Improve dataplane programming performance and decrease
        occupancy by having only one process instead of two.
        It also simplifies the codebase substantially.
      - Simplify deployment (now only one binary needed).
      - Use netlink directly for critical-path route programming
        operations.
      - Move to a synchronization model for route programming.
        Allows for monitoring and restoring routes if they are
        removed.  Allows for clean up of routes that relate to
        orphaned endpoints.
      - Ensure IPIP tunnel device configuration is maintained;
        replace it if it is accidentally removed.
      - Retry iptables/ipset updates in more failure cases to work
        around transient failures of those commands.
      - Switch to a synchronisation model for iptables.  Avoid
        reprogramming rules that haven't changed.  This improves
        performance.
      - Label our iptables rules with a hash to allow rules to be
        identified.  Allows for simpler sync and cleanup.
      - Limit OpenStack special-case rules to deployments with "tap"
        devices (#1020).

    - Add support for host endpoint policies that bypass the conntrack
      table.  Useful for high connection throughput workloads such as
      memcacheDB. (#1284)
    - Fix that setting LogFilePath doesn't prevent early logging (#803)
    - Fix log spam when adding tunl0 device (#1008)
    - Retry ipset commands to deal with transient failures (#1181)
    - Document deb/RPM release process (#1237)
    - Rev libcalico-go to v1.1.3, includes a number of fixes (#1364).
    [Changes recorded in 2.1.0-rc8 tag]
    - Clean up undocumented options
    [Changes recorded in 2.1.0-rc7 tag]
    - Rev libcalico-go to v1.1.2 (#1378).
    - Ignore empty configuration values (#1370).
    [Changes recorded in 2.1.0-rc6 tag]
    - Build the felix RPMS on EL6 as well (#1327)
    - Disable interfaces that are admin down. (#1354)
    - Throttle dataplane updates and opportunistically batch. (#1356)
    - Fix IP address parsing to use net.IP.To4() instead of len(). (#1358)
    - Rev calico/go-build container to v0.4 to pick up patch to runtime.
    - Implement bulk updates to ipsets. (Improves performance.)
    - Implement periodic resyncs of IP sets. (Works around #1347)
    - Add prometheus metrics for exec calls.
    - Rev libcalico-go to 1.1.1. (Includes minor fixes.)
    [Changes recorded in 2.1.0-rc5 tag]
    - Change chain name prefix from "cali" to "cali-" to avoid conflict with DHCP agent. (#1336)
    - Remove unused policy rendering code and simplify. (#1337)
    - Decouple stats collector from usage reporter (#1353).
    - Add log to indicate end of initial sync. (#1350)
    - Ignore removal of non-Calico chain. Fixes spammy warning logs. (#1352)
    [Changes recorded in 2.1.0-rc4 tag]
    - Improve logs around resync.  Downgrade smoe spammy logs.
    - glide: Pin libcalico-go
    [Changes recorded in 2.1.0-rc3 tag]
    Changes since 2.1.0-rc2:

    - Implement loose RPF startup check. (#1322)
    - Add coverage reporting target for golang. (#1323)
    - Handle interfaces being renamed in interface monitor. (#1329)
    - Aggressively re-check iptables after an update. (#1326)
    - Rev libcalico-go to v1.1.0-rc1.
    [Changes recorded in 2.1.0-rc2 tag]
    Changes since 2.1.0-rc1:

    - Add extra prometheus metrics (#1304)
    - Switch to goimports for formatting code (#1305)
    - Add gometalinter and fix a couple of bugs it spotted. (#1306)
    - Increase timeout when doing async calc graph test. (#1312)
    - Pass chain insert mode down to iptables.Table.
    - Implement periodic refresh of route table. (#1313)
    - Explicitly ACCEPT packets that are allowed by host policy. (#1318)
    - Remove flags that are unused in golang dataplane driver. (#1321)
    - Plumb through Ipv6Support flag and ReportingIntervalSecs. (#1320)
    - Add automated check of dependency licenses.
    [Changes recorded in 2.1.0-rc1 tag]
    - Rework EventBuffer as EventSequencer.
    - Change ActiveRulesCalculator to generate dummy drop rules.
    - WiP on iptables writer.
    - Improve logutils: avoid name clash with user-supplied fields.
    - Implement iptables hash resync.  Fix up programming.
    - Rework Felix's main() to pull out external dataplane driver.  Start of internal driver.
    - Add IP set CRUD logic.
    - Minor cleanups.
    - Get IP sets programming in internal DP driver.
    - Refactor to create a Rule and Chain class.
    - Skeleton for policy programming.  Still needs rule rendering!
    - Minor clean-ups.
    - Skeleton for rule rendering logic and other minor tweaks.
    - Implement basic dispatch chain logic.  Add endpointManager.
    - Validate that workload endpoints have names; required by felix.
    - Add drop action to dispatch chains.
    - Add support for hooking kernel chains, use to hook FORWARD chain.
    - Add backoff/panic on iptables failure.
    - Factor out manager objects.
    - Start of profile support.
    - Add dedicated MatchCriteria type for building rules.
    - Add profiles to endpoint chains.
    - Fix failure to delete iptables chains.
    - Switch to RenderInsert() for calculating insert rules.
    - Fix up hash extraction and add UTs.
    - Do deletes right at the end, after cleaning up insertions.
    - WiP on routing table syncer.
    - Add routing table syncer.  Currently poll-based.
    - Skip interfaces that are marked as down when updating routes.
    - Program workload endpoint routes.
    - Minor fixes: - Fix that iptables.Table never set the in-sync flag. - Retry after failing to program routes. (Still need to start monitoring for changes.)
    - Do per-interface proc-sys config.
    - Implement mainline match criteria and fix V6 IP set rendering.
    - Default to using internal dataplane driver.
    - Fix up iptables UT.
    - Add dummy endpoint status reports; should get OpenStack running.
    - Fix name of outbound profile chain.
    - WiP on ipsets cleanup.
    - WiP on route programming retry/monitoring.
    - Implement process status reporting.
    - Add static NAT chains.  Add OpenStack Metadata IP special-case.
    - Add support for setting destination MAC address when programming routes.
    - Add an opaque ID/hash to each rule.
    - Fix that dispatch chains were being calculated from stale data.
    - Fixes to routing table:
    - Add a make patch-script target.
    - Fix copy/paste error in dispatch chain rendering.
    - Add special-case regex used to find old felix rule insertions.
    - Clean ups:
    - Add IPAM pool masquerade support.
    - Self review/go fmt markups.
    - Fix UTs.
    - WiP on IPIP mode.
    - Make WorkloadEndpointChainName usable for host endpoints also
    - Use clearer 'ifaceName' for EndpointChainName arg
    - WiP on IPIP manager
    - Remove label from IP address.
    - Improve comments/logs in IPIP code.
    - Improve handling of ICMPv6: guess the IP version from the protocol version.
    - Add negated match criteria, UTs and fixes.
    - Improve internal dataplane comments.
    - Improve external dataplane commenting.
    - Add log action, log prefix support and DropActionOverride support.
    - Support >15 ports in a match.
    - Tweak cleanup script to remove cali chains.
    - Populate felix-INPUT chain, refine naming, split out wl-to-host chain.
    - Fix UT broken by removal of field.
    - Implement filter output chain, ready for host endpoints to be added.
    - Fix that RouteTable was syncing routes for non-calico interfaces.
    - Add missing return statement.
    - IP sets self-review markups.
    - Shim IP set commands for UT.
    - UTs for ExistenceCache.
    - Organise ipsets classes into files.  Move tests to ipsets_test package.
    - Implement HostDispatchChains
    - Start a test suite for the internal dataplane driver
    - Enhance ifacemonitor to provide address updates as well
    - Checkpoint - ** Coding tasks [4/8]
    - Implement HostEndpointToIptablesChains
    - Link from static input/output chains to host endpoint chains
    - UT fix
    - Implement host endpoint failsafe chains
    - Fixes from running calico-felix by hand
    - Finishing adding host endpoint failsafes
    - Link in cali-INPUT and cali-OUTPUT
    - Add UTs for IPSet object.
    - More UTs for IP sets, cover failure cases.
    - Revert incorrect empty map initializers
    - Code review markups
    - Add mainling UTs for IP set Registry.
    - Add non-coverage UT target (which is lots faster).
    - Making things work - but not sure I need all of these
    - Code review markups
    - Remove conntrack flows when an endpoint is removed.
    - RouteTable and conntrack fixes:
    - Remove optimization from RouteTable that is now incorrect.
    - Code review markups
    - Better error reporting on route sync.
    - Change ifaceAddrs to be a Set
    - Delay status reports: work around OpenStack FV issue.
    - Implement endpoint status reporting.
    - Improve comments and UTs in iptables package.
    - Use host endpoint ID as map key, instead of pointer to ID
    - Code review markups
    - self-review markups
    - Notify iface addrs regardless of iface oper state
    - UT fix
    - Start a UT suite for the 'set' package
    - Improve logging.
    - Work-in-progress on adding iptables UTs.
    - Coverage tests for iptables Table object and minor improvements:
    - Implement periodic iptables refresh.
    - Fix comment.
    - Refresh IPIP tunnel device config on a timer.
    - Mop up some TODOs:
    - Fix lack of log hook in intdataplane test suite.
    - Implement configuration of mark bits, fix mark rendering and add UTs.
    - Fix log leakage during test run.
    - Downgrade spammy route programming failure log to Warning.
    - Fix out-of-date comment.
    - Improve logging when config parsing fails.
    - Shim netlink in routetable package.
    - Mainline tests for RouteTable along with removal of sync conditions.
    - Recheck interface existence to avoid logging errors during tear down.
    - Expand error filtering to more cases to avoid spammy logs on failures.
    - Add more UT for set package.
    - Minor cleanups to routetable.  Remove unused function.
    - Fix that dispatchChains didn't indirect through DropRules().
    - Create structure for ifacemonitor UT
    - Progress on ifacemonitor UT
    - ifacemonitor UT - full coverage except error conditions
    - Call callbacks when link removal is spotted by resync
    - Fix accidental channel write blocking
    - Add comments to explain ifacemonitor testing
    - Address callback now expected when link is down
    - Don't notify addresses after link record deleted
    - Only call address callback when iface addrs are changing
    - Make callback detection channels non-global
    - Remove sleep, make test resilient to slow running
    - Other code review markups
    - Support running Felix on a NAT gateway or router
    - Code review markups.
    - Add UT for conntrack package.
    - Fix occasional test hang: need correct ifIndex on link deletion
    - Add UT for static chains.
    - Cover StaticNATTableChains.
    - Cover rule rendering corner cases.
    - Add UT for per-endpoint chain rendering.
    - Add UT for NAT outgoing rules.
    - Fix test hang: allow for occasional extra addr callback
    - Retry iptables-save to improve robustness and avoid log spam.
    - Code review markups
    - Adjust jittered ticker tests to avoid comparing real sleeps.
    - Fix tracking of best host endpoint match for a host interface
    - Add extra logging around IPIP startup.
    - Fix flap of IPIP tunnel address at start up.
    - Avoid setting link MTU or flags if they're already correct.
    - Write deltas to IP sets where possible.
    - Endpoint manager UT
    - Complete coverage of resolveHostEndpoints
    - Rework host endpoint tests into better ginkgo style
    - Fix: host i/fs map to programmed chains, not host endpoints
    - Fix append bug
    - Add tests with two resolved host interfaces
    - Order rules by i/f name in both host and wl dispatch chains
    - Test which gets used when multiple host eps match an interface
    - Improve representation of host endpoint configuration
    - Code review markups.
    - Shim dataplane in IPIP manager.
    - Add UT for IPIP manager dataplane programming.
    - Add error-case coverage for IPIP manager.
    - Rework ipipManager to deal with transient duplicate IPs.  Add UTs.
    - Honour max IP set size.
    - Add set.FromArray() and Set.AddAll() functions.
    - Add UT for ipsets manager.
    - Add set.From() and use to streamline UTs.
    - Add UT for masquerade manager.
    - UT masquerade manager dirtiness tracking.
    - Add UTs for policy manager.
    - Code review markups.
    - Add UT for status combiner.
    - Really test IPv4 and IPv6 versions of EndpointManager
    - Add go-ut-watch make target.
    - Workload endpoints UT
    - Fix: remove old chains when endpoint's iface changes
    - Introduce TableOptions parameter on NewTable.
    - Rename 'procSysWriter' field to 'writeProcSys'
    - Port ChainInsertMode to golang.
    - Port LogPrefix parameter to Go.
    - Implement tree-based dispatch chains.
    - Code review markups.
    - Code review markups.
    - Floating IPs in golang dataplane driver
    - Code fixes and missing manager reg
    - Adapt existing UTs
    - Code review markups
    - UT and fixes
    - Markups from FV testing:
    - Add host endpoint status reports.
    - Only recalculate the dispatch chains if the data they depend on has changed.
    - Improve commenting/naming.
    - Fix failure to make host endpoint status dirty and add UT.
    - Code review markups.
    - Add marker fields so that action types get traced out in UT output.
    - Include all release notes since last packaging
    - Allow overriding the Git-determined version
    - Felix 2.0.2 Deb/RPM packaging
    - Add support for untracked policies on host endpoints.
    - Rename test file for event sequencer.
    - UTs for untracked policy.
    - Add marker fields so that action types get traced out in UT output.
    - UT and fixes for raw host endpoint chain generation.
    - UT for policy manager.
    - UT for deletion of non-existing chain.
    - Demote overly prominent ifacemonitor warning log
    - Fix that iptables RPF check was being applied for IPv4.
    - Add UT for raw chains.
    - Endpoint manager UT and fixes for notrack.
    - Add additional diags to iptables.Table when it's about to panic.
    - Quick fix for policy/endpoint sequencing issue.  Program all policies to both raw and filter.
    - Code review markups.
    - Remove Python code and update Makefile.
    - Move go code up to main directory.
    - Fix up Golang imports after moving go files.
    - Update Makefile for new location of go files.
    - Guard against running builds from non-git dir.
    - Move go/docs folder into root.
    - Remove gen-version.sh.
    - Remove unneeded line.
    - Tidy up .gitignore.
    - Make iptables mark allocation stateful.
    - Add more UT.
    - Improve dataplane driver API doc.
    - Cleanup README, CONTRIBUTING and unused file.
    - Fix that an empty string for FailsafeIn/OutboundHostPorts was rejected.
    - Fix ifacemonitor UT concurrent map access
    - Check for expected NAT OUTPUT chain
    - Add NAT table insertion for OUTPUT chain
    - Pin libcalico-go to v1.0.2
    - Code review markups
    - Switch to calico/go-build container
    - Pin calico/build to version with Felix's deps.
    - Code review markups.
    - Add datamodel overview to API doc.
    - Remove accidental inclusion of licensecheck code from other branch.
    - Code review markups.
    - Fix heading.

* Wed Jan 25 2017 Neil Jerram <neil@tigera.io> 2.0.2-1
  - Felix 2.0.2 (from Git commit c9e5e3a).
    [Changes recorded in 2.0.2 tag]
    - Really use libcalico-go v1.0.1
    [Changes recorded in 2.0.1 tag]
    - Add support for policing forwarded traffic via host endpoints.
    - Configure an option to append or insert the iptables rules generated by calico-felix.
    - Fix that ipv4_nat was not working (for floating IPs).
    - Fix slow Felix builds.
    - Fix for https://github.com/projectcalico/calicoctl/issues/1419.
    - Fix log spam when we fail to remove routes from a deleted interface.
    - Improve calculation graph comments.
    - Allow using dependencies that need SSH for access.
    - Add make target for patching complete Felix 2.0.x install.
    - Remove etcd version pin from glide.yaml.
    - Use libcalico-go v1.0.1
    [Changes recorded in 2.0.1-rc1 tag]
    - Add support for policing forwarded traffic via host endpoints.
    - Configure an option to append or insert the iptables rules generated by calico-felix.
    - Python-driver-side plumbing for floating IPs
    - Fix that ipv4_nat was not working (for floating IPs)
    - Fix slow Felix builds.
    - Fix logic in static link test.  Move inside container.
    - Fix configure_ipip_device() to pass IPAddress to set_interface_ips().
    - Fix log spam when we fail to remove routes from a deleted interface.
    - Disable make's implicit rules, which slow down the build.
    - Improve calculation graph comments.
    - Felix 2.0.0 Deb/RPM packaging
    - Document how to sign and publish Deb/RPM packages
    - Allow using dependencies that need SSH for access
    - Add make target for patching complete Felix 2.0.x install

* Fri Dec 16 2016 Neil Jerram <neil@tigera.io> 2.0.0-1
  - Felix 2.0.0 (from Git commit de9ffc2).
    - Rev libcalico-go to 1.0.0-rc5.
    - Update to use libcalico-go 1.0.0

* Wed Dec 07 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.rc4
  - Felix 2.0.0-rc4 (from Git commit 706bb9c).
    Felix version 2.0.0-rc4

    - Record Deb/RPM packaging for Felix 2.0.0-rc3
    - If an interface is down, make sure we remove its routes.
    - Make rule generation tolerate missing IP version for ICMP.
    - Skip rules that have CIDRs for different IP versions.
    - Use libcalico-go v1.0.0-rc4
    - Use realpath instead of readlink -f

* Mon Dec 05 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.rc3
  - Felix 2.0.0-rc3 (from Git commit 6bdd086).
    Felix version 2.0.0-rc3

    - Add 5 minutes to initial usage reporting delay
    - Record Felix 2.0.0-rc2 packaging
    - Clean up some minor release process niggles
    - Add a make patch-script target
    - Update to current libcalico-go master

* Thu Dec 01 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.rc2
  - Felix 2.0.0-rc2 (from Git commit a98a7a5).
    - Improve early logging configuration (fixes #1156)
      - Default to logging errors.
      - Provide an override environment variable that allows early logging
        to be turned off or increased. (FELIX_EARLYLOGSEVERITYSCREEN)
    - Allow access to floating IPs from the Calico host as well as from
      further afield.
    - Fix that clusterType was being defaulted when clusterGUID was missing.
    - Incorporate latest libcalico-go improvements (v1.0.0-rc1)
    - Update for current logrus API (fixes #1162)
    - Improve release process for Felix
    - Update libcalico-go to v1.0.0-rc2

* Mon Nov 07 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.3.beta3
  - felix version 2.0.0-0.3.beta3 release
    - Pin logrus to 4b6ea73.
    - Pin libcalico-go to v1.0.0-beta-rc2.
    - Use 'glide up' to update other Go dependencies.

* Fri Nov 04 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.2.beta2
  - felix version 2.0.0-0.2.beta2 release
    - Fix that nat-outgoing was not being honoured.

* Fri Nov 04 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.beta
  - felix version 2.0.0-0.1.beta release
    - Separate Felix into dataplane driver and dataplane-independent
      parts.  (The initial dataplane driver is the one that uses Linux
      iptables and routing commands; this division will allow us to target
      other dataplane implementations.)
    - Rewrite the dataplane-independent part of Felix in Go, for improved
      performance.
    - Update calico-diags to collect Upstart logs.
    - Improve usage reporting: extra stats, better version number.
    - Improve endpoint status reporting.
    - Support Kubernetes backend.
    - Build system improvements.

* Mon Oct 31 2016 Neil Jerram <neil@tigera.io> 1.4.4-1
  - felix version 1.4.4 release
    - Add a retry for deleting conntrack entries.
    - calico-diags: include DevStack logs, if present
    - Make repo branch for coverage diff configurable
    - Add 'this doc has moved' to relevant location in new docs site.
    - Update coveralls badge.
    - IP SAN support in pyinstaller build
    - Add SemaphoreCI badge.
    - Pin pycparser version.

* Mon Oct 03 2016 Neil Jerram <neil@tigera.io> 1.4.3-1
  - calico version 1.4.3 release
    - Support InterfacePrefix having multiple values, to allow hybrid Calico use by
      OpenStack and Kubernetes/Docker/Mesos at the same time.
    - Use PyInstaller-based Felix in calico/felix container build.
    - Update Debian and RPM packaging to stop requiring /etc/calico/felix.cfg, as
      Felix itself no longer requires this file to exist.
    - Update URLs for the renaming of this repository from 'calico' to 'felix'.

* Wed Sep 21 2016 Neil Jerram <neil@tigera.io> 1.4.2-1
  - Calico version 1.4.2
    - Add CircleCI config
    - Fix for baremetal issue (#1071)
    - Allow {inbound,outbound}_rules to be omitted, and handle as []
    - Add IgnoreLooseRPF config parameter
    - Handle interface renaming
    - Documentation improvements:
      - Add EtcdEndpoints to Felix configuration reference.
      - Improve overview documentation about Calico security.
      - Update recommended RPM repo for Calico with Liberty or later
    - Add Usage Reporting to Felix
    - Allow customization of 'etcdctl' for calico-diags
    - Add config option to disable IPv6
    - Reduce EtcdWatcher timeout to 10s
    - Increase urllib3 log severity to avoid log spam from EtcdWatcher

* Fri Jul 22 2016 Neil Jerram <neil@tigera.io> 1.4.0-1
  - Calico version 1.4.0 release
    - Fix example policy in bare metal docs to be valid json
    - Use a different conntrack command to trigger module load.
    - Missing conntrack requires conntrack, not iptables
    - Allow missing or "default" for tier order.
    - Updates for transition to Tigera. (#1055, #1049)
    - specified coverage >=4.02,<4.1 to work around #1057
    - Fix hypothesis test for label validation. (#1060)
    - Default to using system certificate store.
    - Fix that conntrack rules only RETURNed packets rather than ACCEPTing.
    - Fill in missing log substitution (#1066)
    - Add tool to remove all felix iptables/ipsets changes. (#1048)
    - Add option to override DROP rules for debugging policy.
    - Add log action, and ability to log any rule.

* Mon Jun 27 2016 Neil Jerram <neil@tigera.io> 1.4.0-0.3.pre
  - calico pre-release (from Git commit 4b1a68)
    - Add support for securing bare-metal host endpoints.  This is a significant
      change that extends Calico's security model to hosts as well as the
      workloads running on them.
    - InterfacePrefix now defaults to "cali", which is a safe default that happens
      to be the correct value for container systems.
    - MAC address field in endpoint objects is now optional.  If omitted, the MAC
      address is not policed in iptables.
    - Add support for running Felix on RedHat 6.5+ and other distributions with
      glibc 2.12+ and kernel 2.6.32+ via creation of Python 2.7 PyInstaller bundle.
    - Fix iptables programming for interfaces with untypically long names.
    - Documentation fixes and updates.
    - Add Xenial support (systemd configuration for Felix).
    - Update CLA process and copyrights for new sponsor Tigera.
    - Add Dockerfile metadata labels (as defined at label-schema.org).
    - Check that conntrack and iptables are installed at start-of-day.
    - Fix that a config section called [DEFAULT] was ignored.
    - Simplify upstart job. (#1035)
    - Add Timeout to socket.accept(). (#1045)

* Thu Feb 25 2016 Shaun Crampton <shaun@projectcalico.org> 1.3.0-1
  - Felix now parses the etcd snapshot in parallel with the event stream;
    this dramatically increases scale when under load.
  - Various performance and scale improvements.
  - Removed support for Python 2.6.  python-etcd no longer supports 2.6
    as of 0.4.3.
  - Add IpInIpTunnelAddr configuration parameter to allow the IP address of
    the IPIP tunnel device to be set.
  - Add IptablesMarkMask configuration parameter to control which bits are
    used from the iptables forwarding mark.
  - Increase default size of ipsets and make configurable via the
    MaxIpsetSize parameter.
  - Bug fixes, including fixes to NAT when using IPIP mode.

* Tue Jan 12 2016 Matt Dupre <matt@projectcalico.org> 1.3.0-0.6.pre
  - Pre-release of 1.3.0.

* Thu Dec 10 2015 Matt Dupre <matt@projectcalico.org> 1.2.2-1
  - Don't report port deletion as an error status.
  - Improve leader election performance after restart.
  - Catch additional python-etcd exceptions.
  - Reduce election refresh interval.
  - Resolve "Felix dies if interface missing" on Alpine Linux.
  - Rebase to latest 2015.1.2 and 2014.2.4 upstream Ubuntu packages.

* Fri Nov 13 2015 Matt Dupre <matt@projectcalico.org> 1.2.1-1
  - Fix Felix ipset exception when using IPIP.
  - Use iptables protocol numbers not names.
  - Fixes to diagnostics collection scripts.
  - Pin networking-calico pip version.
  - Really delete routes to ns-* devices in pre-Liberty OpenStack.

* Mon Oct 26 2015 Matt Dupre <matt@projectcalico.org> 1.2.0-1
  - Truncate long output from FailedSystemCall exception.
  - Add instructions for use with OpenStack Liberty.

* Mon Oct 19 2015 Matt Dupre <matt@projectcalico.org> 1.2.0-0.2.pre
  - Add liveness reporting to Felix.  Felix now reports its liveness into
    etcd and the neutron driver copies that information to the Neutron DB.
    If Felix is down on a host, Neutron will not try to schedule a VM on
    that host.
  - Add endpoint status reporting to Felix.  Felix now reports the state of
    endpoints into etcd so that the OpenStack plugin can report this
    information into Neutron.  If Felix fails to configure a port, this now
    causes VM creation to fail.
  - Performance enhancements to ipset manipulation.
  - Rev python-etcd dependency to 0.4.1.  Our patched python-etcd version
    (which contains additional patches) is still required.
  - Reduce occupancy of Felix's tag resolution index in the common case
    where IP addresses only have a single owner.
  - Felix now sets the default.rp_filter sysctl to ensure that endpoints
    come up with the Kernel's RPF check enabled by default.
  - Optimize Felix's actor framework to reduce message-passing overhead.

* Tue Sep 08 2015 Neil Jerram <Neil.Jerram@metaswitch.com> 1.1.0
  - Improve the documentation about upgrading a Calico/OpenStack system.
  - Fix compatibility with latest OpenStack code (oslo_config).
  - Use posix_spawn to improve Felix's performance under heavy load.
  - Explicitly use and enable the kernel's reverse path filtering
    function, and remove our iptables anti-spoofing rules, which were not
    as robust.

* Fri Aug 14 2015 Matt Dupre <matt@projectcalico.org> 1.0.0-1
  - Calico version 1.0.0 release

* Tue Aug 10 2015 Matt Dupre <matt@projectcalico.org> 0.29~rc1
  - First release candidate

* Tue Aug 04 2015 Matt Dupre <matt@projectcalico.org> 0.28
  - Felix now restarts if its etcd configuration changes.
  - Felix now periodically refreshes iptables to be robust to other processes
    corrupting its chains.
  - More thorough resynchronization of etcd from the Neutron mechanism driver.
  - Added process-specific information to the diagnostics dumps from Felix.

* Wed Jul 15 2015 Matt Dupre <matt@projectcalico.org> 0.27.1
  - Interim bug-fix release - reinstate DHCP checksum calculation rule.

* Tue Jul 14 2015 Matt Dupre <matt@projectcalico.org> 0.27
  - Limit number of concurrent shell-outs in felix to prevent file descriptor
    exhaustion.
  - Have felix periodically resync from etcd and force-refresh the dataplane.
  - Stop restarting Felix on Ubuntu if it fails more than 5 times in 10 seconds.
  - Move DHCP checksum calculation to Neutron.
  - Get all fixed IPs for a port.

* Mon Jun 29 2015 Cory Benfield <cory@projectcalico.org> 0.26
  - Update and improve security model documentation.
  - Streamline conntrack rules, move them to top-level chains to avoid
    duplication.
  - Narrow focus of input iptables chain so that it only applies to
    Calico-handled traffic.
  - Provide warning log when attempting to use Neutron networks that are not of
    type 'local' or 'flat' with Calico.
  - Handle invalid JSON in IPAM key in etcd.
  - Move all log rotation into logrotate and out of Felix, to prevent conflicts.
  - Change log rotation strategy for logrotate to not rotate small log files.
  - Delay starting the Neutron resynchronization thread until after all the
    necessary state has been configured, to avoid race conditions.
  - Prevent systemd restarting Felix when it is killed by administrators.

* Mon Jun 22 2015 Cory Benfield <cory@projectcalico.org> 0.25
  - Remove stale conntrack entries when an endpoint's IP is removed.
  - #672: Fix bug where profile chain was left empty instead of being
    stubbed out.
  - Improve security between endpoint and host and simplify INPUT chain logic.

* Mon Jun 15 2015 Cory Benfield <cory@projectcalico.org> 0.24
  - Add Felix statistics logging on USR1 signal.
  - Add support for routing over IP-in-IP interfaces in order to make it
    easier to evaluate Calico without reconfiguring underlying network.
  - Reduce felix occupancy by replacing endpoint dictionaries by "struct"
    objects.
  - Allow different hosts to have different interface prefixes for combined
    OpenStack and Docker systems.
  - Add missing support for 0 as a TCP port.
  - Add support for arbitrary IP protocols.
  - Intern various IDs in felix to reduce occupancy.
  - Fix bug where Calico may not propagate security group rule changes from
    OpenStack.
  - Reduced logspam from Calico Mechanism Driver.

* Mon Jun 08 2015 Matt Dupre <matt@projectcalico.org> 0.23
  - Reset ARP configuration when endpoint MAC changes.
  - Forget about profiles when they are deleted.
  - Treat bad JSON as missing data.
  - Add instructions for Kilo on RHEL7.
  - Extend diagnostics script to collect etcd and RabbitMQ information.
  - Improve BIRD config to prevent NETLINK: File Exists log spam.
  - Reduce Felix logging volume.

* Tue Jun 02 2015 Matt Dupre <matt@projectcalico.org> 0.22.1
  - Updated Mechanism driver to specify fixed MAC address for Calico tap
    interfaces.
  - Prevent the possibility of gevent context-switching during garbage collection
    in Felix.
  - Increase the number of file descriptors available to Felix.
  - Firewall input characters in profiles and tags.
  - Implement tree-based dispatch chains to improve IPTables performance with
    many local endpoints.
  - Neutron mechanism driver patches and docs for OpenStack Kilo release.
  - Correct IPv6 documentation for Juno and Kilo.

* Tue May 26 2015 Matt Dupre <matt@projectcalico.org> 0.21
  - Support for running multiple neutron-server instances in OpenStack
  - Support for running neutron-server API workers in OpenStack
  - Calico Mechanism Driver now performs leader election to control state
    resynchronization
  - Extended data model to support multiple security profiles per endpoint
  - Calico Mechanism Driver now attempts to delete empty etcd directories
  - Felix no longer leaks memory when etcd directories it watches are deleted
  - Fix error on port creation where the Mechanism Driver would create, delete,
    and then recreate the port in etcd
  - Handle EtcdKeyNotFound from atomic delete methods
  - Handle etcd cluster ID changes on API actions
  - Fix ipsets cleanup to correctly iterate through stopping ipsets
  - Ensure that metadata is not blocked by over-restrictive rules on outbound
    traffic
  - Updates and clarifications to documentation

* Mon May 18 2015 Matt Dupre <matt@projectcalico.org> 0.20
  - Felix graceful restart support
  - Refactoring and additional unit testing

* Mon May 11 2015 Neil Jerram <neil@projectcalico.org> 0.19
- Further fixes and improvements to Calico components
  - Add script that automates the merging required for a Debian/Ubuntu package
  - Actually save off the endpoints in the endpoint index.
  - Fix reference leak in felix caused by reference cycle.
  - Core review markups and cleanups to ref-tracking code.
  - Add FV-level test that genuinely leaks an exception.

* Tue May 05 2015 Neil Jerram <neil@projectcalico.org> 0.18
- Further fixes and improvements to Calico components
  - Note that RHEL 6.5 instructions are not yet complete
  - Document that Felix requires a config file, or it won't start on RHEL
  - Tidy up line wrapping in RHEL install docs
  - Move utility functions to frules
  - Minor code tidies in dispatch.py
  - Refactor DispatchManager API to not use dicts
  - Add unit tests for DispatchChains
  - Clarify DispatchChains comparison logic
  - Move common validation code to single place.
  - Reinstate etc after overwriting import.
  - Initial code review markups for iptables updater.
  - Code review markups for fiptables.py.
  - Address some RHEL 7 install instruction issues:
  - Minor grammar markups
  - Fix missing import in common
  - Revert "Initial code review markups for iptables updater."
  - Docstrings for UpdateSplitter
  - Remove invalid module reference
  - Retire RHEL 6.5 instructions until we can fix them up, or are convinced there is no demand.
  - Allow for config to be read from config files.
  - Code review feedback
  - changed bgp_export policy to be interface of origin based
  - Ensure no logs are made to screen in mainline with screen logging disabled
  - syntax cleanup, prettified, and default filter added back in.
  - cut and paste doh... - v4 default address used in v6 config file
  - Work in progress on cleanup/support for anycast IPs.
  - Minor fixes: typos and incorrect indexing into dicts.
  - Fixes and cleanups: move updates into lower level methods.
  - Fix missing delete when cleaning up ip address.
  - Minor cleanups and self-review markups.
  - Code review markups.  Track dirty tags and update en-masse.
  - Revert "Revert "Initial code review markups for iptables updater.""
  - Revert rename of _Transaction.updates, it is referenced by IptablesUpdater.
  - Suppress start-of-day iptables-restore errors from CaS-type operations.
  - Tidy up etcd exception logging.
  - Clean up devices exception logging.
  - Add actor life-cycle logging.
  - Add endpoint and profile IDs as comments in iptables chains.
  - Unit tests for the UpdateSplitter
  - RHEL7 doc: fix formatting of Calico repo config
  - RHEL7 doc: don't mention Icehouse
  - Clarify that mapping is dict
  - Update documentation of configuration for Felix.
  - Felix review and some UT (actor, refcount)
  - Replace endpoint ID with tuple that includes host and workload too.
  - Code review markups to refcount.py.
  - Don't process endpoint creation until SOD complete
  - Docs typo fix: incorrect etcd mount in fstab
  - Remove comments
  - Document the new mailing lists
  - Update involved.rst
  - Plugin: provide correct workload ID - fixes #445
  - Plugin: provide correct workload ID - UT updates
  - Update README.md
  - Cleanup README line length
  - Missing sec group retries
  - Close race between resync and access to self.sgs in plugin.
  - Remove race in needed_profile cleanup by using a semaphore.
  - Be resilient to ports disappearing while loading SG members.
  - Protect all access to the security groups dict.
  - Fix up UT environment to include neutron.common.exceptions.
  - Reinstate ability to take file path as command line parameter.
  - Markups to config file specification - tidy exception handling
  - Wording tweaks based on previous version of config documentation.

* Mon Apr 27 2015 Neil Jerram <neil@projectcalico.org> 0.17
- Bug fixes and improvements to Calico components
  - Clean up config loading (code review markups).
  - Remove references to ACL manager from RHEL docs
  - Etcd install instructions for RHEL
  - Be more defensive in etcd polling, catch various HTTP-related exceptions.
  - Fix import order in felix.py to invoke gevent monkey-patch first.
  - Fix missing arg to log message.
  - Remove incorrect comment.
  - Fix plugin to set only icmp_type/code and not port range for ICMP.
  - Add UTs for ICMP rule generation.
  - Add felix support for ICMP code, firewall values.
  - Validate plugin data agsint felix's validation routines.
  - Code review markups.
  - Fix missing continue: use setting of response as a gate in fetcd.py.
  - Increase severity of socket.timeout warning.
  - Add httplib errors into excepts.
  - Code review markups.
  - Update involved.rst
  - Update contribute.rst
  - Tidy up line lengths
  - Revert "Tidy up line lengths"
  - Tidy up line lengths
  - Don't unnecessarily pin versions
  - Fix up a range of commnents.
  - Cleanup toctree for contribution doc
  - Further README cleanup
  - The letter 'a' is tricksy
  - Update contribute.rst
  - RPM Version 0.16
  - Fix RPM version
  - Beef up syslog format, add a couple of additional logs.
  - Debian packaging: python-gevent is not actually needed on controller
  - RPM packaging: remove ACL manager and ZMQ deps; add python-gevent (fixes #435)
  - Packaging: add dependency of Felix on net-tools, for the arp command (fixes #146)
  - Make ipset uperations idempotent.
  - Fix cluster UUID check.  Copy UUID from old client to new, fix typo in arg name.
  - RHEL install markups
  - Fix my own review markups
  - Run etcd on startup
  - After reboots
  - Copy etcd binaries to the right place
  - Update bundle for etcd architecture
  - Use commit id instead of tag in tox dependency
  - Code review markups.
  - Prevent ActiveIpset from recreating ipset after on_unreferenced().
  - Fix missing stdin argument to Popen, beef up diags for ActiveIpset.
  - Code review markups.
  - Update openstack.rst
  - Don't setuid on RHEL 6.5.
  - Wrapping lines
  - Fix numbering in ubuntu-opens-install.rst
  - Add missing jump target to ICMPv6 from endpoint rule.
  - Add "icmp_code" to whitelist of allowed rule fields.
  - Prevent programming of ICMP type 255, which the kernel treats as wildcard.
  - Isolate rule parsing failure to individual rule.

* Tue Apr 21 2015 Matt Dupre <matt@projectcalico.org> 0.16
- First release with etcd

* Fri Apr 10 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.15
- Fix exception in Neutron mechanism driver
- Many documentation changes and additions

* Fri Mar 20 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.14
- Move documentation from separate calico-docs GitHub wiki to Read the Docs
- Neutron mechanism driver fixes

* Fri Mar 06 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.13
- Bug fixes and enhancements to Calico components
  - Remove python-iptables
  - Add EL6.5 support
  - Make Calico components restart after failures
  - Enhance diagnostics gathering script
  - Fix live migration support
  - Many logging, testing and configuration improvements
  - Improve handling of connection timeouts
  - Program proxy NDP

* Fri Feb 13 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.12.1
- Bug fixes and improvements to Calico components
  - Initial refactor of fsocket.
  - Fix issue #133 (lost resync when connection error)
  - Fix restart failure on connection error (bug #97)
  - More timing tests, and fixing of resulting bugs.
  - Tighten up resync testing, with bug fix.
  - ACL Manager fix: Suppress superfluous unsolicited ACLUPDATE messages when nothing has changed
  - Use ip route replace instead of add Fixes timing window when route exists during live migration
  - Fix #164: Disable proxy_delay on taps to avoid delayed proxy ARP response.
  - Better doc and organization for setup code
  - mech_calico: Bind as directed by Neutron server's bind_host config
  - Delete routes when endpoint destroyed
  - Send ENDPOINTDESTROYED rsp even whenendpoint is unknown (fixes #192)
  - More robust exception handling in handle_endpoint{updated|destroyed}
  - Unit testing and diagnostics improvements

* Fri Jan 30 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.11
- Logging improvements and additional unit tests
- ACL Manager fixes
  - Support multiple security groups on a single endpoint
  - ACL Manager stops listening for network updates silently when a rule
    references an empty security group
  - Ensure ACL Manager exits cleanly with a log when worker threads crash

* Fri Jan 23 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.10.3~rc3
- Add Red Hat 7 support
- Many code fixes and enhancements

* Fri Nov 21 2014 Neil Jerram <nj@metaswitch.com> 0.8
- New fixes and enhancements to Felix
  - Clean up code and tidy up ready so that accept default rules can work.
  - Some trivial code tidy left over from the merges.
  - Minor typo fixes.
  - Code review markups.
  - Fix bug where duplicate rules created.
  - Fix up ICMP rules for all ICMP.
  - Various code review markups ready for merging.
  - Unblock outgoing DHCP. Bug in fix to issue38.
  - Fix more issues with issue38 code.  Allow DHCP for IPv6 too Fix up
    getting in / out interfaces backwards
  - Handle ACLUPDATE for deleted endpoint.
  - Config file tweaks. Comment out values matching defaults.
  - Add Metadata IP and Port configuration to Felix
  - Allow address as well as IP for metadata.
  - Ban traffic to the loopback address from VMs (unless for metadata)

* Tue Nov 11 2014 Neil Jerram <nj@metaswitch.com> 0.7
- Update packaging to support source package creation and upload.
  - Implement install steps in setup.py and debian/rules, instead of setup.cfg.

* Fri Nov 07 2014 Neil Jerram <nj@metaswitch.com> 0.6
- Many fixes and enhancements to Felix (the new Calico agent)
  - IP v6 support and minor bug fixes.
  - Minor logging enhancement.
  - Fix dull bug where we never left long enough for resync responses to return on a slow system, ignoring the config values.
  - Many more updates. Apart from intermittent iptables issues, mostly working well. Next action is to fix those.
  - Finally fix dull issue with python-iptables, state and IPv6.
  - Add ep_retry code.
  - Fix small bugette in handling of endpoint retry.
  - Stop using "state" completely - "conntrack" seems more reliable.
  - Fix up bug where we created IPv6 sets as IPv4, then crashed.
  - GETACLUPDATE response may arrive before tap interface created; handle it.
  - Speculative fix for problem with icmp ip6tables rules.
  - Do not get confused during second resync and delete endpoints.
  - Allow for the state of endpoints to be disabled.
  - Subscribe to ACL heartbeats to avoid timing it out continuously.
  - Minor cosmetic edits.
  - More minor refactoring and code tidy up.
  - Remove IPs from an endpoint when they are removed by the API. Also, some minor code tidies.
  - Clean up logic when removing unused IPs.
  - Fix up dull typo in IP removal code.
  - Fix bug where tap address got wrong MAC address.
  - Put in candidate workaround for looping in iptables configuration.
- Packaging: calico-felix needs dependency on python-dev(el)
- RPM packaging fixes
  - Start and stop Calico services on install/uninstall
  - Run Calico services as root, not as 'neutron'
- ACL Manager fix
  - ACL manager was sending a three part message for keepalives. Make it a two part message like the others.

* Mon Oct 27 2014 Neil Jerram <nj@metaswitch.com> 0.5
- New Calico architecture

* Fri Sep 26 2014 Neil Jerram <nj@metaswitch.com> 0.4.1
- Install generator script and template for BIRD6 config

* Tue Sep 16 2014 Neil Jerram <nj@metaswitch.com> 0.4
- Import routes from all ethernet interfaces (in BIRD config)
- Changes to remove unnecessary dependencies on linuxbridge code
- Enhancements for Calico/IPv6 connectivity

* Fri Jul 18 2014 Neil Jerram <nj@metaswitch.com> 0.3
- First RPM-packaged release of Project Calico
