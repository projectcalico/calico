// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dataplanedefs

import (
	"net"
	"regexp"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/kubernetes"

	bpftimeouts "github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector"
	felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
)

// Config is the Linux dataplane's configuration, shared by the main loop and
// its managers.
type Config struct {
	Hostname             string
	NodeZone             string
	IPv6Enabled          bool
	RuleRendererOverride rules.RuleRenderer
	IPIPMTU              int
	VXLANMTU             int
	VXLANMTUV6           int
	VXLANPort            int
	VXLANSrcPortMin      int
	VXLANSrcPortMax      int

	MaxIPSetSize int

	RouteSyncDisabled            bool
	IptablesBackend              string
	IPSetsRefreshInterval        time.Duration
	RouteRefreshInterval         time.Duration
	DeviceRouteSourceAddress     net.IP
	DeviceRouteSourceAddressIPv6 net.IP
	DeviceRouteProtocol          netlink.RouteProtocol
	RemoveExternalRoutes         bool

	// ProgramIPIPClusterRoutes and ProgramNoEncapClusterRoutes record whether Felix, as opposed
	// to confd and BIRD, is responsible for the cluster routes of IPIP and of unencapsulated IP
	// Pools respectively.  NoEncapNeeded already incorporates ProgramNoEncapClusterRoutes (see
	// calc.EncapsulationCalculator.NoEncapNeeded).
	ProgramIPIPClusterRoutes    bool
	ProgramNoEncapClusterRoutes bool
	NoEncapNeeded               bool

	IPForwarding                   string
	TableRefreshInterval           time.Duration
	IptablesPostWriteCheckInterval time.Duration
	IptablesInsertMode             string
	IptablesLockTimeout            time.Duration
	IptablesLockProbeInterval      time.Duration
	XDPRefreshInterval             time.Duration

	FloatingIPsEnabled bool

	LocalSubnetL2Reachability                string
	LocalSubnetL2ReachabilityRefreshInterval time.Duration

	Wireguard wireguard.Config

	NetlinkTimeout time.Duration

	RulesConfig rules.Config

	IfaceMonitorConfig ifacemonitor.Config

	StatusReportingInterval time.Duration

	ConfigChangedRestartCallback func()
	FatalErrorRestartCallback    func(error)

	PostInSyncCallback func()
	HealthAggregator   *health.HealthAggregator
	WatchdogTimeout    time.Duration
	RouteTableManager  *idalloc.IndexAllocator

	DebugSimulateDataplaneHangAfter  time.Duration
	DebugSimulateDataplaneApplyDelay time.Duration

	ExternalNodesCidrs []string

	BPFEnabled                         bool
	BPFOverlayIPOnDevice               bool
	BPFPolicyDebugEnabled              bool
	BPFDisableUnprivileged             bool
	BPFJITHardening                    string
	BPFKubeProxyIptablesCleanupEnabled bool
	BPFLogLevel                        string
	BPFConntrackLogLevel               string
	BPFLogFilters                      map[string]string
	BPFCTLBLogFilter                   string
	BPFExtToServiceConnmark            int
	BPFDataIfacePattern                *regexp.Regexp
	NFTablesFlowTableDataIfacePattern  *regexp.Regexp
	BPFL3IfacePattern                  *regexp.Regexp
	XDPEnabled                         bool
	XDPAllowGeneric                    bool
	BPFConntrackCleanupMode            apiv3.BPFConntrackMode
	BPFConntrackTimeouts               bpftimeouts.Timeouts
	BPFCgroupV2                        string
	BPFConnTimeLBEnabled               bool
	BPFConnTimeLB                      string
	BPFHostNetworkedNAT                string
	BPFNodePortDSREnabled              bool
	BPFDSROptoutCIDRs                  []string
	BPFPSNATPorts                      numorstring.Port
	BPFMapSizeRoute                    int
	BPFMapSizeConntrack                int
	BPFMapSizePerCPUConntrack          int
	BPFMapSizeConntrackScaling         string
	BPFMapSizeConntrackCleanupQueue    int
	BPFMapSizeNATFrontend              int
	BPFMapSizeNATBackend               int
	BPFMapSizeNATAffinity              int
	BPFMapSizeIPSets                   int
	BPFMapSizeIfState                  int
	BPFMapSizeMaglev                   int
	BPFMaglevLUTSize                   int
	BPFIpv6Enabled                     bool
	BPFHostConntrackBypass             bool
	BPFIPFragmentReassemblyEnabled     bool
	BPFEnforceRPF                      string
	BPFDisableGROForIfaces             *regexp.Regexp
	BPFExcludeCIDRsFromNAT             []string
	BPFExportBufferSizeMB              int
	BPFRedirectToPeer                  string
	BPFAttachType                      apiv3.BPFAttachOption
	BPFIPFragTimeout                   time.Duration

	BPFProfiling               string
	KubeProxyMinSyncPeriod     time.Duration
	KubeProxyHealtzPort        int
	SidecarAccelerationEnabled bool
	WorkloadSourceSpoofing     bool

	// Flow logs related fields.
	NfNetlinkBufSize int
	Collector        collector.Collector
	LookupsCache     *calc.LookupsCache
	FlowLogsEnabled  bool

	ServiceLoopPrevention string

	LookPathOverride func(file string) (string, error)

	KubeClientSet kubernetes.Interface

	FeatureDetectOverrides map[string]string
	FeatureGates           map[string]string

	MTUIfacePattern *regexp.Regexp
	RequireMTUFile  bool

	RouteSource string

	IPv4NormalRoutePriority   int
	IPv4ElevatedRoutePriority int
	IPv6NormalRoutePriority   int
	IPv6ElevatedRoutePriority int

	LiveMigrationRouteConvergenceTime time.Duration

	// IPAMClient is the Calico IPAM client used to swap owner attributes
	// when a KubeVirt live migration completes.
	IPAMClient ipam.Interface

	KubernetesProvider felixconfig.Provider

	// For testing purposes - allows unit tests to mock out the creation of the nftables dataplane.
	NewNftablesDataplane nftables.NewNftablesDataplaneFn
}

// CTLBExcludesUDP returns whether the connect-time load balancer leaves UDP to
// the TC programs.
func (config *Config) CTLBExcludesUDP() bool {
	return config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBTCP) &&
		config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATEnabled)
}

// CTLBUDPAffinityTimeout returns how long the connect-time load balancer holds a
// backend affine to an unconnected UDP socket, or 0 if the CTLB does not handle
// UDP on this node. The CTLB uses this so that consecutive datagrams from one
// socket reach one backend; the BPF kube-proxy needs the same value so that its
// affinity map cleanup leaves those entries alone until they really have expired.
func (config *Config) CTLBUDPAffinityTimeout() time.Duration {
	if config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBDisabled) || config.CTLBExcludesUDP() {
		return 0
	}
	// The BPF programs are given the timeout in whole seconds.
	return config.BPFConntrackTimeouts.UDPTimeout.Truncate(time.Second)
}
