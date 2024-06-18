// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"net"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	// ChainNamePrefix is a prefix used for all our iptables chain names.  We include a '-' at
	// the end to reduce clashes with other apps.  Our OpenStack DHCP agent uses prefix
	// 'calico-dhcp-', for example.
	ChainNamePrefix = "cali-"

	// IPSetNamePrefix: similarly for IP sets, we use the following prefix; the IP sets layer
	// adds its own "-" so it isn't included here.
	IPSetNamePrefix = ipsets.IPSetNamePrefix

	ChainFilterInput   = ChainNamePrefix + "INPUT"
	ChainFilterForward = ChainNamePrefix + "FORWARD"
	ChainFilterOutput  = ChainNamePrefix + "OUTPUT"

	ChainRawPrerouting         = ChainNamePrefix + "PREROUTING"
	ChainRawOutput             = ChainNamePrefix + "OUTPUT"
	ChainRawUntrackedFlows     = ChainNamePrefix + "untracked-flows"
	ChainRawBPFUntrackedPolicy = ChainNamePrefix + "untracked-policy"

	ChainFailsafeIn  = ChainNamePrefix + "failsafe-in"
	ChainFailsafeOut = ChainNamePrefix + "failsafe-out"

	ChainNATPrerouting  = ChainNamePrefix + "PREROUTING"
	ChainNATPostrouting = ChainNamePrefix + "POSTROUTING"
	ChainNATOutput      = ChainNamePrefix + "OUTPUT"
	ChainNATOutgoing    = ChainNamePrefix + "nat-outgoing"

	ChainManglePrerouting  = ChainNamePrefix + "PREROUTING"
	ChainManglePostrouting = ChainNamePrefix + "POSTROUTING"

	IPSetIDNATOutgoingAllPools  = "all-ipam-pools"
	IPSetIDNATOutgoingMasqPools = "masq-ipam-pools"

	IPSetIDAllHostNets        = "all-hosts-net"
	IPSetIDAllVXLANSourceNets = "all-vxlan-net"
	IPSetIDThisHostIPs        = "this-host"

	ChainFIPDnat = ChainNamePrefix + "fip-dnat"
	ChainFIPSnat = ChainNamePrefix + "fip-snat"

	ChainCIDRBlock = ChainNamePrefix + "cidr-block"

	PolicyInboundPfx   PolicyChainNamePrefix  = ChainNamePrefix + "pi-"
	PolicyOutboundPfx  PolicyChainNamePrefix  = ChainNamePrefix + "po-"
	ProfileInboundPfx  ProfileChainNamePrefix = ChainNamePrefix + "pri-"
	ProfileOutboundPfx ProfileChainNamePrefix = ChainNamePrefix + "pro-"

	PolicyGroupInboundPrefix  string = ChainNamePrefix + "gi-"
	PolicyGroupOutboundPrefix string = ChainNamePrefix + "go-"

	ChainWorkloadToHost       = ChainNamePrefix + "wl-to-host"
	ChainFromWorkloadDispatch = ChainNamePrefix + "from-wl-dispatch"
	ChainToWorkloadDispatch   = ChainNamePrefix + "to-wl-dispatch"

	ChainDispatchToHostEndpoint          = ChainNamePrefix + "to-host-endpoint"
	ChainDispatchFromHostEndpoint        = ChainNamePrefix + "from-host-endpoint"
	ChainDispatchToHostEndpointForward   = ChainNamePrefix + "to-hep-forward"
	ChainDispatchFromHostEndPointForward = ChainNamePrefix + "from-hep-forward"
	ChainDispatchSetEndPointMark         = ChainNamePrefix + "set-endpoint-mark"
	ChainDispatchFromEndPointMark        = ChainNamePrefix + "from-endpoint-mark"

	ChainForwardCheck        = ChainNamePrefix + "forward-check"
	ChainForwardEndpointMark = ChainNamePrefix + "forward-endpoint-mark"

	ChainSetWireguardIncomingMark = ChainNamePrefix + "wireguard-incoming-mark"

	ChainRpfSkip = ChainNamePrefix + "rpf-skip"

	WorkloadToEndpointPfx   = ChainNamePrefix + "tw-"
	WorkloadPfxSpecialAllow = "ALLOW"
	WorkloadFromEndpointPfx = ChainNamePrefix + "fw-"

	SetEndPointMarkPfx = ChainNamePrefix + "sm-"

	HostToEndpointPfx          = ChainNamePrefix + "th-"
	HostFromEndpointPfx        = ChainNamePrefix + "fh-"
	HostToEndpointForwardPfx   = ChainNamePrefix + "thfw-"
	HostFromEndpointForwardPfx = ChainNamePrefix + "fhfw-"

	RPFChain = ChainNamePrefix + "rpf"

	RuleHashPrefix = "cali:"

	// HistoricNATRuleInsertRegex is a regex pattern to match to match
	// special-case rules inserted by old versions of felix.  Specifically,
	// Python felix used to insert a masquerade rule directly into the
	// POSTROUTING chain.
	//
	// Note: this regex depends on the output format of iptables-save so,
	// where possible, it's best to match only on part of the rule that
	// we're sure can't change (such as the ipset name in the masquerade
	// rule).
	HistoricInsertedNATRuleRegex = `-A POSTROUTING .* felix-masq-ipam-pools .*|` +
		`-A POSTROUTING -o tunl0 -m addrtype ! --src-type LOCAL --limit-iface-out -m addrtype --src-type LOCAL -j MASQUERADE`

	KubeProxyInsertRuleRegex = `-j KUBE-[a-zA-Z0-9-]*SERVICES|-j KUBE-FORWARD`
)

type PolicyDirection string

const (
	PolicyDirectionInbound  PolicyDirection = "inbound"  // AKA ingress
	PolicyDirectionOutbound PolicyDirection = "outbound" // AKA egress
)

// Typedefs to prevent accidentally passing the wrong prefix to the Policy/ProfileChainName()
type (
	PolicyChainNamePrefix  string
	ProfileChainNamePrefix string
)

var (
	// AllHistoricChainNamePrefixes lists all the prefixes that we've used for chains.  Keeping
	// track of the old names lets us clean them up.
	AllHistoricChainNamePrefixes = []string{
		// Current.
		"cali-",

		// Early RCs of Felix 2.1 used "cali" as the prefix for some chains rather than
		// "cali-".  This led to name clashes with the DHCP agent, which uses "calico-" as
		// its prefix.  We need to explicitly list these exceptions.
		"califw-",
		"calitw-",
		"califh-",
		"calith-",
		"calipi-",
		"calipo-",

		// Pre Felix v2.1.
		"felix-",
	}
	// AllHistoricIPSetNamePrefixes, similarly contains all the prefixes we've ever used for IP
	// sets.
	AllHistoricIPSetNamePrefixes = []string{"felix-", "cali"}
	// LegacyV4IPSetNames contains some extra IP set names that were used in older versions of
	// Felix and don't fit our versioned pattern.
	LegacyV4IPSetNames = []string{"felix-masq-ipam-pools", "felix-all-ipam-pools"}

	// Rule previxes used by kube-proxy.  Note: we exclude the so-called utility chains KUBE-MARK-MASQ and co because
	// they are jointly owned by kube-proxy and kubelet.
	KubeProxyChainPrefixes = []string{
		"KUBE-FORWARD",
		"KUBE-SERVICES",
		"KUBE-EXTERNAL-SERVICES",
		"KUBE-NODEPORTS",
		"KUBE-SVC-",
		"KUBE-SEP-",
		"KUBE-FW-",
		"KUBE-XLB-",
	}
)

type RuleRenderer interface {
	StaticFilterTableChains(ipVersion uint8) []*generictables.Chain
	StaticNATTableChains(ipVersion uint8) []*generictables.Chain
	StaticNATPostroutingChains(ipVersion uint8) []*generictables.Chain
	StaticRawTableChains(ipVersion uint8) []*generictables.Chain
	StaticBPFModeRawChains(ipVersion uint8, wgEncryptHost, disableConntrack bool) []*generictables.Chain
	StaticMangleTableChains(ipVersion uint8) []*generictables.Chain
	StaticFilterForwardAppendRules() []generictables.Rule

	WorkloadDispatchChains(map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*generictables.Chain
	WorkloadEndpointToIptablesChains(ifaceName string, epMarkMapper EndpointMarkMapper, adminUp bool, ingressPolicies []*PolicyGroup, egressPolicies []*PolicyGroup, profileIDs []string) []*generictables.Chain
	PolicyGroupToIptablesChains(group *PolicyGroup) []*generictables.Chain

	WorkloadInterfaceAllowChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*generictables.Chain

	EndpointMarkDispatchChains(
		epMarkMapper EndpointMarkMapper,
		wlEndpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint,
		hepEndpoints map[string]proto.HostEndpointID,
	) []*generictables.Chain

	HostDispatchChains(map[string]proto.HostEndpointID, string, bool) []*generictables.Chain
	FromHostDispatchChains(map[string]proto.HostEndpointID, string) []*generictables.Chain
	ToHostDispatchChains(map[string]proto.HostEndpointID, string) []*generictables.Chain
	HostEndpointToFilterChains(
		ifaceName string,
		epMarkMapper EndpointMarkMapper,
		ingressPolicies []*PolicyGroup,
		egressPolicies []*PolicyGroup,
		ingressForwardPolicies []*PolicyGroup,
		egressForwardPolicies []*PolicyGroup,
		profileIDs []string,
	) []*generictables.Chain
	HostEndpointToMangleEgressChains(
		ifaceName string,
		egressPolicies []*PolicyGroup,
		profileIDs []string,
	) []*generictables.Chain
	HostEndpointToRawEgressChain(
		ifaceName string,
		egressPolicies []*PolicyGroup,
	) *generictables.Chain
	HostEndpointToRawChains(
		ifaceName string,
		ingressPolicies []*PolicyGroup,
		egressPolicies []*PolicyGroup,
	) []*generictables.Chain
	HostEndpointToMangleIngressChains(
		ifaceName string,
		preDNATPolicies []*PolicyGroup,
	) []*generictables.Chain

	PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*generictables.Chain
	ProfileToIptablesChains(profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *generictables.Chain)
	ProtoRuleToIptablesRules(pRule *proto.Rule, ipVersion uint8) []generictables.Rule

	MakeNatOutgoingRule(protocol string, action generictables.Action, ipVersion uint8) generictables.Rule
	NATOutgoingChain(active bool, ipVersion uint8) *generictables.Chain

	DNATsToIptablesChains(dnats map[string]string) []*generictables.Chain
	SNATsToIptablesChains(snats map[string]string) []*generictables.Chain
	BlockedCIDRsToIptablesChains(cidrs []string, ipVersion uint8) []*generictables.Chain

	WireguardIncomingMarkChain() *generictables.Chain

	IptablesFilterDenyAction() generictables.Action

	FilterInputChainAllowWG(ipVersion uint8, c Config, allowAction generictables.Action) []generictables.Rule
	ICMPv6Filter(action generictables.Action) []generictables.Rule
}

type DefaultRuleRenderer struct {
	generictables.ActionFactory

	Config
	inputAcceptActions       []generictables.Action
	filterAllowAction        generictables.Action
	mangleAllowAction        generictables.Action
	blockCIDRAction          generictables.Action
	iptablesFilterDenyAction generictables.Action

	NewMatch func() generictables.MatchCriteria

	// wildcard is the symbol to use for wildcard matches.
	wildcard string

	// maxNameLength is the maximum length of a chain name.
	maxNameLength int
}

func (r *DefaultRuleRenderer) IptablesFilterDenyAction() generictables.Action {
	return r.iptablesFilterDenyAction
}

func (r *DefaultRuleRenderer) ipSetConfig(ipVersion uint8) *ipsets.IPVersionConfig {
	if ipVersion == 4 {
		return r.IPSetConfigV4
	} else if ipVersion == 6 {
		return r.IPSetConfigV6
	} else {
		log.WithField("version", ipVersion).Panic("Unknown IP version")
		return nil
	}
}

type Config struct {
	IPSetConfigV4 *ipsets.IPVersionConfig
	IPSetConfigV6 *ipsets.IPVersionConfig

	WorkloadIfacePrefixes []string

	IptablesMarkAccept   uint32
	IptablesMarkPass     uint32
	IptablesMarkScratch0 uint32
	IptablesMarkScratch1 uint32
	IptablesMarkEndpoint uint32
	// IptablesMarkNonCaliEndpoint is an endpoint mark which is reserved
	// to mark non-calico (workload or host) endpoint.
	IptablesMarkNonCaliEndpoint uint32

	KubeNodePortRanges     []numorstring.Port
	KubeIPVSSupportEnabled bool

	OpenStackMetadataIP          net.IP
	OpenStackMetadataPort        uint16
	OpenStackSpecialCasesEnabled bool

	VXLANEnabled   bool
	VXLANEnabledV6 bool
	VXLANPort      int
	VXLANVNI       int

	IPIPEnabled            bool
	FelixConfigIPIPEnabled *bool
	// IPIPTunnelAddress is an address chosen from an IPAM pool, used as a source address
	// by the host when sending traffic to a workload over IPIP.
	IPIPTunnelAddress net.IP
	// Same for VXLAN.
	VXLANTunnelAddress   net.IP
	VXLANTunnelAddressV6 net.IP

	AllowVXLANPacketsFromWorkloads bool
	AllowIPIPPacketsFromWorkloads  bool

	WireguardEnabled            bool
	WireguardEnabledV6          bool
	WireguardInterfaceName      string
	WireguardInterfaceNameV6    string
	WireguardIptablesMark       uint32
	WireguardListeningPort      int
	WireguardListeningPortV6    int
	WireguardEncryptHostTraffic bool
	RouteSource                 string

	IptablesLogPrefix         string
	EndpointToHostAction      string
	IptablesFilterAllowAction string
	IptablesMangleAllowAction string
	IptablesFilterDenyAction  string

	FailsafeInboundHostPorts  []config.ProtoPort
	FailsafeOutboundHostPorts []config.ProtoPort

	DisableConntrackInvalid bool

	NATPortRange                       numorstring.Port
	IptablesNATOutgoingInterfaceFilter string

	NATOutgoingAddress             net.IP
	BPFEnabled                     bool
	BPFForceTrackPacketsFromIfaces []string
	ServiceLoopPrevention          string

	NFTables bool
}

var unusedBitsInBPFMode = map[string]bool{
	"IptablesMarkPass":            true,
	"IptablesMarkScratch1":        true,
	"IptablesMarkEndpoint":        true,
	"IptablesMarkNonCaliEndpoint": true,
}

func (c *Config) validate() {
	// Scan for unset iptables mark bits.  We use reflection so that we have a hope of catching
	// newly-added fields.
	myValue := reflect.ValueOf(c).Elem()
	myType := myValue.Type()
	found := 0
	usedBits := uint32(0)
	for i := 0; i < myValue.NumField(); i++ {
		fieldName := myType.Field(i).Name
		if strings.HasPrefix(fieldName, "IptablesMark") && fieldName != "IptablesMarkNonCaliEndpoint" {
			if c.BPFEnabled && unusedBitsInBPFMode[fieldName] {
				log.WithField("field", fieldName).Debug("Ignoring unused field in BPF mode.")
				continue
			}
			bits := myValue.Field(i).Interface().(uint32)
			if bits == 0 {
				log.WithField("field", fieldName).Panic(
					"IptablesMarkXXX field not set.")
			}
			if usedBits&bits > 0 {
				log.WithField("field", fieldName).Panic(
					"IptablesMarkXXX field overlapped with another's bits.")
			}
			usedBits |= bits
			found++
		}
	}
	if found == 0 {
		// Check the reflection found something we were expecting.
		log.Panic("Didn't find any IptablesMarkXXX fields.")
	}
}

func NewRenderer(config Config) RuleRenderer {
	log.WithField("config", config).Info("Creating rule renderer.")
	config.validate()

	actions := iptables.Actions()
	var reject generictables.Action = iptables.RejectAction{}
	var accept generictables.Action = iptables.AcceptAction{}
	var drop generictables.Action = iptables.DropAction{}
	var ret generictables.Action = iptables.ReturnAction{}

	if config.NFTables {
		actions = nftables.Actions()
		reject = nftables.RejectAction{}
		accept = nftables.AcceptAction{}
		drop = nftables.DropAction{}
		ret = nftables.ReturnAction{}
	}

	newMatchFn := func() generictables.MatchCriteria {
		if config.NFTables {
			return nftables.Match()
		}
		return iptables.Match()
	}

	// First, what should we do when packets are not accepted.
	var iptablesFilterDenyAction generictables.Action
	switch config.IptablesFilterDenyAction {
	case "REJECT":
		log.Info("packets that are not passed by any policy or profile will be rejected.")
		iptablesFilterDenyAction = reject
	default:
		log.Info("packets that are not passed by any policy or profile will be dropped.")
		iptablesFilterDenyAction = drop
	}

	// Convert configured actions to rule slices.
	// First, what should we do with packets that come from workloads to the host itself.
	var inputAcceptActions []generictables.Action
	switch config.EndpointToHostAction {
	case "DROP":
		log.Info("Workload to host packets will be dropped.")
		inputAcceptActions = []generictables.Action{drop}
	case "REJECT":
		log.Info("Workload to host packets will be rejected.")
		inputAcceptActions = []generictables.Action{reject}
	case "ACCEPT":
		log.Info("Workload to host packets will be accepted.")
		inputAcceptActions = []generictables.Action{accept}
	default:
		log.Info("Workload to host packets will be returned to INPUT chain.")
		inputAcceptActions = []generictables.Action{ret}
	}

	// What should we do with packets that are accepted in the forwarding chain
	var filterAllowAction, mangleAllowAction generictables.Action
	switch config.IptablesFilterAllowAction {
	case "RETURN":
		log.Info("filter table allowed packets will be returned to FORWARD chain.")
		filterAllowAction = ret
	default:
		log.Info("filter table allowed packets will be accepted immediately.")
		filterAllowAction = accept
	}
	switch config.IptablesMangleAllowAction {
	case "RETURN":
		log.Info("mangle table allowed packets will be returned to PREROUTING chain.")
		mangleAllowAction = ret
	default:
		log.Info("mangle table allowed packets will be accepted immediately.")
		mangleAllowAction = accept
	}

	// How should we block CIDRs for loop prevention?
	var blockCIDRAction generictables.Action
	switch config.ServiceLoopPrevention {
	case "Drop":
		log.Info("Packets to unknown service IPs will be dropped")
		blockCIDRAction = drop
	case "Reject":
		log.Info("Packets to unknown service IPs will be rejected")
		blockCIDRAction = reject
	default:
		log.Info("Packets to unknown service IPs will be allowed to loop")
	}

	maxNameLength := iptables.MaxChainNameLength
	wildcard := iptables.Wildcard
	if config.NFTables {
		wildcard = nftables.Wildcard
		maxNameLength = nftables.MaxChainNameLength
	}

	return &DefaultRuleRenderer{
		Config:                   config,
		ActionFactory:            actions,
		NewMatch:                 newMatchFn,
		inputAcceptActions:       inputAcceptActions,
		filterAllowAction:        filterAllowAction,
		mangleAllowAction:        mangleAllowAction,
		blockCIDRAction:          blockCIDRAction,
		iptablesFilterDenyAction: iptablesFilterDenyAction,
		wildcard:                 wildcard,
		maxNameLength:            maxNameLength,
	}
}
