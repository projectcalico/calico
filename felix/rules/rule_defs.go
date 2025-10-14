// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/felix/ipsets"
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

	ChainEgressDSCP      = ChainNamePrefix + "egress-dscp"
	IPSetIDDSCPEndpoints = "dscp-src-net"

	IPSetIDAllPools             = "all-ipam-pools"
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

	NftablesToWorkloadDispatchMap   = ChainNamePrefix + "to-wl-dispatch"
	NftablesFromWorkloadDispatchMap = ChainNamePrefix + "from-wl-dispatch"

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

	// NFLOGPrefixMaxLength is NFLOG max prefix length which is 64 characters.
	// Ref: http://ipset.netfilter.org/iptables-extensions.man.html#lbDI
	NFLOGPrefixMaxLength = 64

	// NFLOG groups. 1 for inbound and 2 for outbound.  3 for
	// snooping DNS response for domain information.
	NFLOGInboundGroup  uint16 = 1
	NFLOGOutboundGroup uint16 = 2
	NFLOGDomainGroup   uint16 = 3

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

type RuleAction byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleActionAllow RuleAction = 'A'
	RuleActionDeny  RuleAction = 'D'
	// Pass onto the next tier
	RuleActionPass RuleAction = 'P'
)

func (r RuleAction) String() string {
	switch r {
	case RuleActionAllow:
		return "Allow"
	case RuleActionDeny:
		return "Deny"
	case RuleActionPass:
		return "Pass"
	}
	return ""
}

type RuleDir byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleDirIngress RuleDir = 'I'
	RuleDirEgress  RuleDir = 'E'
)

func (r RuleDir) String() string {
	switch r {
	case RuleDirIngress:
		return "Ingress"
	case RuleDirEgress:
		return "Egress"
	}
	return ""
}

type RuleOwnerType byte

const (
	// We define these with specific byte values as we write this value directly into the NFLOG
	// prefix.
	RuleOwnerTypePolicy  RuleOwnerType = 'P'
	RuleOwnerTypeProfile RuleOwnerType = 'R'
)

func (r RuleOwnerType) String() string {
	switch r {
	case RuleOwnerTypePolicy:
		return "Policy"
	case RuleOwnerTypeProfile:
		return "Profile"
	}
	return ""
}

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
