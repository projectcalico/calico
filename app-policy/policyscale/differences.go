// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package policyscale

import "slices"

// Difference names a rule shape, or a kind of policy or endpoint, for which the pending verdict
// can differ from what a dataplane enforces. The oracle always answers with what the dataplanes
// enforce, so a test that compares against it leaves out the flows that can expose a difference
// at the place it compares.
type Difference string

const (
	OneFamilyNegatedCIDRs      Difference = "one-family-negated-cidrs"
	NegatedICMPTypeAndCode     Difference = "negated-icmp-type-and-code"
	NegatedICMPWithoutProtocol Difference = "negated-icmp-without-protocol"
	SCTPPorts                  Difference = "sctp-ports"
	UnparsedProtocolsOnBPF     Difference = "unparsed-protocols-on-bpf"
	ICMPTypeAndCodeRules       Difference = "icmp-type-and-code-rules"
	ProtocolNamesOnBPF         Difference = "protocol-names-on-bpf"
	DoNotTrackOrPreDNATPolicy  Difference = "do-not-track-or-pre-dnat-policy"
	HostEndpoints              Difference = "host-endpoints"
	NoProfileMatched           Difference = "no-profile-matched"
	NumericICMPWithoutVersion  Difference = "numeric-icmp-without-ip-version"
)

// Where is a place a difference shows: in the evaluator itself, against every dataplane, or on one
// dataplane only.
type Where string

const (
	Evaluator Where = "evaluator"
	Iptables  Where = "iptables"
	Nftables  Where = "nftables"
	BPF       Where = "bpf"
)

// KnownDifference says where a difference shows and why.
type KnownDifference struct {
	Difference Difference
	Where      []Where
	Why        string
	// Generated reports whether the rule-shape preset builds flows that can expose it. The others
	// are listed for tests that build their own policies or endpoints.
	Generated bool
	// WholeRules reports that the dataplane can't apply the rules at all, so a test leaves them out
	// of the policy set (see ShapesParams.LeaveOut) rather than only skipping their flows.
	WholeRules bool
}

// KnownDifferences returns every case where the pending verdict is known to differ from what a
// dataplane enforces. It is the one list the differential tests and the functional tests leave
// out, so a fix removes its entry and both start covering the case. Each call returns a new copy.
func KnownDifferences() []KnownDifference {
	out := make([]KnownDifference, len(knownDifferences))
	for i, d := range knownDifferences {
		d.Where = slices.Clone(d.Where)
		out[i] = d
	}
	return out
}

var knownDifferences = []KnownDifference{
	{
		Difference: OneFamilyNegatedCIDRs,
		Where:      []Where{Evaluator},
		Why: "The dataplanes leave a rule out of an IP family that none of its negated CIDRs belong to. " +
			"The evaluator still applies the rule to that family, so that application layer policy keeps " +
			"denying requests from outside the listed networks.",
		Generated: true,
	},
	{
		Difference: NegatedICMPTypeAndCode,
		Where:      []Where{Nftables},
		Why: "Felix renders a negated ICMP type and code for nftables as icmp type != T code != C, which " +
			"would exclude a packet only when both differ, where iptables, BPF and the evaluator exclude " +
			"only the exact pair (EV-7634). nft rejects that rule, so it never loads (EV-7640, " +
			"ICMPTypeAndCodeRules); the difference shows once nftables loads it.",
		Generated: true,
	},
	{
		Difference: NegatedICMPWithoutProtocol,
		Where:      []Where{Iptables, BPF},
		Why: "A rule with negated ICMP criteria and no ICMP protocol: iptables refuses it, so the " +
			"update that carries it isn't programmed, and BPF applies it to the low byte of any " +
			"destination port, or the whole port for a type and code. The evaluator and nftables " +
			"match only ICMP with it.",
	},
	{
		Difference: NumericICMPWithoutVersion,
		Where:      []Where{Iptables, Nftables},
		Why: "A rule with an ICMP type or code on protocol 1 or 58 given as a number, and no IP " +
			"version, is rendered for both families, and iptables and nftables refuse the other " +
			"family's rule, so the update that carries it isn't programmed.",
	},
	{
		Difference: SCTPPorts,
		Where:      []Where{Iptables, Nftables, BPF},
		Why: "The flow-log collector reads no ports from SCTP packets it logs, so it works out the " +
			"pending verdict of an SCTP flow with ports of zero. BPF reads no SCTP ports either, so " +
			"there a rule with SCTP ports never matches, enforced or pending.",
		Generated: true,
	},
	{
		Difference: UnparsedProtocolsOnBPF,
		Where:      []Where{BPF},
		Why: "BPF parses no transport header for protocols other than TCP, UDP, ICMP and ICMPv6. It logs " +
			"their flows, SCTP and UDP-Lite among them, with protocol 0, and with no pending policies " +
			"on the source side.",
		Generated: true,
	},
	{
		Difference: ICMPTypeAndCodeRules,
		Where:      []Where{Nftables},
		Why: "Felix renders an ICMP type-and-code match for nftables as icmp type T code C, and the " +
			"negated one as icmp type != T code != C, which nft rejects. Felix then can't program its " +
			"table at all, and exits (EV-7640).",
		Generated:  true,
		WholeRules: true,
	},
	{
		Difference: ProtocolNamesOnBPF,
		Where:      []Where{BPF},
		Why: "BPF doesn't know the protocol names ICMPv6 and UDPLite, so a rule that names either never " +
			"matches there, enforced or pending (EV-7633).",
		Generated: true,
	},
	{
		Difference: DoNotTrackOrPreDNATPolicy,
		Where:      []Where{Iptables, Nftables, BPF},
		Why: "When a DoNotTrack or PreDNAT policy that selects a workload is last in a tier, the enforced " +
			"flow log names it for the tier's default action, but the evaluator never sees such " +
			"policies for a workload.",
	},
	{
		Difference: HostEndpoints,
		Where:      []Where{Iptables, Nftables, BPF},
		Why:        "Pending verdicts are worked out for workload endpoints only.",
	},
	{
		Difference: NoProfileMatched,
		Where:      []Where{Evaluator},
		Why: "When a flow gets past every tier and no profile matches it, the dataplane reports a " +
			"deny by no profile, at index 0. The evaluator reports nothing when the endpoint has " +
			"profiles, and a deny under the profile tier's own name, at index -1, when it has none.",
	},
}

// DifferencesAt returns the differences that show at any of the given places. A test that compares
// the evaluator with the oracle passes Evaluator; one that compares pending with enforced verdicts
// on a dataplane passes Evaluator and that dataplane.
func DifferencesAt(where ...Where) []Difference {
	var out []Difference
	for _, d := range knownDifferences {
		for _, w := range d.Where {
			if slices.Contains(where, w) {
				out = append(out, d.Difference)
				break
			}
		}
	}
	return out
}

// LeaveOutAt returns the differences at any of the given places whose rules a dataplane can't
// apply, for ShapesParams.LeaveOut.
func LeaveOutAt(where ...Where) []Difference {
	var out []Difference
	for _, d := range knownDifferences {
		if d.WholeRules && slices.ContainsFunc(d.Where, func(w Where) bool { return slices.Contains(where, w) }) {
			out = append(out, d.Difference)
		}
	}
	return out
}
