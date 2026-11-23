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
	DoNotTrackOrPreDNATPolicy  Difference = "do-not-track-or-pre-dnat-policy"
	HostEndpoints              Difference = "host-endpoints"
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
}

// KnownDifferences is every case where the pending verdict is known to differ from what a
// dataplane enforces. It is the one list the differential tests and the functional tests leave
// out, so a fix removes its entry here and both start covering the case.
var KnownDifferences = []KnownDifference{
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
		Why: "nftables renders a negated ICMP type and code as type != T and code != C, so it excludes a " +
			"packet only when both differ. iptables, BPF and the evaluator exclude only a packet that has " +
			"both.",
		Generated: true,
	},
	{
		Difference: NegatedICMPWithoutProtocol,
		Where:      []Where{Iptables, BPF},
		Why: "A rule with negated ICMP criteria and no ICMP protocol: iptables renders the ICMP match " +
			"without the protocol, and BPF applies it to the low byte of any destination port. The " +
			"evaluator matches no packet but ICMP with it.",
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
}

// DifferencesAt returns the differences that show at any of the given places. A test that compares
// the evaluator with the oracle passes Evaluator; one that compares pending with enforced verdicts
// on a dataplane passes Evaluator and that dataplane.
func DifferencesAt(where ...Where) []Difference {
	var out []Difference
	for _, d := range KnownDifferences {
		for _, w := range d.Where {
			if slices.Contains(where, w) {
				out = append(out, d.Difference)
				break
			}
		}
	}
	return out
}
