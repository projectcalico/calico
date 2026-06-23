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

// Package policy provides shared helpers for Felix FV tests that need to
// assert whether a policy is (or is not) programmed in the dataplane. The
// helpers are dataplane-mode aware (BPF, nftables, iptables) so individual
// tests do not have to re-implement the same mode-switching logic.
package policy

import (
	"strings"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
)

// ProgrammedOn returns a function, suitable for use with Eventually, that
// reports whether the named policy is programmed on the given workload
// interface of the given Felix instance.
//
// In BPF mode it inspects the per-interface BPF policy dump for both the
// ingress and egress hooks. The per-interface dump must be used (rather than
// the "all" pseudo-interface) because the debug JSON is keyed by real
// interface name and the command silently produces no output when the file is
// missing; dump errors are tolerated and simply reported as "not programmed
// yet" so the caller's Eventually can retry.
//
// In iptables/nftables mode the policy chain names embed the policy name, so a
// ruleset grep is sufficient.
func ProgrammedOn(felix *infrastructure.Felix, ifaceName, policyName string) func() bool {
	return func() bool {
		if infrastructure.BPFMode() {
			for _, hook := range []string{"ingress", "egress"} {
				out, err := bpfDump(felix, ifaceName, hook)
				if err != nil {
					continue
				}
				if strings.Contains(out, policyName) {
					return true
				}
			}
			return false
		}

		var cmd []string
		if infrastructure.NFTMode() {
			cmd = []string{"nft", "list", "ruleset"}
		} else {
			cmd = []string{"iptables-save", "-t", "filter"}
		}
		out, err := felix.ExecOutput(cmd...)
		if err != nil {
			return false
		}
		return strings.Contains(out, policyName)
	}
}

// bpfDump is an error-tolerant variant of DumpBPF used by ProgrammedOn.
func bpfDump(felix *infrastructure.Felix, iface, hook string) (string, error) {
	if felix.TopologyOptions.EnableIPv6 {
		return felix.ExecOutput("calico-bpf", "-6", "policy", "dump", iface, hook)
	}
	return felix.ExecOutput("calico-bpf", "policy", "dump", iface, hook)
}
