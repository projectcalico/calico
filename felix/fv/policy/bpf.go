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

package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/proto"
)

// DumpBPF returns the human-readable BPF policy program dump for the given
// interface and hook ("ingress"/"egress"). It asserts that the dump command
// succeeds; use it inside an Eventually when the program may not yet be
// attached.
func DumpBPF(felix *infrastructure.Felix, iface, hook string) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "policy", "dump", iface, hook)
	} else {
		out, err = felix.ExecOutput("calico-bpf", "policy", "dump", iface, hook)
	}
	Expect(err).NotTo(HaveOccurred())
	return out
}

// DumpBPFAsm is like DumpBPF but includes the generated assembly.
func DumpBPFAsm(felix *infrastructure.Felix, iface, hook string) string {
	var (
		out string
		err error
	)

	if felix.TopologyOptions.EnableIPv6 {
		out, err = felix.ExecOutput("calico-bpf", "-6", "policy", "dump", iface, hook, "--asm")
	} else {
		out, err = felix.ExecOutput("calico-bpf", "policy", "dump", iface, hook, "--asm")
	}
	Expect(err).NotTo(HaveOccurred())
	return out
}

// WaitForGlobalNetworkPolicyBPF waits for the given GlobalNetworkPolicy to
// appear in the BPF policy dump for the given interface and hook.
func WaitForGlobalNetworkPolicyBPF(felix *infrastructure.Felix, iface, hook, policyName string) string {
	search := fmt.Sprintf("Policy: GlobalNetworkPolicy %s", policyName)
	return WaitForBPF(felix, iface, hook, search)
}

// WaitForNetworkPolicyBPF waits for the given NetworkPolicy in the given
// namespace to appear in the BPF policy dump for the given interface and hook.
func WaitForNetworkPolicyBPF(felix *infrastructure.Felix, iface, hook, ns, policyName string) string {
	search := fmt.Sprintf("Policy: NetworkPolicy %s/%s", ns, policyName)
	return WaitForBPF(felix, iface, hook, search)
}

// WaitForBPF waits for the given search string to appear in the BPF policy
// dump for the given interface and hook, returning the matching dump.
func WaitForBPF(felix *infrastructure.Felix, iface, hook, search string) string {
	out := ""
	EventuallyWithOffset(2, func() string {
		out = DumpBPF(felix, iface, hook)
		return out
	}, "5s", "200ms").Should(ContainSubstring(search))

	return out
}

// RuleProgrammedBPF reports whether a rule with the given action is programmed
// for polName in the BPF policy debug info for the given interface and hook.
func RuleProgrammedBPF(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkProgrammedBPF(felix, iface, hook, polName, action, isWorkload, "", proto.IPVersion_IPV4)
}

// NetworkPolicyProgrammedBPF reports whether the given NetworkPolicy (in
// namespace polNS) with the given action is programmed in the BPF policy debug
// info for the given interface and hook.
func NetworkPolicyProgrammedBPF(felix *infrastructure.Felix, iface, hook, polNS, polName, action string, isWorkload bool) bool {
	namespacedName := fmt.Sprintf("%s/%s", polNS, polName)
	return checkProgrammedBPF(felix, iface, hook, namespacedName, action, isWorkload, "NetworkPolicy", proto.IPVersion_IPV4)
}

// GlobalNetworkPolicyProgrammedBPF reports whether the given
// GlobalNetworkPolicy with the given action is programmed in the BPF policy
// debug info for the given interface and hook (IPv4).
func GlobalNetworkPolicyProgrammedBPF(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkProgrammedBPF(felix, iface, hook, polName, action, isWorkload, "GlobalNetworkPolicy", proto.IPVersion_IPV4)
}

// GlobalNetworkPolicyProgrammedBPFV6 is the IPv6 equivalent of
// GlobalNetworkPolicyProgrammedBPF.
func GlobalNetworkPolicyProgrammedBPFV6(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool) bool {
	return checkProgrammedBPF(felix, iface, hook, polName, action, isWorkload, "GlobalNetworkPolicy", proto.IPVersion_IPV6)
}

// checkProgrammedBPF inspects the per-interface BPF policy debug JSON and
// reports whether the named policy (and, when action is set, a rule with that
// action) is present between the policy's start/end markers.
func checkProgrammedBPF(felix *infrastructure.Felix, iface, hook, polName, action string, isWorkload bool, polType string, ipFamily proto.IPVersion) bool {
	startStr := ""
	endStr := ""
	if polType != "" {
		startStr = fmt.Sprintf("Start of %s %s", polType, polName)
		endStr = fmt.Sprintf("End of %s %s", polType, polName)
	}
	actionStr := fmt.Sprintf("Start of rule %s action:\"%s\"", polName, action)
	var policyDbg bpf.PolicyDebugInfo
	out, err := felix.ExecOutput("cat", bpf.PolicyDebugJSONFileName(iface, hook, ipFamily))
	if err != nil {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	err = dec.Decode(&policyDbg)
	if err != nil {
		return false
	}

	hookStr := "tc ingress"
	if isWorkload {
		if hook == "ingress" {
			hookStr = "tc egress"
		}
	} else {
		if hook == "egress" {
			hookStr = "tc egress"
		}
	}
	if policyDbg.IfaceName != iface || policyDbg.Hook != hookStr || policyDbg.Error != "" {
		return false
	}

	startOfPolicy := false
	endOfPolicy := false
	actionMatch := false

	for _, insn := range policyDbg.PolicyInfo {
		for _, comment := range insn.Comments {
			if strings.Contains(comment, startStr) {
				startOfPolicy = true
			}
			if strings.Contains(comment, actionStr) && startOfPolicy && !endOfPolicy {
				actionMatch = true
			}
			if startOfPolicy && actionMatch && strings.Contains(comment, endStr) {
				endOfPolicy = true
			}
		}
	}

	return startOfPolicy && endOfPolicy && actionMatch
}
