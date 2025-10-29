// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package infrastructure

// dumpFelixDiags collects a standard set of diagnostics from a Felix node.
// It is intentionally conservative and conditioned on test modes so it
// can be used universally from DumpErrorData() on failures.
func dumpFelixDiags(f *Felix) {
	// Core Linux networking dumps.
	f.Exec("ip", "link")
	f.Exec("ip", "addr")
	f.Exec("ip", "rule", "list")
	f.Exec("ip", "route", "show", "table", "all")
	f.Exec("ip", "route", "show", "cached")
	f.Exec("conntrack", "-L")

	// Table dumps (iptables or nftables) depending on mode.
	if NFTMode() {
		f.Exec("nft", "list", "ruleset")
	} else {
		f.Exec("iptables-save", "-c")
	}

	// IPv6-specific diagnostics if IPv6 is enabled for this node.
	if f.TopologyOptions.EnableIPv6 {
		f.Exec("ip", "-6", "link")
		f.Exec("ip", "-6", "addr")
		f.Exec("ip", "-6", "rule")
		f.Exec("ip", "-6", "route", "show", "table", "all")
		f.Exec("ip", "-6", "route", "show", "cached")
		f.Exec("ip", "-6", "neigh")
		f.Exec("conntrack", "-L", "-f", "ipv6")
		if !NFTMode() {
			f.Exec("ip6tables-save", "-c")
		}
	}

	// BPF-specific diagnostics when running in BPF mode.
	if BPFMode() {
		// Data-plane maps & state.
		f.Exec("calico-bpf", "ipsets", "dump")
		f.Exec("calico-bpf", "routes", "dump")
		f.Exec("calico-bpf", "nat", "dump")
		f.Exec("calico-bpf", "conntrack", "dump")
		f.Exec("calico-bpf", "arp", "dump")
		f.Exec("calico-bpf", "counters", "dump")
		f.Exec("calico-bpf", "ifstate", "dump")
		// Policy attached to host (best-effort on eth0).
		f.Exec("calico-bpf", "policy", "dump", "eth0", "all")
		if f.TopologyOptions.EnableIPv6 {
			// IPv6 route and policy dumps where supported.
			f.Exec("calico-bpf", "-6", "routes", "dump")
			f.Exec("calico-bpf", "policy", "-6", "dump", "eth0", "all")
		}
	}
}
