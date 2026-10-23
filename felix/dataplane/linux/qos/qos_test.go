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

package qos

import (
	"sort"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestOrphanedIfbLinks(t *testing.T) {
	workload := "cali0027f0645a2"
	activeIfb := GetIfbDeviceName(workload)
	staleIfb := GetIfbDeviceName("cali-old-workload")

	links := []netlink.Link{
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: workload}},
		&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: activeIfb}},
		&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: staleIfb}},
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "bwp1234"}},
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}},
	}

	orphaned := orphanedIfbLinks(links, []string{"cali", "tap"})
	var names []string
	for _, link := range orphaned {
		names = append(names, link.Attrs().Name)
	}
	sort.Strings(names)

	if want := []string{staleIfb}; len(names) != len(want) || names[0] != want[0] {
		t.Fatalf("orphaned IFBs = %v, want %v", names, want)
	}
}

func TestOrphanedIfbLinksDoesNotTreatUnrelatedPrefixAsWorkload(t *testing.T) {
	workload := "tap123"
	ifb := GetIfbDeviceName(workload)

	links := []netlink.Link{
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: workload}},
		&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: ifb}},
	}

	if orphaned := orphanedIfbLinks(links, []string{"cali"}); len(orphaned) != 1 {
		t.Fatalf("orphaned IFBs = %v, want the IFB to be orphaned", orphaned)
	}
}
