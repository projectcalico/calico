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
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestOrphanedIfbNames(t *testing.T) {
	isWorkload := func(name string) bool { return strings.HasPrefix(name, "cali") }
	ifb := func(name string) netlink.Link { return &netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: name}} }
	veth := func(name string) netlink.Link { return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}} }

	liveIfb := GetIfbDeviceName("cali0027f0645a2")
	orphanIfb := GetIfbDeviceName("calideadbeef123")
	nonWorkloadIfb := GetIfbDeviceName("eth0")

	links := []netlink.Link{
		veth("cali0027f0645a2"),
		ifb(liveIfb),
		ifb(orphanIfb),
		veth("eth0"),
		ifb(nonWorkloadIfb),
		ifb("bwp12345"),
		veth("bwcalinotanifb"),
	}

	got := orphanedIfbNames(links, isWorkload)
	slices.Sort(got)
	want := []string{nonWorkloadIfb, orphanIfb}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("orphanedIfbNames() = %v, want %v", got, want)
	}
}
