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

package linux

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
)

func TestIsNetkitUnsupported(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain string", errors.New("boom"), false},
		{"eopnotsupp", syscall.EOPNOTSUPP, true},
		{"enotsup alias", syscall.ENOTSUP, true}, // == EOPNOTSUPP on Linux
		{"wrapped eopnotsupp", fmt.Errorf("netlink: %w", syscall.EOPNOTSUPP), true},
		{"einval is real error", syscall.EINVAL, false},
		{"eexist", syscall.EEXIST, false},
		{"eperm", syscall.EPERM, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetkitUnsupported(tc.err); got != tc.want {
				t.Errorf("isNetkitUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestAddWorkloadLinkIntegration exercises addWorkloadLink against real
// temporary netnses. Both the "host" and "container" sides live in fresh
// unshared netnses so the test is fully isolated from the environment it
// runs in (avoiding collisions with leftover/real interfaces in CI which may
// run with --net=host). Requires root (CAP_SYS_ADMIN to unshare netns) and,
// for the netkit subtest, kernel 6.7+.
func TestAddWorkloadLinkIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping integration test: requires root (unshare netns)")
	}

	subtests := []struct {
		name     string
		request  string
		wantType string
		needs67  bool
	}{
		{"default-is-veth", "", types.DeviceTypeVeth, false},
		{"explicit-veth", types.DeviceTypeVeth, types.DeviceTypeVeth, false},
		{"netkit-on-67", types.DeviceTypeNetkit, types.DeviceTypeNetkit, true},
	}

	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needs67 && !kernelAtLeast(t, 6, 7) {
				t.Skip("skipping: requires kernel 6.7+ for netkit")
			}

			hostNS, err := ns.TempNetNS()
			if err != nil {
				t.Fatalf("TempNetNS (host): %v", err)
			}
			defer func() { _ = hostNS.Close() }()

			contNS, err := ns.TempNetNS()
			if err != nil {
				t.Fatalf("TempNetNS (cont): %v", err)
			}
			defer func() { _ = contNS.Close() }()

			d := &LinuxDataplane{
				mtu:        1500,
				queues:     1,
				deviceType: tc.request,
				logger:     logrus.NewEntry(logrus.New()),
			}
			const hostName = "host0"

			var gotType string
			// Use Do (which switches via fd) rather than WithNetNSPath:
			// ns.TempNetNS path strings re-resolve through /proc/<pid>/task/<tid>
			// which may no longer point at the captured netns once the
			// creating goroutine has been recycled.
			err = contNS.Do(func(_ ns.NetNS) error {
				la := netlink.NewLinkAttrs()
				la.Name = "eth0"
				la.MTU = 1500
				var innerErr error
				gotType, innerErr = d.addWorkloadLink(la, hostName, hostNS)
				return innerErr
			})
			if err != nil {
				t.Fatalf("addWorkloadLink: %v", err)
			}
			if gotType != tc.wantType {
				t.Errorf("created type = %q, want %q", gotType, tc.wantType)
			}

			err = hostNS.Do(func(_ ns.NetNS) error {
				link, err := netlink.LinkByName(hostName)
				if err != nil {
					return fmt.Errorf("host-side link lookup: %w", err)
				}
				if link.Type() != tc.wantType {
					t.Errorf("host link kernel type = %q, want %q", link.Type(), tc.wantType)
				}
				if tc.wantType == types.DeviceTypeNetkit {
					nk, ok := link.(*netlink.Netkit)
					if !ok {
						return fmt.Errorf("host link is %T, want *netlink.Netkit", link)
					}
					if !nk.IsPrimary() {
						t.Errorf("host-side netkit must be primary (Felix attaches BPF_NETKIT_PRIMARY here)")
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("inspecting host-side link: %v", err)
			}
		})
	}
}

func kernelAtLeast(t *testing.T, wantMajor, wantMinor int) bool {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("read osrelease: %v", err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(b)), ".", 3)
	if len(parts) < 2 {
		t.Fatalf("unexpected osrelease %q", string(b))
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("parse major: %v", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse minor: %v", err)
	}
	if major != wantMajor {
		return major > wantMajor
	}
	return minor >= wantMinor
}
