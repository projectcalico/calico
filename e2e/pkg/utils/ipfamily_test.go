// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"testing"

	"github.com/onsi/gomega"
)

func TestFamilyOf(t *testing.T) {
	g := gomega.NewWithT(t)
	for ip, want := range map[string]IPFamily{
		"10.0.0.1":         IPv4,
		"fd00::1":          IPv6,
		"::ffff:10.0.0.1":  IPv4,
		"2001:db8:60:70::": IPv6,
	} {
		got, ok := FamilyOf(ip)
		g.Expect(ok).To(gomega.BeTrue(), ip)
		g.Expect(got).To(gomega.Equal(want), ip)
	}
	for _, bad := range []string{"", "not-an-ip", "10.0.0.0/8"} {
		_, ok := FamilyOf(bad)
		g.Expect(ok).To(gomega.BeFalse(), bad)
	}
}

func TestFamilySizes(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(IPv4.HostBits()).To(gomega.Equal(32))
	g.Expect(IPv6.HostBits()).To(gomega.Equal(128))
	g.Expect(IPv4.HeaderBytes()).To(gomega.Equal(20))
	g.Expect(IPv6.HeaderBytes()).To(gomega.Equal(40))
}
