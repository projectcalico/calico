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

package accounting

import (
	"fmt"
	"math"
	"slices"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// reservationsCovering returns one IPReservation per CIDR, which is the interesting
// shape: reservations that overlap each other arrive as separate resources.
func reservationsCovering(cidrs []string) []*v3.IPReservation {
	var reservations []*v3.IPReservation
	for i, cidr := range cidrs {
		reservations = append(reservations, &v3.IPReservation{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("reservation-%d", i)},
			Spec:       v3.IPReservationSpec{ReservedCIDRs: []string{cidr}},
		})
	}
	return reservations
}

type numReservedCase struct {
	name         string
	pool         string
	reservations []string
	wantReserved int
}

func TestNumReservedIPsInCIDR(t *testing.T) {
	for _, tc := range []numReservedCase{
		{
			name: "no reservations",
			pool: "10.0.0.0/24",
		},
		{
			name:         "one reservation",
			pool:         "10.0.0.0/24",
			reservations: []string{"10.0.0.32/30"},
			wantReserved: 4,
		},
		{
			// The nested and duplicated CIDRs must not be counted more than once.
			name:         "overlapping reservations",
			pool:         "10.0.0.0/24",
			reservations: []string{"10.0.0.0/25", "10.0.0.5/32", "10.0.0.64/26", "10.0.0.0/25"},
			wantReserved: 128,
		},
		{
			name:         "reservation covering the whole pool",
			pool:         "10.0.0.0/24",
			reservations: []string{"10.0.0.0/16"},
			wantReserved: 256,
		},
		{
			name:         "reservation outside the pool",
			pool:         "10.0.0.0/24",
			reservations: []string{"192.168.0.0/24", "fd00::/120"},
		},
		{
			name:         "reservation over half the pool",
			pool:         "10.0.0.0/24",
			reservations: []string{"10.0.0.128/25"},
			wantReserved: 128,
		},
		{
			name:         "IPv6 pool",
			pool:         "fd00::/120",
			reservations: []string{"fd00::/126"},
			wantReserved: 4,
		},
		{
			// Bigger than validation allows, but the count must saturate rather than wrap.
			name:         "reservation too big for an int",
			pool:         "fd00::/8",
			reservations: []string{"fd00::/8"},
			wantReserved: math.MaxInt,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			numReserved, err := NumReservedIPsInCIDR(cnet.MustParseNetwork(tc.pool), reservationsCovering(tc.reservations))
			if err != nil {
				t.Fatalf("NumReservedIPsInCIDR returned an error: %v", err)
			}
			if numReserved != tc.wantReserved {
				t.Errorf("NumReservedIPsInCIDR = %d, want %d", numReserved, tc.wantReserved)
			}
		})
	}
}

type reservationCIDRsCase struct {
	name     string
	reserved []string
	want     []string
}

func TestReservationCIDRs(t *testing.T) {
	for _, tc := range []reservationCIDRsCase{
		{
			name:     "CIDRs and bare IPs",
			reserved: []string{"10.0.0.0/24", "10.1.0.1", "fd00::1"},
			want:     []string{"10.0.0.0/24", "10.1.0.1/32", "fd00::1/128"},
		},
		{
			name:     "surrounding whitespace",
			reserved: []string{" 10.0.0.0/24 "},
			want:     []string{"10.0.0.0/24"},
		},
		{
			// Validation should prevent all of these, but a hand-written CRD can
			// still carry them and they must not take the count with them.
			name:     "malformed entries are skipped",
			reserved: []string{"", "   ", "not-a-cidr", "10.0.0.0/33", "10.0.0.0/24"},
			want:     []string{"10.0.0.0/24"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cidrs := ReservationCIDRs([]*v3.IPReservation{{
				ObjectMeta: metav1.ObjectMeta{Name: "reservation"},
				Spec:       v3.IPReservationSpec{ReservedCIDRs: tc.reserved},
			}})

			var got []string
			for _, c := range cidrs {
				got = append(got, c.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ReservationCIDRs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewReservedIPsContains(t *testing.T) {
	RegisterTestingT(t)
	set, err := NewReservedIPs([]*v3.IPReservation{reservation("r", "10.0.0.0/30")})
	Expect(err).NotTo(HaveOccurred())
	Expect(set.Contains(cnet.MustParseIP("10.0.0.3").IP)).To(BeTrue())
	Expect(set.Contains(cnet.MustParseIP("10.0.0.4").IP)).To(BeFalse())

	var none *ReservedIPs
	Expect(none.Contains(cnet.MustParseIP("10.0.0.3").IP)).To(BeFalse())
}

func TestNumReservedIPsInCIDRBigExceedsInt(t *testing.T) {
	RegisterTestingT(t)
	cidr := cnet.MustParseNetwork("fd00::/48")
	reservations := []*v3.IPReservation{reservation("all", "fd00::/48")}

	total, err := NumReservedIPsInCIDRBig(cidr, reservations)
	Expect(err).NotTo(HaveOccurred())
	Expect(total.String()).To(Equal("1208925819614629174706176"))

	clamped, err := NumReservedIPsInCIDR(cidr, reservations)
	Expect(err).NotTo(HaveOccurred())
	Expect(clamped).To(Equal(math.MaxInt))
}
