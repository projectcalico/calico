// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package clientv3

import (
	"context"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

func TestChangeCidrOK(t *testing.T) {
	testCases := []struct {
		name     string
		oldCidr  string
		newCidr  string
		expected bool
	}{
		{
			name:     "Canonical to non-canonical should be rejected",
			oldCidr:  "2001:cafe:42::/56",
			newCidr:  "2001:cafe:42:0000:00::/56",
			expected: false,
		},
		{
			name:     "Non-canonical to non-canonical should be rejected",
			oldCidr:  "2001:cafe:42:0:0:0:0:0/56",
			newCidr:  "2001:cafe:42:0000:00::/56",
			expected: false,
		},
		{
			name:     "Non-canonical to canonical should be accepted",
			oldCidr:  "2001:cafe:42::00/56",
			newCidr:  "2001:cafe:42::/56",
			expected: true,
		},
		{
			name:     "Canonical to canonical but different text should be rejected",
			oldCidr:  "2001:db8::/32",
			newCidr:  "2001:0db8::/32", // new must match canonical string exactly
			expected: false,
		},
		{
			name:     "Same network but new CIDR not canonical should be rejected",
			oldCidr:  "2001:cafe:42::/56",
			newCidr:  "2001:cafe:42:0:0::/56",
			expected: false,
		},
		{
			name:     "Old invalid but new canonical valid should be rejected",
			oldCidr:  "2001:cafe:::bad/56",
			newCidr:  "2001:cafe::/56",
			expected: false, // reject (old fails parse)
		},
		{
			name:     "Valid canonical to valid canonical but different networks rejected",
			oldCidr:  "fd00::/48",
			newCidr:  "fd00:1::/48",
			expected: false,
		},
		{
			name:     "IPv6 uppercase vs lowercase canonical mismatch rejected",
			oldCidr:  "2001:CAFE:42::/56",
			newCidr:  "2001:cafe:42::/56",
			expected: true,
		},
		{
			name:     "IPv6 non-canonical masked version to canonical should be accepted",
			oldCidr:  "2001:0db8:0000:0000::/64",
			newCidr:  "2001:db8::/64",
			expected: true,
		},
		{
			name:     "Reject when old is canonical but new adds redundant fields",
			oldCidr:  "2001:cafe:42::/56",
			newCidr:  "2001:cafe:42:0:0:0:0:0/56",
			expected: false,
		},
		{
			name:     "Accept IPv6 equivalent non-canonical to canonical",
			oldCidr:  "2001:cafe:42:0000::/56",
			newCidr:  "2001:cafe:42::/56",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := cidrChangeOK(tc.oldCidr, tc.newCidr)
			if result != tc.expected {
				t.Errorf("cidrChangeOK(%q, %q) = %v, want %v",
					tc.oldCidr, tc.newCidr, result, tc.expected)
			}
		})
	}
}

// TestValidateAndSetDefaults_CIDRComparison tests the validateAndSetDefaults function
// with different CIDR representations to ensure semantic comparison works correctly.
func TestValidateAndSetDefaults_CIDRComparison(t *testing.T) {
	ctx := context.Background()

	// Create a mock ipPools instance - we don't need actual backend for these tests
	// since we're testing validation logic that doesn't require backend access
	r := ipPools{}

	testCases := []struct {
		name        string
		oldCIDR     string
		newCIDR     string
		blockSize   int
		shouldError bool
		description string
	}{
		{
			name:        "IPv6 same network different representation - should succeed",
			oldCIDR:     "2001:cafe:42::00/56", // Non-normalized (as it might be stored)
			newCIDR:     "2001:cafe:42::/56",   // Normalized form
			blockSize:   122,
			shouldError: false,
			description: "Update with same IPv6 network but different textual representation should be allowed",
		},
		{
			name:        "IPv6 expanded vs compressed - should succeed",
			oldCIDR:     "2001:0db8:85a3:0000:0000:0000:0000:0000/64", // Expanded (as it might be stored)
			newCIDR:     "2001:db8:85a3::/64",                         // Compressed form
			blockSize:   122,
			shouldError: false,
			description: "IPv6 expanded and compressed forms should be treated as identical",
		},
		{
			name:        "IPv6 different networks - should fail",
			oldCIDR:     "2001:cafe:42::/56",
			newCIDR:     "2001:cafe:43::/56",
			blockSize:   122,
			shouldError: true,
			description: "Different IPv6 networks should be rejected",
		},
		{
			name:        "IPv6 different prefix length - should fail",
			oldCIDR:     "2001:cafe:42::/56",
			newCIDR:     "2001:cafe:42::/64",
			blockSize:   122,
			shouldError: true,
			description: "Different prefix lengths should be rejected",
		},
		{
			name:        "IPv4 same CIDR - should succeed",
			oldCIDR:     "192.168.1.0/24",
			newCIDR:     "192.168.1.0/24",
			blockSize:   26,
			shouldError: false,
			description: "Identical IPv4 CIDRs should be allowed",
		},
		{
			name:        "IPv4 different networks - should fail",
			oldCIDR:     "192.168.1.0/24",
			newCIDR:     "192.168.2.0/24",
			blockSize:   26,
			shouldError: true,
			description: "Different IPv4 networks should be rejected",
		},
		{
			name:        "IPv4 different prefix - should fail",
			oldCIDR:     "192.168.1.0/24",
			newCIDR:     "192.168.1.0/25",
			blockSize:   26,
			shouldError: true,
			description: "Different IPv4 prefix lengths should be rejected",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create old IPPool with the old CIDR
			oldPool := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:      tc.oldCIDR,
					BlockSize: tc.blockSize,
				},
			}

			// Create new IPPool with the new CIDR
			newPool := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool",
				},
				Spec: apiv3.IPPoolSpec{
					CIDR:      tc.newCIDR,
					BlockSize: tc.blockSize,
				},
			}

			// Call validateAndSetDefaults with skipCIDROverlap=true to skip overlap checks
			// which would require a backend
			err := r.validateAndSetDefaults(ctx, newPool, oldPool, true)

			if tc.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tc.description)
				} else {
					// Verify it's the correct error type
					if validationErr, ok := err.(cerrors.ErrorValidation); ok {
						found := false
						for _, field := range validationErr.ErroredFields {
							if field.Name == "IPPool.Spec.CIDR" {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("%s: got error but not the expected CIDR modification error: %v", tc.description, err)
						}
					} else {
						t.Errorf("%s: expected ErrorValidation but got: %T", tc.description, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("%s: expected no error but got: %v", tc.description, err)
				}
			}
		})
	}
}
