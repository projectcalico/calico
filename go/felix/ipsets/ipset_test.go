// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package ipsets_test

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"time"
)

const (
	ipSetID = "s:qMt7iLlGDhvLnCjM0l9nzxbabcd"

	v4MainIPSetName = "cali4-s:qMt7iLlGDhvLnCjM0l9nzxb"
	v4TempIPSetName = "cali4ts:qMt7iLlGDhvLnCjM0l9nzxb"

	v6MainIPSetName = "cali6-s:qMt7iLlGDhvLnCjM0l9nzxb"
	v6TempIPSetName = "cali6ts:qMt7iLlGDhvLnCjM0l9nzxb"
)

var (
	v4Members1And2  = []string{"10.0.0.1", "10.0.0.2"}
	v4Members12And3 = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	v4Members2And3  = []string{"10.0.0.2", "10.0.0.3"}

	v6Members1And2 = []string{"fe80::1", "fe80::2"}
)

var _ = Describe("Ipset", func() {
	var dataplane *mockDataplane
	var cache *ExistenceCache
	var ipset *IPSet

	meta := IPSetMetadata{
		MaxSize: 1234,
		SetID:   ipSetID,
		Type:    IPSetTypeHashIP,
	}
	v4VersionConf := NewIPVersionConfig(
		IPFamilyV4,
		"cali",
		rules.AllHistoricIPSetNamePrefixes,
		rules.LegacyV4IPSetNames,
	)
	v6VersionConf := NewIPVersionConfig(
		IPFamilyV6,
		"cali",
		rules.AllHistoricIPSetNamePrefixes,
		nil,
	)

	var sleeps []time.Duration

	// Render a copy of the tests with and without a random failure.
	describeTests := func(
		simulateTransientFailure bool,
	) {
		desc := fmt.Sprintf("IPv4 in empty dataplane with members 1 and 2 and a failure: %v",
			simulateTransientFailure)
		Describe(desc, func() {
			BeforeEach(func() {
				sleeps = nil
				dataplane = newMockDataplane()
				dataplane.FailNextRestore = simulateTransientFailure
				cache = NewExistenceCache(dataplane.newCmd)
				ipset = NewIPSet(
					v4VersionConf,
					meta,
					cache,
					dataplane.newCmd,
				)
				ipset.Sleep = func(d time.Duration) {
					sleeps = append(sleeps, d)
				}
				ipset.ReplaceMembers(v4Members1And2)
			})

			if simulateTransientFailure {
				It("should sleep if it retries", func() {
					ipset.Apply()
					Expect(sleeps).To(Equal([]time.Duration{100 * time.Millisecond}))
				})
			} else {
				It("should not sleep if no retries", func() {
					ipset.Apply()
					Expect(sleeps).To(Equal([]time.Duration(nil)))
				})
			}
			It("should do initial rewrite after Apply", func() {
				dataplane.ExpectMembers(map[string][]string{})
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
			})
			It("should clean up pre-existing temp set", func() {
				tempSet := set.New()
				tempSet.Add("10.0.0.5")
				dataplane.IPSetMembers[v4TempIPSetName] = tempSet
				dataplane.IPSetMetadata[v4TempIPSetName] = setMetadata{
					Name:    v4TempIPSetName, // Created as the temp set then swapped.
					Type:    IPSetTypeHashIP,
					Family:  IPFamilyV4,
					MaxSize: 1235, // Different value should get squashed
				}
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members1And2})
				Expect(dataplane.IPSetMetadata[v4MainIPSetName]).To(Equal(setMetadata{
					Name:    v4TempIPSetName, // Created as the temp set then swapped.
					Type:    IPSetTypeHashIP,
					Family:  IPFamilyV4,
					MaxSize: 1234,
				}))
			})
			It("should create temp set then swap into place", func() {
				ipset.Apply()
				Expect(dataplane.IPSetMetadata[v4MainIPSetName]).To(Equal(setMetadata{
					Name:    v4TempIPSetName, // Created as the temp set then swapped.
					Type:    IPSetTypeHashIP,
					Family:  IPFamilyV4,
					MaxSize: 1234,
				}))
			})
			It("should handle multiple rewrites before Apply()", func() {
				ipset.ReplaceMembers(v4Members2And3)
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members2And3})
			})
			It("should handle multiple rewrites", func() {
				ipset.Apply()
				ipset.ReplaceMembers(v4Members2And3)
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members2And3})
			})
			It("should handle additions with a rewrite pending", func() {
				ipset.AddMembers([]string{"10.0.0.3"})
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members12And3})
			})
			It("should handle additions with no rewrite pending", func() {
				ipset.Apply()
				ipset.AddMembers([]string{"10.0.0.3"})
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members12And3})
			})
			It("should handle deletions with a rewrite pending", func() {
				ipset.RemoveMembers([]string{"10.0.0.2"})
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: {"10.0.0.1"}})
			})
			It("should handle deletion with no rewrite pending", func() {
				ipset.Apply()
				ipset.RemoveMembers([]string{"10.0.0.2"})
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: {"10.0.0.1"}})
			})
			It("should coalesce deletions then a rewrite", func() {
				ipset.RemoveMembers([]string{"10.0.0.2"})
				ipset.ReplaceMembers(v4Members2And3)
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v4MainIPSetName: v4Members2And3})
			})
			It("should update the cache", func() {
				ipset.Apply()
				Expect(cache.IPSetExists(v4MainIPSetName)).To(BeTrue())
				Expect(cache.IPSetExists(v4TempIPSetName)).To(BeFalse())
			})
		})

		Describe("IPv6 basic mainline", func() {
			BeforeEach(func() {
				dataplane = newMockDataplane()
				cache = NewExistenceCache(dataplane.newCmd)
				ipset = NewIPSet(
					v6VersionConf,
					meta,
					cache,
					dataplane.newCmd,
				)
				ipset.ReplaceMembers(v6Members1And2)
			})

			// Since the IPSet object mainly deals with strings, rather than parsing the IPs,
			// we only do a couple of IPv6 tests to check that the IPv6-ness of the metadata is
			// passed through.
			It("should contain expected addresses after Apply()", func() {
				ipset.Apply()
				dataplane.ExpectMembers(map[string][]string{v6MainIPSetName: v6Members1And2})
			})
			It("should use IPv6 IP set names and do swap", func() {
				ipset.Apply()
				Expect(dataplane.IPSetMetadata[v6MainIPSetName]).To(Equal(setMetadata{
					Name:    v6TempIPSetName, // Created as the temp set then swapped.
					Type:    IPSetTypeHashIP,
					Family:  IPFamilyV6,
					MaxSize: 1234,
				}))
			})
		})
	}
	describeTests(true)
	describeTests(false)
})
