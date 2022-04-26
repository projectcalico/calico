// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package ip_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = DescribeTable("CommonPrefix",
	func(a, b, expected string) {
		aCIDR := ip.MustParseCIDROrIP(a)
		bCIDR := ip.MustParseCIDROrIP(b)
		expCIDR := ip.MustParseCIDROrIP(expected)

		Expect(ip.CommonPrefix(aCIDR, bCIDR)).To(Equal(expCIDR))
		Expect(ip.CommonPrefix(bCIDR, aCIDR)).To(Equal(expCIDR))
	},
	// Zero cases.
	cpEntry("0.0.0.0/0", "0.0.0.0/0", "0.0.0.0/0"),
	cpEntry("0.0.0.0/0", "10.0.0.0/8", "0.0.0.0/0"),
	cpEntry("0.0.0.0/0", "0.0.3.0/24", "0.0.0.0/0"),
	cpEntry("::/0", "::/0", "::/0"),
	cpEntry("::/0", "fc00:fe11::/96", "::/0"),
	cpEntry("::/0", "::3:0/120", "::/0"),

	// One contained in the other.
	cpEntry("10.0.0.0/8", "10.0.3.0/24", "10.0.0.0/8"),
	cpEntry("fc00:fe11::/96", "fc00:fe11:3::/120", "fc00:fe11::/46"),

	// Disjoint.
	cpEntry("64.0.0.0/8", "65.0.3.0/24", "64.0.0.0/7"),
	cpEntry("64.0.0.0/9", "65.0.3.128/25", "64.0.0.0/7"),
	cpEntry("64.0.3.0/24", "65.0.3.0/24", "64.0.0.0/7"),
	cpEntry("64.0.3.0/8", "64.0.3.0/24", "64.0.0.0/8"), // Non-canonical CIDR
	cpEntry("fc00:fe11::/96", "fcff:fe11::/120", "fc00::/8"),
	cpEntry("fc00:fe11::/112", "fcff:fe11::/120", "fc00::/8"),
	cpEntry("fc00:fe11:3::/112", "fcff:fe11::/120", "fc00::/8"),
)

func cpEntry(a, b, exp string) TableEntry {
	return Entry(fmt.Sprintf("Common prefix of %v and %v should be %v", a, b, exp), a, b, exp)
}

var _ = Describe("CIDRTrie tests", func() {
	var trie *ip.CIDRTrie

	BeforeEach(func() {
		trie = &ip.CIDRTrie{}
	})

	update := func(cidr string) {
		trie.Update(ip.MustParseCIDROrIP(cidr), "data:"+cidr)
	}

	remove := func(cidr string) {
		trie.Delete(ip.MustParseCIDROrIP(cidr))
	}

	contents := func() []string {
		var s []string
		for _, t := range trie.ToSlice() {
			cidrStr := t.CIDR.String()
			Expect(t.Data).To(Equal("data:"+cidrStr), "Trie returned entry with unexpected data")
			s = append(s, cidrStr)
		}
		return s
	}

	lookup := func(cidr string) []string {
		var s []string
		for _, t := range trie.LookupPath(nil, ip.MustParseCIDROrIP(cidr)) {
			cidrStr := t.CIDR.String()
			Expect(t.Data).To(Equal("data:"+cidrStr), "Trie returned entry with unexpected data")
			s = append(s, cidrStr)
		}
		return s
	}

	lpm := func(cidr string, expectedCidr string) interface{} {
		cidrIn := ip.MustParseCIDROrIP(cidr)
		cidrOut, data := trie.LPM(cidrIn)

		if data != nil {
			Expect(cidrOut.Contains(cidrIn.Addr())).To(BeTrue())
			cidrExp := ip.MustParseCIDROrIP(expectedCidr)
			Expect(cidrExp).To(Equal(cidrOut))
		}

		return data
	}

	Context("IPv4", func() {
		BeforeEach(func() {
			trie = &ip.CIDRTrie{}
		})

		It("should allow inserting a single CIDR", func() {
			update("10.0.0.0/8")
			Expect(contents()).To(ConsistOf("10.0.0.0/8"))
		})

		It("should ignore deletes on an empty trie", func() {
			remove("11.0.0.0/8")
			Expect(contents()).To(BeEmpty())
		})

		It("should ignore deletes for outside the trie", func() {
			update("10.0.0.0/8")
			remove("11.0.0.0/8")
			Expect(contents()).To(ConsistOf("10.0.0.0/8"))
		})

		It("should ignore deletes when recursing on child that turns out to have a mismatch with the target", func() {
			update("10.0.0.0/8")
			update("10.0.1.0/24")
			remove("10.0.0.1/32")
			Expect(contents()).To(ConsistOf("10.0.0.0/8", "10.0.1.0/24"))
		})

		It("should ignore deletes when child is missing", func() {
			update("10.0.0.0/8")
			remove("10.0.0.1/32")
			Expect(contents()).To(ConsistOf("10.0.0.0/8"))
		})

		It("should fail to lookup in empty trie", func() {
			Expect(lookup("11.0.0.0/8")).To(BeEmpty())
		})

		It("should fail to lookup outside the trie", func() {
			update("10.0.0.0/8")
			Expect(lookup("11.0.0.0/8")).To(BeEmpty())
		})

		It("should fail to lookup intermediate node", func() {
			update("0.0.0.0/1")
			update("128.0.0.0/1")
			Expect(lookup("0.0.0.0/0")).To(BeEmpty())
		})

		It("should fail to lookup when recursing on child that turns out to have a mismatch with the target", func() {
			update("10.0.0.0/8")
			update("10.0.1.0/24")
			Expect(lookup("11.0.0.0/8")).To(BeEmpty())
		})

		It("should fail to lookup when child is missing", func() {
			update("10.0.0.0/8")
			Expect(lookup("11.0.0.0/8")).To(BeEmpty())
		})

		It("should panic when inserting/deleting/looking up a mismatched IP version CIDR", func() {
			update("10.0.0.0/8")
			Expect(func() { update("fc00:fe11::/96") }).To(Panic())
			Expect(func() { remove("fc00:fe11::/96") }).To(Panic())
			Expect(func() { lookup("fc00:fe11::/96") }).To(Panic())
		})
	})

	Context("IPv6", func() {
		BeforeEach(func() {
			trie = &ip.CIDRTrie{}
		})

		It("should allow inserting a single CIDR", func() {
			update("fc00:fe11::/96")
			Expect(contents()).To(ConsistOf("fc00:fe11::/96"))
		})

		It("should ignore deletes on an empty trie", func() {
			remove("fc00:fe12::/96")
			Expect(contents()).To(BeEmpty())
		})

		It("should ignore deletes for outside the trie", func() {
			update("fc00:fe11::/96")
			remove("fcff:fe11::/96")
			Expect(contents()).To(ConsistOf("fc00:fe11::/96"))
		})

		It("should ignore deletes when recursing on child that turns out to have a mismatch with the target", func() {
			update("fc00:fe11::/96")
			update("fc00:fe11:0:1::/120")
			remove("fc00:fe11:0:2:2::/128")
			Expect(contents()).To(ConsistOf("fc00:fe11::/96", "fc00:fe11:0:1::/120"))
		})

		It("should ignore deletes when child is missing", func() {
			update("fc00:fe11::/96")
			remove("fc00:fe11:0:2:2::/128")
			Expect(contents()).To(ConsistOf("fc00:fe11::/96"))
		})

		It("should fail to lookup in empty trie", func() {
			Expect(lookup("fc00:fe11:0:1::/120")).To(BeEmpty())
		})

		It("should fail to lookup outside the trie", func() {
			update("fc00:fe11::/96")
			Expect(lookup("fcff:fe11::/96")).To(BeEmpty())
		})

		It("should fail to lookup intermediate node", func() {
			update("::/1")
			update("fc00::/1")
			Expect(lookup("::/0")).To(BeEmpty())
		})

		It("should fail to lookup when recursing on child that turns out to have a mismatch with the target", func() {
			update("fc00:fe11::/96")
			update("fc00:fe11:0:1::/120")
			Expect(lookup("fcff:fe11:0:2:2::/96")).To(BeEmpty())
		})

		It("should fail to lookup when child is missing", func() {
			update("fc00:fe11::/96")
			Expect(lookup("fcff:fe11:0:2:2::/96")).To(BeEmpty())
		})

		It("should panic when inserting/deleting/looking up a mismatched IP version CIDR", func() {
			update("fc00:fe11::/96")
			Expect(func() { update("10.0.0.1/8") }).To(Panic())
			Expect(func() { remove("10.0.0.1/8") }).To(Panic())
			Expect(func() { lookup("10.0.0.1/8") }).To(Panic())
		})
	})

	Context("LPM", func() {
		Context("IPv4", func() {
			BeforeEach(func() {
				trie = &ip.CIDRTrie{}
			})

			Context("single node", func() {
				BeforeEach(func() {
					update("10.2.1.0/24")
				})

				It("should find 10.2.1.1", func() {
					Expect(lpm("10.2.1.1/32", "10.2.1.0/24")).NotTo(BeNil())
				})

				It("should not find 10.2.3.1", func() {
					Expect(lpm("10.2.3.1/32", "")).To(BeNil())
				})
			})

			Context("without value in root", func() {
				BeforeEach(func() {
					update("1.1.1.1/8")
					update("1.1.5.1/24")
					update("1.1.1.1/16")
					update("1.1.1.1/32")
					update("2.1.1.1/8")
					update("2.1.1.1/16")
				})

				It("should find precise", func() {
					Expect(lpm("1.1.1.1/32", "1.1.1.1/32")).NotTo(BeNil())
				})

				It("should find prefix for precise", func() {
					Expect(lpm("1.1.1.5/32", "1.1.1.1/16")).NotTo(BeNil())
				})

				It("should find internal node", func() {
					Expect(lpm("1.1.0.0/16", "1.1.0.0/16")).NotTo(BeNil())
				})

				It("should find internal prefix", func() {
					Expect(lpm("1.1.2.0/24", "1.1.0.0/16")).NotTo(BeNil())
				})

				It("should find root prefix", func() {
					Expect(lpm("3.0.0.0/7", "2.1.1.1/8")).NotTo(BeNil())
				})

				It("should not find prefix", func() {
					Expect(lpm("4.0.0.0/7", "")).To(BeNil())
				})

			})

			Context("LPM with root", func() {
				BeforeEach(func() {
					update("0.0.0.0/0")
				})

				It("should find root", func() {
					Expect(lpm("4.0.0.0/7", "0.0.0.0/0")).NotTo(BeNil())
				})
			})
		})

		Context("IPv6", func() {
			BeforeEach(func() {
				trie = &ip.CIDRTrie{}
			})

			Context("single node", func() {
				BeforeEach(func() {
					update("fc00:fe11::1/112")
				})

				It("should find fc00:fe11::1", func() {
					Expect(lpm("fc00:fe11::1/128", "fc00:fe11::/112")).NotTo(BeNil())
				})

				It("should not find fcff:fe11::1", func() {
					Expect(lpm("fcff:fe11::1/128", "")).To(BeNil())
				})
			})

			Context("without value in root", func() {
				BeforeEach(func() {
					update("7c00:fe11::1/96")
					update("7c00:fe11:5::1/112")
					update("7c00:fe11::1/104")
					update("7c00:fe11::1/128")
					update("fc00:fe11::1/96")
					update("fc00:fe11::1/104")
				})

				It("should find precise", func() {
					Expect(lpm("7c00:fe11::1/128", "7c00:fe11::1/128")).NotTo(BeNil())
				})

				It("should find prefix for precise", func() {
					Expect(lpm("7c00:fe11::5/128", "7c00:fe11::1/104")).NotTo(BeNil())
				})

				It("should find internal node", func() {
					Expect(lpm("7c00:fe11::/104", "7c00:fe11::/104")).NotTo(BeNil())
				})

				It("should find internal prefix", func() {
					Expect(lpm("7c00:fe11::/112", "7c00:fe11::/104")).NotTo(BeNil())
				})

				It("should find root prefix", func() {
					// Expect(trie).To(BeNil()) //TODO
					Expect(lpm("fc00:fe11::/32", "fc00:fe11::1/104")).NotTo(BeNil())
				})

				It("should not find prefix", func() {
					Expect(lpm("8000::/8", "")).To(BeNil())
				})

			})

			Context("LPM with root", func() {
				BeforeEach(func() {
					update("::/0")
				})

				It("should find root", func() {
					Expect(lpm("fc00:fe11::1/112", "::/0")).NotTo(BeNil())
				})
			})
		})
	})

	pEntry := func(cidrs ...string) TableEntry {
		return Entry(fmt.Sprint(cidrs), cidrs)
	}
	DescribeTable("permutation tests",
		func(cidrs []string) {
			// First, we double the length of the input.  When we iterate over a particular permutation, we'll
			// take the first instance of a given CIDR to mean "insert" and the second to mean "remove".  This is very
			// inefficient(!) since many of the sequences end up being equivalent but it does cover all the bases.
			cidrs = append(cidrs, cidrs...)
			permute(cidrs, func(cidrs []string) {
				// expected tracks the CIDRs that should be in the trie.
				expected := set.New()
				for _, c := range cidrs {
					// Add or remove the given CIDR depending on whether it should be there or not.
					if expected.Contains(c) {
						expected.Discard(c)
						remove(c)
					} else {
						expected.Add(c)
						update(c)
					}
					var expSlice []string
					expected.Iter(func(item interface{}) error {
						cidr := item.(string)
						expSlice = append(expSlice, cidr)

						path := lookup(cidr)
						for _, c := range path {
							Expect(expected.Contains(c)).To(BeTrue(), fmt.Sprintf(
								"Trie returned a path (%v) including a CIDR that wasn't supposed to be in the trie (%v)", path, c))
						}

						return nil
					})
					Expect(contents()).To(ConsistOf(expSlice),
						fmt.Sprintf("Trie had incorrect contents with this sequence of CIDRs: %s", cidrs))
				}
			})
		},
		pEntry("0.0.0.0/0"),
		pEntry("10.0.0.0/8"),
		pEntry("0.0.0.0/0", "10.0.0.0/8", "11.0.0.0/8"),
		pEntry("132.2.3.4/32", "132.2.3.5/32", "132.2.3.6/32"),
		pEntry("0.0.0.0/0", "128.0.0.0/1", "0.0.0.0/1"), // 0.0.0.0/0 is the intermediate node for the other two CIDRs.
		pEntry("1.0.0.0/8", "1.0.0.0/24", "1.0.0.27/32"),
		pEntry("::/0"),
		pEntry("fc00:fe11::/96"),
		pEntry("::/0", "fc00:fe11::/96", "fcff:fe11::/96"),
		pEntry("fc00:fe11::4/128", "fc00:fe11::5/128", "fc00:fe11::6/128"),
		pEntry("::/0", "8000::/1", "::/1"), // ::/0 is the intermediate node for the other two CIDRs.
		pEntry("fc00:fe11::/96", "fc00:fe11:1:2:3::/120", "fc00:fe11:1:2:3::1/128"),
	)
})

// Based on the blog post at https://yourbasic.org/golang/generate-permutation-slice-string/ (CC-BY-3.0)
// permute calls f with each permutation of a.
func permute(a []string, f func([]string)) {
	permuteInner(a, f, 0)
}

// Permute the values at index i to len(a)-1.
func permuteInner(a []string, f func([]string), i int) {
	if i > len(a) {
		f(a)
		return
	}
	permuteInner(a, f, i+1)
	for j := i + 1; j < len(a); j++ {
		a[i], a[j] = a[j], a[i]
		permuteInner(a, f, i+1)
		a[i], a[j] = a[j], a[i]
	}
}

var benchmarkResult uint32

func BenchmarkV4Addr_AsUint32(b *testing.B) {
	a := ip.MustParseCIDROrIP("10.0.0.1").Addr().(ip.V4Addr)
	for i := 0; i < b.N; i++ {
		benchmarkResult += a.AsUint32()
	}
}
