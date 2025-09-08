// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
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

package nftables_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/iptables/testutils"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/nftables"
	. "github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/rules"
)

var expectedBaseChains = []string{
	"filter-INPUT",
	"filter-FORWARD",
	"filter-OUTPUT",
	"nat-PREROUTING",
	"nat-INPUT",
	"nat-OUTPUT",
	"nat-POSTROUTING",
	"mangle-PREROUTING",
	"mangle-INPUT",
	"mangle-FORWARD",
	"mangle-OUTPUT",
	"mangle-POSTROUTING",
	"raw-PREROUTING",
	"raw-OUTPUT",
}

var _ = Describe("Table with an empty dataplane", func() {
	var table *NftablesTable
	var featureDetector *environment.FeatureDetector
	var f *fakeNFT
	BeforeEach(func() {
		newDataplane := func(fam knftables.Family, name string) (knftables.Interface, error) {
			f = NewFake(fam, name)
			return f, nil
		}
		featureDetector = environment.NewFeatureDetector(nil)
		table = NewTable(
			"calico",
			4,
			rules.RuleHashPrefix,
			featureDetector,
			TableOptions{
				NewDataplane:     newDataplane,
				LookPathOverride: testutils.LookPathNoLegacy,
				OpRecorder:       logutils.NewSummarizer("test loop"),
			},
			true,
		)
	})

	It("should Apply() on an empty state)", func() {
		Expect(table.Apply()).To(BeNumerically("<", 100*time.Millisecond))

		// Expect our base chains to have been created.
		chains, err := f.List(context.TODO(), "chain")
		Expect(err).NotTo(HaveOccurred())
		Expect(len(chains)).To(Equal(14))
	})

	It("should support adding a chain", func() {
		chain := generictables.Chain{
			Name: "test-chain",
		}
		table.UpdateChain(&chain)
		Expect(table.Apply()).To(BeNumerically("<", 100*time.Millisecond))

		// The chain isn't referenced yet, so shouldn't show up.
		chains, err := f.List(context.TODO(), "chain")
		Expect(err).NotTo(HaveOccurred())
		Expect(chains).To(ConsistOf(expectedBaseChains))
		Expect(f.transactions).To(HaveLen(1))

		// Add a rule to a base chain that references it. This should trigger programming.
		jumpChain := generictables.Chain{
			Name: "filter-FORWARD",
			Rules: []generictables.Rule{
				{
					Match:  Match(),
					Action: JumpAction{Target: chain.Name},
				},
			},
		}
		table.UpdateChain(&jumpChain)
		Expect(table.Apply()).To(BeNumerically("<", 100*time.Millisecond))
		Expect(f.transactions).To(HaveLen(2))

		// We should see the new chain appear now.
		chains, err = f.List(context.TODO(), "chain")
		Expect(err).NotTo(HaveOccurred())
		Expect(chains).To(ConsistOf(append(expectedBaseChains, chain.Name)))

		// Delete the rule and confirm it is removed.
		jumpChainCp := jumpChain
		jumpChainCp.Rules = nil
		table.UpdateChain(&jumpChainCp)
		Expect(table.Apply()).To(BeNumerically("<", 100*time.Millisecond))
		Expect(f.transactions).To(HaveLen(3))

		// We should see the chain removed since it is no longer referenced.
		chains, err = f.List(context.TODO(), "chain")
		Expect(err).NotTo(HaveOccurred())
		Expect(chains).NotTo(ContainElement(chain.Name))
	})

	It("should ignore delete of nonexistent chain", func() {
		// Apply the base chains.
		table.Apply()
		Expect(f.transactions).To(HaveLen(1))

		// Remove a non-existent chain. It should not trigger any new updates.
		table.RemoveChains([]*generictables.Chain{
			{Name: "cali-foobar", Rules: []generictables.Rule{{Match: nftables.Match(), Action: AcceptAction{}}}},
		})
		table.Apply()
		Expect(f.transactions).To(HaveLen(1))
	})

	It("Should defer updates until Apply is called", func() {
		table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
			{Match: nftables.Match(), Action: DropAction{}},
		})
		table.UpdateChains([]*generictables.Chain{
			{Name: "cali-foobar", Rules: []generictables.Rule{{Match: nftables.Match(), Action: AcceptAction{}}}},
		})
		Expect(f.transactions).To(BeEmpty())
		table.Apply()
		Expect(f.transactions).NotTo(BeEmpty())
	})

	It("Should panic on nft failures", func() {
		// Insert rules into a non-existent chain.
		table.InsertOrAppendRules("badchain", []generictables.Rule{
			{Match: nftables.Match(), Action: DropAction{}},
		})
		Expect(func() {
			table.Apply()
		}).To(Panic())
	})

	Describe("after inserting a rule", func() {
		BeforeEach(func() {
			table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
				{Match: nftables.Match(), Action: DropAction{}},
			})
			table.Apply()
			Expect(f.transactions).To(HaveLen(1))
		})

		It("should be in the dataplane", func() {
			rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
			Expect(err).NotTo(HaveOccurred())
			Expect(rules).To(ContainRule(knftables.Rule{
				Chain:   "filter-FORWARD",
				Rule:    "counter drop",
				Comment: ptr("cali:DCGauXoHP5A9-AIO;"),
			}))
		})

		It("further inserts should be idempotent", func() {
			table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
				{Match: nftables.Match(), Action: DropAction{}},
			})
			table.Apply()

			rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
			Expect(err).NotTo(HaveOccurred())
			Expect(rules).To(ContainRule(knftables.Rule{
				Chain:   "filter-FORWARD",
				Rule:    "counter drop",
				Comment: ptr("cali:DCGauXoHP5A9-AIO;"),
			}))
		})

		Describe("after inserting a rule then updating the insertions", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
					{Match: nftables.Match(), Action: DropAction{}},
					{Match: nftables.Match(), Action: AcceptAction{}},
					{Match: nftables.Match(), Action: DropAction{}},
					{Match: nftables.Match(), Action: AcceptAction{}},
				})
				table.Apply()
				Expect(f.transactions).To(HaveLen(2))
			})

			It("should update the dataplane", func() {
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRules([]knftables.Rule{
					{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:DCGauXoHP5A9-AIO;")},
					{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:6tpY0LmXqEPD5dsI;")},
					{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:_Zdh35A6d8kLWs7z;")},
					{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:K23j5egouXzd1qRD;")},
				}))
			})
		})

		Describe("after another process removes the insertion (empty chain)", func() {
			BeforeEach(func() {
				// Remove the chains out-of-band from the Table.
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				tx := f.NewTransaction()
				for _, r := range rules {
					cp := *r
					tx.Delete(&cp)
				}
				Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())
				rules, err = f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(0), "Failed to clean up rules!")
			})

			It("should put it back on the next explicit refresh", func() {
				table.InvalidateDataplaneCache("test")
				table.Apply()
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRules([]knftables.Rule{
					{
						Chain:   "filter-FORWARD",
						Rule:    "counter drop",
						Comment: ptr("cali:DCGauXoHP5A9-AIO;"),
					},
				}))
			})
		})

		Describe("after another process removes an append", func() {
			BeforeEach(func() {
				// Append a rule to the filter-FORWARD base chain, and trigger programming.
				table.AppendRules("filter-FORWARD", []generictables.Rule{
					{Match: nftables.Match(), Action: AcceptAction{}},
				})
				table.Apply()

				// It should be there now.
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(2), "Failed to append rule!")

				// Remove all the rules out-of-band.
				tx := f.NewTransaction()
				for _, r := range rules {
					cp := *r
					tx.Delete(&cp)
				}
				Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())

				// Check it is gone.
				rules, err = f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(0), "Failed to clean up rules!")
			})

			It("should put it back on the next explicit refresh", func() {
				table.InvalidateDataplaneCache("test")
				table.Apply()
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRules([]knftables.Rule{
					{
						Chain:   "filter-FORWARD",
						Rule:    "counter drop",
						Comment: ptr("cali:DCGauXoHP5A9-AIO;"),
					},

					{
						Chain:   "filter-FORWARD",
						Rule:    "counter accept",
						Comment: ptr("cali:Q43zYEHuKfFnJfs1;"),
					},
				}))
			})
		})

		Describe("after another process replaces the insertion (non-empty chain)", func() {
			BeforeEach(func() {
				// Remove the chains out-of-band from the Table.
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				tx := f.NewTransaction()
				for _, r := range rules {
					cp := *r
					tx.Delete(&cp)
				}
				// Add a few rules to the chain as well.
				tx.Add(&knftables.Chain{Name: "ufw-before-logging-forward"})
				tx.Add(&knftables.Chain{Name: "ufw-before-forward"})
				tx.Add(&knftables.Chain{Name: "ufw-after-forward"})
				tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "jump ufw-before-logging-forward"})
				tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "jump ufw-before-forward"})
				tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "jump ufw-after-forward"})
				Expect(f.Run(context.TODO(), tx)).NotTo(HaveOccurred())
				rules, err = f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(3), "Failed to replace rules!")
			})

			It("should put it back on the next refresh", func() {
				table.InvalidateDataplaneCache("test")
				table.Apply()
				rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRules([]knftables.Rule{
					{
						Chain:   "filter-FORWARD",
						Rule:    "counter drop",
						Comment: ptr("cali:DCGauXoHP5A9-AIO;"),
					},
				}))

				// The other chains that don't belong to us should be removed.
				chains, err := f.List(context.TODO(), "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ConsistOf(expectedBaseChains))
			})
		})

		Describe("after adding a couple of chains", func() {
			BeforeEach(func() {
				table.UpdateChains([]*generictables.Chain{
					{Name: "cali-foobar", Rules: []generictables.Rule{
						{Action: AcceptAction{}},
						{Action: DropAction{}},
					}},
					{Name: "cali-bazzbiff", Rules: []generictables.Rule{
						{Action: AcceptAction{}},
						{Action: DropAction{}},
					}},
				})
				table.Apply()
			})

			It("nothing should get programmed due to lack of references", func() {
				chains, err := f.List(context.TODO(), "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ConsistOf(expectedBaseChains))
			})

			Describe("after adding a reference from another unreferenced chain", func() {
				BeforeEach(func() {
					table.UpdateChain(&generictables.Chain{
						Name: "cali-FORWARD",
						Rules: []generictables.Rule{
							{Action: JumpAction{Target: "cali-foobar"}},
						},
					})
					table.Apply()
				})

				It("nothing should get programmed due to having no path back to root chain", func() {
					chains, err := f.List(context.TODO(), "chain")
					Expect(err).NotTo(HaveOccurred())
					Expect(chains).To(ConsistOf(expectedBaseChains))
				})

				Describe("after adding an indirect reference from a base chain", func() {
					BeforeEach(func() {
						table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
							{Action: JumpAction{Target: "cali-FORWARD"}},
						})
						table.Apply()
					})

					It("both chains should be programmed", func() {
						chains, err := f.List(context.TODO(), "chain")
						Expect(err).NotTo(HaveOccurred())
						Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-FORWARD", "cali-foobar")))
					})

					Describe("after deleting the rule from the base chain", func() {
						BeforeEach(func() {
							table.InsertOrAppendRules("filter-FORWARD", nil)
							table.Apply()
						})

						It("should clean up both chains", func() {
							chains, err := f.List(context.TODO(), "chain")
							Expect(err).NotTo(HaveOccurred())
							Expect(chains).To(ConsistOf(expectedBaseChains))
						})
					})

					Describe("after switching the intermediate rule", func() {
						BeforeEach(func() {
							table.UpdateChain(&generictables.Chain{
								Name: "cali-FORWARD",
								Rules: []generictables.Rule{
									{Action: JumpAction{Target: "cali-bazzbiff"}},
								},
							})
							table.Apply()
						})

						It("correct chain should be swapped in", func() {
							chains, err := f.List(context.TODO(), "chain")
							Expect(err).NotTo(HaveOccurred())
							Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-FORWARD", "cali-bazzbiff")))
						})
					})

					Describe("after removing the reference", func() {
						BeforeEach(func() {
							table.UpdateChain(&generictables.Chain{
								Name:  "cali-FORWARD",
								Rules: []generictables.Rule{},
							})
							table.Apply()
						})

						It("should clean up referred chain", func() {
							chains, err := f.List(context.TODO(), "chain")
							Expect(err).NotTo(HaveOccurred())
							Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-FORWARD")))
						})
					})
				})
			})

			Describe("after adding a reference from another referenced chain", func() {
				BeforeEach(func() {
					table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
						{Action: JumpAction{Target: "cali-FORWARD"}},
					})
					table.UpdateChain(&generictables.Chain{
						Name: "cali-FORWARD",
						Rules: []generictables.Rule{
							{Action: JumpAction{Target: "cali-foobar"}},
						},
					})
					table.Apply()
				})

				It("it should get programmed", func() {
					chains, err := f.List(context.TODO(), "chain")
					Expect(err).NotTo(HaveOccurred())
					Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-FORWARD", "cali-foobar")))
				})

				Describe("after adding a reference from an insert", func() {
					BeforeEach(func() {
						table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
							{Action: JumpAction{Target: "cali-foobar"}},
						})
						table.Apply()
					})

					It("intermediate chain should be removed", func() {
						chains, err := f.List(context.TODO(), "chain")
						Expect(err).NotTo(HaveOccurred())
						Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-foobar")))
					})

					Describe("after deleting the intermediate chain", func() {
						BeforeEach(func() {
							table.RemoveChainByName("cali-FORWARD")
							table.Apply()
						})

						It("should make no change", func() {
							chains, err := f.List(context.TODO(), "chain")
							Expect(err).NotTo(HaveOccurred())
							Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-foobar")))
						})

						Describe("after removing the insert", func() {
							BeforeEach(func() {
								table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{})
								table.Apply()
							})
							It("chain should be removed", func() {
								chains, err := f.List(context.TODO(), "chain")
								Expect(err).NotTo(HaveOccurred())
								Expect(chains).To(ConsistOf(expectedBaseChains))
							})
						})
					})
				})
			})

			Describe("after adding a reference from a base chain", func() {
				BeforeEach(func() {
					table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
						{Action: JumpAction{Target: "cali-foobar"}},
					})
					table.Apply()
					Expect(f.transactions).To(HaveLen(2))
				})

				It("it should get programmed", func() {
					chains, err := f.List(context.TODO(), "chain")
					Expect(err).NotTo(HaveOccurred())
					Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-foobar")))

					// Assert the rules are correct.
					rules, err := f.ListRules(context.TODO(), "cali-foobar")
					Expect(err).NotTo(HaveOccurred())
					Expect(rules).To(EqualRules([]knftables.Rule{
						{Chain: "cali-foobar", Rule: "counter accept", Comment: ptr("cali:en3LGdDuVUQEgLl8;")},
						{Chain: "cali-foobar", Rule: "counter drop", Comment: ptr("cali:iSw4pE2oK6hZ-s52;")},
					}))
				})

				Describe("after removing the reference", func() {
					BeforeEach(func() {
						table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{})
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})

					It("it should get removed", func() {
						chains, err := f.List(context.TODO(), "chain")
						Expect(err).NotTo(HaveOccurred())
						Expect(chains).To(ConsistOf(expectedBaseChains))
					})
				})

				Describe("then updating the chain", func() {
					BeforeEach(func() {
						table.UpdateChains([]*generictables.Chain{
							{Name: "cali-foobar", Rules: []generictables.Rule{
								// We swap the rules.
								{Action: DropAction{}},
								{Action: AcceptAction{}},
							}},
						})
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})

					It("should be updated", func() {
						rules, err := f.ListRules(context.TODO(), "cali-foobar")
						Expect(err).NotTo(HaveOccurred())
						Expect(rules).To(EqualRules([]knftables.Rule{
							{Chain: "cali-foobar", Rule: "counter drop", Comment: ptr("cali:qEazjD2XdAvzH1n5;")},
							{Chain: "cali-foobar", Rule: "counter accept", Comment: ptr("cali:0breZU0oqlsEQH-N;")},
						}))
					})

					It("shouldn't get written more than once", func() {
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})

					It("should squash idempotent updates", func() {
						table.UpdateChains([]*generictables.Chain{
							{Name: "cali-foobar", Rules: []generictables.Rule{
								// Same data as above.
								{Action: DropAction{}},
								{Action: AcceptAction{}},
							}},
						})
						Expect(f.transactions).To(HaveLen(3))
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})
				})

				Describe("then extending the chain", func() {
					BeforeEach(func() {
						table.UpdateChains([]*generictables.Chain{
							{Name: "cali-foobar", Rules: []generictables.Rule{
								{Action: AcceptAction{}},
								{Action: DropAction{}},
								{Action: ReturnAction{}},
							}},
						})
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})

					It("should be updated", func() {
						rules, err := f.ListRules(context.TODO(), "cali-foobar")
						Expect(err).NotTo(HaveOccurred())
						Expect(rules).To(EqualRules([]knftables.Rule{
							{Chain: "cali-foobar", Rule: "counter accept", Comment: ptr("cali:en3LGdDuVUQEgLl8;")},
							{Chain: "cali-foobar", Rule: "counter drop", Comment: ptr("cali:iSw4pE2oK6hZ-s52;")},
							{Chain: "cali-foobar", Rule: "counter return", Comment: ptr("cali:UvIbKv-XqfNkFU3a;")},
						}))
					})

					Describe("then truncating the chain", func() {
						BeforeEach(func() {
							table.UpdateChains([]*generictables.Chain{
								{Name: "cali-foobar", Rules: []generictables.Rule{
									{Action: AcceptAction{}},
								}},
							})
							table.Apply()
							Expect(f.transactions).To(HaveLen(4))
						})

						It("should be updated", func() {
							rules, err := f.ListRules(context.TODO(), "cali-foobar")
							Expect(err).NotTo(HaveOccurred())
							Expect(rules).To(EqualRules([]knftables.Rule{
								{Chain: "cali-foobar", Rule: "counter accept", Comment: ptr("cali:en3LGdDuVUQEgLl8;")},
							}))
						})
					})

					Describe("then replacing the chain", func() {
						BeforeEach(func() {
							table.UpdateChains([]*generictables.Chain{
								{Name: "cali-foobar", Rules: []generictables.Rule{
									{Action: ReturnAction{}},
								}},
							})
							table.Apply()
							Expect(f.transactions).To(HaveLen(4))
						})
						It("should be updated", func() {
							rules, err := f.ListRules(context.TODO(), "cali-foobar")
							Expect(err).NotTo(HaveOccurred())
							Expect(rules).To(EqualRulesFuzzy([]knftables.Rule{
								{Chain: "cali-foobar", Rule: "counter return"},
							}))
						})
					})
				})

				Describe("then removing the chain by name", func() {
					BeforeEach(func() {
						table.RemoveChainByName("cali-foobar")
						table.Apply()
						Expect(f.transactions).To(HaveLen(3))
					})

					It("should be gone from the dataplane", func() {
						_, err := f.ListRules(context.TODO(), "cali-foobar")
						Expect(err).To(HaveOccurred())
					})
				})

				Describe("then removing the chain", func() {
					BeforeEach(func() {
						table.RemoveChains([]*generictables.Chain{
							{Name: "cali-foobar", Rules: []generictables.Rule{
								{Action: AcceptAction{}},
								{Action: DropAction{}},
							}},
						})
						table.Apply()
					})
					It("should be gone from the dataplane", func() {
						_, err := f.ListRules(context.TODO(), "cali-foobar")
						Expect(err).To(HaveOccurred())
					})
				})
			})
		})

		Describe("applying updates when underlying rules have changed in a approved chain", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
					{Action: AcceptAction{}},
					{Action: DropAction{}},
					{Action: JumpAction{Target: "cali-foobar"}},
				})
				table.UpdateChains([]*generictables.Chain{
					{Name: "cali-foobar", Rules: []generictables.Rule{
						{Action: AcceptAction{}},
						{Action: DropAction{}},
					}},
				})
				table.Apply()
				Expect(f.transactions).To(HaveLen(2))
			})

			It("should be in the dataplane", func() {
				chains, err := f.List(context.TODO(), "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-foobar")))

				// Assert the rules are correct.
				rules, err := f.ListRules(context.TODO(), "cali-foobar")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRulesFuzzy([]knftables.Rule{
					{Chain: "cali-foobar", Rule: "counter accept"},
					{Chain: "cali-foobar", Rule: "counter drop"},
				}))
				rules, err = f.ListRules(context.TODO(), "filter-FORWARD")
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(EqualRulesFuzzy([]knftables.Rule{
					{Chain: "filter-FORWARD", Rule: "counter accept"},
					{Chain: "filter-FORWARD", Rule: "counter drop"},
					{Chain: "filter-FORWARD", Rule: "counter jump cali-foobar"},
				}))
			})

			Describe("inserting and appending into a base chain results in the expected writes", func() {
				BeforeEach(func() {
					table.AppendRules("filter-FORWARD", []generictables.Rule{
						{Action: DropAction{}, Comment: []string{"append drop rule"}},
						{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
					})
					table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
						{Action: DropAction{}, Comment: []string{"insert drop rule"}},
						{Action: AcceptAction{}, Comment: []string{"insert accept rule"}},
					})

					table.Apply()
					Expect(f.transactions).To(HaveLen(3))
				})

				It("should update the dataplane", func() {
					rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
					Expect(err).NotTo(HaveOccurred())
					Expect(rules).To(EqualRules([]knftables.Rule{
						{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:DCGauXoHP5A9-AIO; insert drop rule")},
						{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:6tpY0LmXqEPD5dsI; insert accept rule")},
						{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:T41ctVF7TLDIehjM; append drop rule")},
						{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:AodlDFLDC_KqOIJO; append accept rule")},
					}))
				})

				Describe("then appending the same rules", func() {
					BeforeEach(func() {
						table.AppendRules("filter-FORWARD", []generictables.Rule{
							{Action: DropAction{}, Comment: []string{"append drop rule"}},
							{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
						})
						table.Apply()

						// No changes should be made.
						Expect(f.transactions).To(HaveLen(3))
					})

					It("should result in no inserts", func() {
						rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
						Expect(err).NotTo(HaveOccurred())
						Expect(rules).To(EqualRulesFuzzy([]knftables.Rule{
							{Chain: "filter-FORWARD", Rule: "counter drop"},
							{Chain: "filter-FORWARD", Rule: "counter accept"},
							{Chain: "filter-FORWARD", Rule: "counter drop"},
							{Chain: "filter-FORWARD", Rule: "counter accept"},
						}))
					})
				})

				Describe("then inserting and appending different rules", func() {
					BeforeEach(func() {
						table.InsertOrAppendRules("filter-FORWARD", []generictables.Rule{
							{Action: DropAction{}, Comment: []string{"insert drop rule"}},
							{Action: AcceptAction{}, Comment: []string{"insert accept rule"}},
							{Action: DropAction{}, Comment: []string{"second insert drop rule"}},
						})
						table.AppendRules("filter-FORWARD", []generictables.Rule{
							{Action: DropAction{}, Comment: []string{"append drop rule"}},
							{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
							{Action: DropAction{}, Comment: []string{"second append drop rule"}},
						})
						table.Apply()
						Expect(f.transactions).To(HaveLen(4))
					})

					It("should result in modifications", func() {
						rules, err := f.ListRules(context.TODO(), "filter-FORWARD")
						Expect(err).NotTo(HaveOccurred())
						Expect(rules).To(EqualRules([]knftables.Rule{
							{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:DCGauXoHP5A9-AIO; insert drop rule")},
							{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:6tpY0LmXqEPD5dsI; insert accept rule")},
							{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:_Zdh35A6d8kLWs7z; second insert drop rule")},
							{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:T41ctVF7TLDIehjM; append drop rule")},
							{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:AodlDFLDC_KqOIJO; append accept rule")},
							{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:tmCXGknk3dgfLo6d; second append drop rule")},
						}))
					})
				})
			})
		})
	})

	Context("map programming", func() {
		It("should program and delete a map + referenced chains", func() {
			// Add chains (but leave them unreferenced - the map will reference them).
			table.UpdateChain(&generictables.Chain{
				Name: "cali-tw-1234",
				Rules: []generictables.Rule{
					{Action: AcceptAction{}},
				},
			})
			table.UpdateChain(&generictables.Chain{
				Name: "cali-tw-5678",
				Rules: []generictables.Rule{
					{Action: DropAction{}},
				},
			})

			// Send the map add.
			meta := nftables.MapMetadata{Name: "cali-tw-dispatch", Type: nftables.MapTypeInterfaceMatch}
			members := map[string][]string{"cali1234": {"jump cali-tw-1234"}, "cali5678": {"jump cali-tw-5678"}}
			table.AddOrReplaceMap(meta, members)

			// Verify that the map is queued for programming.
			upd := table.MapUpdates()
			Expect(upd.MapsToCreate).To(HaveLen(1))

			table.Apply()
			Expect(f.transactions).To(HaveLen(1))

			// Expect the map to be in the dataplane.
			maps, err := f.List(context.TODO(), "maps")
			Expect(err).NotTo(HaveOccurred())
			Expect(maps).To(ConsistOf([]string{"cali-tw-dispatch"}))

			// It should have two members.
			dpMembers, err := f.ListElements(context.TODO(), "map", "cali-tw-dispatch")
			Expect(err).NotTo(HaveOccurred())
			Expect(dpMembers).To(HaveLen(2))

			// There should be two chains programmed.
			chains, err := f.List(context.TODO(), "chain")
			Expect(err).NotTo(HaveOccurred())
			Expect(chains).To(ConsistOf(append(expectedBaseChains, "cali-tw-1234", "cali-tw-5678")))

			// Deleting the map should remove it from the dataplane, as well as the referenced chains.
			table.RemoveMap("cali-tw-dispatch")
			table.Apply()

			// Expect the map to be gone.
			maps, err = f.List(context.TODO(), "maps")
			Expect(err).NotTo(HaveOccurred())
			Expect(maps).NotTo(ContainElement("cali-tw-dispatch"))

			// Expect the referenced chains to be gone.
			chains, err = f.List(context.TODO(), "chain")
			Expect(err).NotTo(HaveOccurred())
			Expect(chains).To(ConsistOf(expectedBaseChains))
		})
	})
})

var _ = Describe("Insert early rules", func() {
	var table generictables.Table
	var featureDetector *environment.FeatureDetector
	var f *fakeNFT
	BeforeEach(func() {
		newDataplane := func(fam knftables.Family, name string) (knftables.Interface, error) {
			f = NewFake(fam, name)
			return f, nil
		}
		featureDetector = environment.NewFeatureDetector(nil)
		table = NewTable(
			"cali-filter",
			4,
			rules.RuleHashPrefix,
			featureDetector,
			TableOptions{
				NewDataplane:     newDataplane,
				LookPathOverride: testutils.LookPathNoLegacy,
				OpRecorder:       logutils.NewSummarizer("test loop"),
			},
			true,
		)
	})

	It("should insert rules immediately without Apply", func() {
		rls := []generictables.Rule{
			{Action: DropAction{}, Comment: []string{"my rule"}},
			{Action: AcceptAction{}, Comment: []string{"my other rule"}},
		}

		err := table.InsertRulesNow("filter-FORWARD", rls)
		Expect(err).NotTo(HaveOccurred())

		// Expect chains.
		chains, err := f.List(context.Background(), "chain")
		Expect(err).NotTo(HaveOccurred())
		Expect(chains).To(ConsistOf([]string{"filter-FORWARD"}))

		// Expect rules
		rules, err := f.ListRules(context.Background(), "filter-FORWARD")
		Expect(err).NotTo(HaveOccurred())
		Expect(rules).To(EqualRules([]knftables.Rule{
			{Chain: "filter-FORWARD", Rule: "counter accept", Comment: ptr("cali:6tpY0LmXqEPD5dsI; my other rule")},
			{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("cali:DCGauXoHP5A9-AIO; my rule")},
		}))
	})

	It("should find out if rules already present", func() {
		rls := []generictables.Rule{
			{Action: DropAction{}, Comment: []string{"my rule"}},
			{Action: AcceptAction{}, Comment: []string{"my other rule"}},
		}

		// Init chains
		hashes := []string{"DCGauXoHP5A9-AIO", "6tpY0LmXqEPD5dsI"}
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Chain{Name: "filter-FORWARD"})
		tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "counter drop", Comment: &hashes[0]})
		tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "counter accept", Comment: &hashes[1]})
		tx.Add(&knftables.Rule{Chain: "filter-FORWARD", Rule: "counter drop", Comment: ptr("some rule")})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())

		res := table.CheckRulesPresent("filter-FORWARD", rls)
		Expect(res).To(HaveLen(2))
	})
})
