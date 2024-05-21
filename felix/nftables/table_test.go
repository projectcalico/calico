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

	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/iptables/testutils"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/nftables"
	. "github.com/projectcalico/calico/felix/nftables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

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
			"calico",
			4,
			rules.RuleHashPrefix,
			featureDetector,
			TableOptions{
				NewDataplane:     newDataplane,
				LookPathOverride: testutils.LookPathNoLegacy,
				OpRecorder:       logutils.NewSummarizer("test loop"),
			},
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
})

// })
//
// var _ = Describe("Tests of post-update recheck behaviour with refresh timer (nft)", func() {
// 	describePostUpdateCheckTests(true, "nft")
// })
//
// var _ = Describe("Tests of post-update recheck behaviour with no refresh timer (nft)", func() {
// 	describePostUpdateCheckTests(false, "nft")
// })
//
// var _ = Describe("Tests of post-update recheck behaviour with refresh timer (legacy)", func() {
// 	describePostUpdateCheckTests(true, "legacy")
// })
//
// var _ = Describe("Tests of post-update recheck behaviour with no refresh timer (legacy)", func() {
// 	describePostUpdateCheckTests(false, "legacy")
// })
//
// func describePostUpdateCheckTests(enableRefresh bool, dataplaneMode string) {
// 	var dataplane *testutils.MockDataplane
// 	var table generictables.Table
// 	var requestedDelay time.Duration
//
// 	BeforeEach(func() {
// 		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
// 			"FORWARD": {},
// 			"INPUT":   {},
// 			"OUTPUT":  {},
// 		}, dataplaneMode)
// 		options := TableOptions{
// 			HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
// 			NewCmdOverride:        dataplane.NewCmd,
// 			SleepOverride:         dataplane.Sleep,
// 			NowOverride:           dataplane.Now,
// 			LookPathOverride:      testutils.LookPathNoLegacy,
// 			OpRecorder:            logutils.NewSummarizer("test loop"),
// 		}
// 		if enableRefresh {
// 			options.RefreshInterval = 30 * time.Second
// 		}
// 		featureDetector := environment.NewFeatureDetector(nil)
// 		featureDetector.NewCmd = dataplane.NewCmd
// 		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
// 		table = NewTable(
// 			"filter",
// 			4,
// 			rules.RuleHashPrefix,
// 			featureDetector,
// 			options,
// 		)
// 		table.InsertOrAppendRules("FORWARD", []generictables.Rule{
// 			{Action: DropAction{}},
// 		})
// 		table.Apply()
// 	})
//
// 	resetAndAdvance := func(amount time.Duration) func() {
// 		return func() {
// 			dataplane.ResetCmds()
// 			dataplane.AdvanceTimeBy(amount)
// 			requestedDelay = table.Apply()
// 		}
// 	}
// 	assertRecheck := func() {
// 		if dataplaneMode == "nft" {
// 			Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save"))
// 		} else {
// 			Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save"))
// 		}
// 	}
// 	assertDelayMillis := func(delay int64) func() {
// 		return func() {
// 			Expect(requestedDelay).To(Equal(time.Duration(delay) * time.Millisecond))
// 		}
// 	}
// 	assertNoCheck := func() {
// 		Expect(dataplane.CmdNames).To(BeEmpty())
// 	}
//
// 	Describe("with slow dataplane", func() {
// 		const saveTime = 200 * time.Millisecond
// 		const restoreTime = 800 * time.Millisecond
//
// 		BeforeEach(func() {
// 			dataplane.OnPreSave = func() {
// 				dataplane.AdvanceTimeBy(saveTime)
// 			}
// 			dataplane.OnPreRestore = func() {
// 				dataplane.AdvanceTimeBy(restoreTime)
// 			}
//
// 			// Just a random change to trigger a save/restore.
// 			table.InsertOrAppendRules("FORWARD", []generictables.Rule{
// 				{Action: AcceptAction{}},
// 			})
// 			table.Apply()
// 		})
//
// 		// Recheck will be delayed to at least (save time + restore time) * 2.
// 		Describe("after advancing time 1995ms", func() {
// 			BeforeEach(resetAndAdvance(1995 * time.Millisecond))
// 			It("should not recheck", assertNoCheck)
// 			It("should request correct delay", assertDelayMillis(5))
//
// 			Describe("after advancing time to 2s", func() {
// 				BeforeEach(resetAndAdvance(5 * time.Millisecond))
// 				It("should recheck", assertRecheck)
// 				It("should request correct delay", assertDelayMillis(2000))
//
// 				Describe("after dataplane speeds up again", func() {
// 					BeforeEach(func() {
// 						table.InsertOrAppendRules("FORWARD", []generictables.Rule{
// 							{Action: DropAction{}},
// 						})
// 					})
// 					BeforeEach(resetAndAdvance(0))
//
// 					It("should request correct delay", func() {
// 						// After the first call, time won't advance any more so
// 						// the peak values will start to decay with each call.
// 						const decayedSaveTime = saveTime * 99 / 100 * 99 / 100
// 						const decayedRestoreTime = restoreTime * 99 / 100
// 						const expectedDelay = 2 * (decayedSaveTime + decayedRestoreTime)
// 						Expect(requestedDelay).To(Equal(expectedDelay))
// 					})
// 				})
// 			})
// 		})
// 	})
//
// 	Describe("after advancing time 49ms", func() {
// 		BeforeEach(resetAndAdvance(49 * time.Millisecond))
// 		It("should not recheck", assertNoCheck)
// 		It("should request correct delay", assertDelayMillis(1))
//
// 		Describe("after advancing time to 50ms", func() {
// 			BeforeEach(resetAndAdvance(1 * time.Millisecond))
// 			It("should recheck", assertRecheck)
// 			It("should request correct delay", assertDelayMillis(50))
//
// 			Describe("after advancing time to 51ms", func() {
// 				BeforeEach(resetAndAdvance(1 * time.Millisecond))
// 				It("should not recheck", assertNoCheck)
// 				It("should request correct delay", assertDelayMillis(49))
//
// 				Describe("after advancing time to 100ms", func() {
// 					BeforeEach(resetAndAdvance(49 * time.Millisecond))
// 					It("should recheck", assertRecheck)
// 					It("should request correct delay", assertDelayMillis(100))
// 				})
// 			})
// 		})
// 		Describe("after advancing time to 999ms", func() {
// 			BeforeEach(resetAndAdvance(950 * time.Millisecond))
// 			It("should recheck", assertRecheck)
// 			It("should request correct delay", assertDelayMillis(601)) // i.e. at 1.6s
//
// 			if enableRefresh {
// 				Describe("after advancing time 60s", func() {
// 					BeforeEach(resetAndAdvance(60 * time.Second))
// 					It("should recheck", assertRecheck)
//
// 					// Now waiting for the next refresh interval.
// 					It("should request correct delay", assertDelayMillis(30000))
// 				})
// 				Describe("after advancing time by an hour", func() {
// 					BeforeEach(resetAndAdvance(time.Hour))
// 					It("should recheck", assertRecheck)
//
// 					// Now waiting for the next refresh interval.
// 					It("should request correct delay", assertDelayMillis(30000))
//
// 					Describe("after advancing time by an hour", func() {
// 						BeforeEach(resetAndAdvance(time.Hour))
// 						It("should recheck", assertRecheck)
//
// 						// Now waiting for the next refresh interval.
// 						It("should request correct delay", assertDelayMillis(30000))
// 					})
// 				})
// 			} else {
// 				Describe("after advancing time 60s", func() {
// 					BeforeEach(resetAndAdvance(60 * time.Second))
// 					It("should recheck", assertRecheck)
//
// 					// Refresh disabled, it just keeps increasing
// 					It("should request correct delay", assertDelayMillis(41401))
// 				})
// 				Describe("after advancing time by an hour", func() {
// 					BeforeEach(resetAndAdvance(time.Hour))
// 					// Last recheck due to the post-write check.
// 					It("should recheck", assertRecheck)
//
// 					// Then, it should give up.
// 					It("should request correct delay", assertDelayMillis(0))
//
// 					Describe("after advancing time by an hour", func() {
// 						BeforeEach(resetAndAdvance(time.Hour))
// 						It("should not recheck", assertNoCheck)
// 						It("should request correct delay", assertDelayMillis(0))
// 					})
// 				})
// 			}
// 		})
// 	})
// }

// var _ = Describe("Table with a dirty dataplane in append mode (nft)", func() {
// 	describeDirtyDataplaneTests(true, "nft")
// })
//
// var _ = Describe("Table with a dirty dataplane in insert mode (nft)", func() {
// 	describeDirtyDataplaneTests(false, "nft")
// })
//
// var _ = Describe("Table with a dirty dataplane in append mode (legacy)", func() {
// 	describeDirtyDataplaneTests(true, "legacy")
// })
//
// var _ = Describe("Table with a dirty dataplane in insert mode (legacy)", func() {
// 	describeDirtyDataplaneTests(false, "legacy")
// })
//
// func describeDirtyDataplaneTests(appendMode bool, dataplaneMode string) {
// 	// These tests all start with some rules already in the dataplane.  We include a mix of
// 	// Calico and non-Calico rules.  Within the Calico rules,we include:
// 	// - rules that match what we're going to ask the Table to program
// 	// - rules that differ and need to be detected/replaced
// 	// - rules that are unexpected (in chains that need to be removed)
// 	// - rules from previous Calico versions, using different chain name prefixes
// 	// - rules that only match the special-case regex.
// 	var dataplane *testutils.MockDataplane
// 	var table generictables.Table
// 	initialChains := func() map[string][]string {
// 		return map[string][]string{
// 			"FORWARD": {
// 				// Non-calico rule
// 				"--jump RETURN",
// 				// Stale calico rules
// 				"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 				"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 				// Non-calico rule
// 				"--jump ACCEPT",
// 				// Old calico rule.  should be cleaned up.
// 				"-j felix-FORWARD",
// 				"--jump felix-FORWARD",
// 				// Regex-matched rule.  should be cleaned up.
// 				"--jump sneaky-rule",
// 				// Non-calico rule
// 				"--jump foo-bar",
// 			},
// 			"INPUT": {
// 				// This rule will get cleaned up because we don't insert any rules
// 				// into the INPUT chain in this test.
// 				"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 			},
// 			"OUTPUT": {
// 				// This rule will get rewritten because its hash is incorrect.
// 				"-m comment --comment \"cali:1234567890ksamdl\" --jump DROP",
// 			},
// 			"unexpected-insert": {
// 				"--jump ACCEPT",
// 				// This rule will get cleaned up because it looks like a Calico
// 				// insert rule but it's in a chain that we don't insert anything
// 				// into.
// 				"-m comment --comment \"cali:hecdSCslEjdBPfds\" --jump DROP",
// 				"--jump DROP",
// 			},
// 			// Calico chain from previous version.  Should be cleaned up.
// 			"felix-FORWARD": {
// 				"--jump ACCEPT",
// 			},
// 			"cali-correct": {
// 				"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
// 			},
// 			"cali-foobar": {
// 				"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
// 				"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
// 				"-m comment --comment \"cali:deadbeef09238384\" --jump RETURN",
// 			},
// 			"cali-stale": {
// 				"-m comment --comment \"cali:qwebjbdfjadfndns\" --jump ACCEPT",
// 				"-m comment --comment \"cali:abcdeflakdjfladj\" --jump DROP",
// 			},
// 			"non-calico": {
// 				"--jump ACCEPT",
// 			},
// 		}
// 	}
//
// 	BeforeEach(func() {
// 		dataplane = testutils.NewMockDataplane("filter", initialChains(), dataplaneMode)
// 		featureDetector := environment.NewFeatureDetector(nil)
// 		featureDetector.NewCmd = dataplane.NewCmd
// 		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
// 		table = NewTable(
// 			"filter",
// 			4,
// 			rules.RuleHashPrefix,
// 			featureDetector,
// 			TableOptions{
// 				HistoricChainPrefixes:    rules.AllHistoricChainNamePrefixes,
// 				ExtraCleanupRegexPattern: "sneaky-rule",
// 				NewCmdOverride:           dataplane.NewCmd,
// 				SleepOverride:            dataplane.Sleep,
// 				LookPathOverride:         testutils.LookPathNoLegacy,
// 				OpRecorder:               logutils.NewSummarizer("test loop"),
// 			},
// 		)
// 	})
//
// 	It("should clean up on first Apply()", func() {
// 		table.Apply()
// 		Expect(dataplane.Chains).To(Equal(map[string][]string{
// 			"FORWARD": {
// 				// Non-calico rule
// 				"--jump RETURN",
// 				// Non-calico rule
// 				"--jump ACCEPT",
// 				// Non-calico rule
// 				"--jump foo-bar",
// 			},
// 			"INPUT":  {},
// 			"OUTPUT": {},
// 			"non-calico": {
// 				"--jump ACCEPT",
// 			},
// 			"unexpected-insert": {
// 				"--jump ACCEPT",
// 				"--jump DROP",
// 			},
// 		}))
// 	})
//
// 	Describe("with pre-cleanup inserts, appends and updates", func() {
// 		// These tests inject some chains and insertions before the first call to Apply().
// 		// That should mean that the Table does a sync operation, avoiding updates to
// 		// chains/rules that haven't changed, for example.
// 		BeforeEach(func() {
// 			table.InsertOrAppendRules("FORWARD", []generictables.Rule{
// 				{Action: DropAction{}},
// 				{Action: AcceptAction{}},
// 				{Action: GotoAction{Target: "cali-foobar"}},
// 			})
// 			table.AppendRules("FORWARD", []generictables.Rule{
// 				{Action: ReturnAction{}},
// 				{Action: DropAction{}},
// 			})
// 			table.InsertOrAppendRules("OUTPUT", []generictables.Rule{
// 				{Action: DropAction{}},
// 				{Action: JumpAction{Target: "cali-correct"}},
// 			})
// 			table.UpdateChains([]*generictables.Chain{
// 				{Name: "cali-foobar", Rules: []generictables.Rule{
// 					{Action: AcceptAction{}},
// 					{Action: DropAction{}},
// 					{Action: ReturnAction{}},
// 				}},
// 			})
// 			table.UpdateChains([]*generictables.Chain{
// 				{Name: "cali-correct", Rules: []generictables.Rule{
// 					{Action: AcceptAction{}},
// 				}},
// 			})
// 		})
// 		checkFinalState := func() {
// 			expChains := map[string][]string{
// 				"cali-foobar": {
// 					"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
// 					"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
// 					"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
// 				},
// 				"unexpected-insert": {
// 					"--jump ACCEPT",
// 					"--jump DROP",
// 				},
// 				"INPUT": {},
// 				"OUTPUT": {
// 					"-m comment --comment \"cali:RtPHXnCQBd3uyJfJ\" --jump DROP",
// 					"-m comment --comment \"cali:Eq8toINAJuMTNYmX\" --jump cali-correct",
// 				},
// 				"non-calico": {
// 					"--jump ACCEPT",
// 				},
// 				"cali-correct": {
// 					"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
// 				},
// 			}
//
// 			if appendMode {
// 				expChains["FORWARD"] = []string{
// 					"--jump RETURN",
// 					"--jump ACCEPT",
// 					"--jump foo-bar",
// 					"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 					"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 					"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
// 					"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
// 					"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
// 				}
// 			} else {
// 				expChains["FORWARD"] = []string{
// 					"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 					"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 					"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
// 					"--jump RETURN",
// 					"--jump ACCEPT",
// 					"--jump foo-bar",
// 					"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
// 					"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
// 				}
// 			}
//
// 			ExpectWithOffset(1, dataplane.Chains).To(Equal(expChains))
// 		}
// 		It("with no errors, it should get to correct final state", func() {
// 			table.Apply()
// 			checkFinalState()
// 			Expect(dataplane.Cmds).To(HaveLen(3)) // a version, save and a restore
// 		})
// 		It("with no errors, it shouldn't sleep", func() {
// 			table.Apply()
// 			Expect(dataplane.CumulativeSleep).To(BeZero())
// 		})
// 		assertOneRetry := func() {
// 			It("it should get to correct final state", func() {
// 				checkFinalState()
// 			})
// 			It("it should retry once", func() {
// 				Expect(dataplane.Cmds).To(HaveLen(4)) // a version, 2 saves and a restore
// 			})
// 			It("it should sleep", func() {
// 				Expect(dataplane.CumulativeSleep).To(Equal(100 * time.Millisecond))
// 			})
// 		}
// 		Describe("With a transient iptables-save failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailNextSaveRead = true
// 				table.Apply()
// 			})
// 			assertOneRetry()
// 		})
// 		Describe("With a transient iptables-save failure and a kill failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailNextSaveRead = true
// 				dataplane.FailNextKill = true
// 			})
// 			It("should panic", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 			})
// 		})
// 		Describe("With a transient iptables-save pipe-close failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailNextPipeClose = true
// 				table.Apply()
// 			})
// 			assertOneRetry()
// 		})
// 		Describe("With a transient iptables-save start failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailNextStart = true
// 				table.Apply()
// 			})
// 			assertOneRetry()
// 			It("should close the pipes", func() {
// 				Expect(dataplane.PipeBuffers).To(HaveLen(2))
// 				for _, pb := range dataplane.PipeBuffers {
// 					Expect(pb.Closed).To(BeTrue())
// 				}
// 			})
// 		})
// 		Describe("With a transient iptables-save start and pipe-close failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailNextStart = true
// 				dataplane.FailNextPipeClose = true
// 				table.Apply()
// 			})
// 			assertOneRetry()
// 			It("should close the pipes", func() {
// 				Expect(dataplane.PipeBuffers).To(HaveLen(2))
// 				for _, pb := range dataplane.PipeBuffers {
// 					Expect(pb.Closed).To(BeTrue())
// 				}
// 			})
// 		})
// 		Describe("With a persistent iptables-save failure", func() {
// 			BeforeEach(func() {
// 				dataplane.FailAllSaves = true
// 			})
// 			It("it should panic", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 			}, 1)
// 			It("it should do exponential backoff", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 				Expect(dataplane.CumulativeSleep).To(Equal((100 + 200 + 400) * time.Millisecond))
// 			}, 1)
// 			It("it should retry 3 times", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 				Expect(dataplane.Cmds).To(HaveLen(5))
// 			}, 1)
// 		})
//
// 		It("shouldn't touch already-correct chain", func() {
// 			table.Apply()
// 			Expect(dataplane.RuleTouched("cali-correct", 1)).To(BeFalse())
// 		})
// 		if dataplaneMode == "legacy" {
// 			It("shouldn't touch already-correct rules", func() {
// 				table.Apply()
// 				// First two rules are already correct...
// 				Expect(dataplane.RuleTouched("cali-foobar", 1)).To(BeFalse())
// 				Expect(dataplane.RuleTouched("cali-foobar", 2)).To(BeFalse())
// 				// Third rule is incorrect.
// 				Expect(dataplane.RuleTouched("cali-foobar", 3)).To(BeTrue())
// 			})
// 		} else {
// 			// In nft mode, we have to rewrite the whole chain if there's any change.
// 			It("should rewrite whole chain", func() {
// 				table.Apply()
// 				// First two rules are already correct...
// 				Expect(dataplane.RuleTouched("cali-foobar", 1)).To(BeTrue())
// 				Expect(dataplane.RuleTouched("cali-foobar", 2)).To(BeTrue())
// 				// Third rule is incorrect.
// 				Expect(dataplane.RuleTouched("cali-foobar", 3)).To(BeTrue())
// 			})
// 		}
// 		It("with a transient error, it should get to correct final state", func() {
// 			// First write to iptables fails; Table should simply retry.
// 			log.Info("About to do a failing Apply().")
// 			dataplane.FailNextRestore = true
// 			table.Apply()
// 			Expect(dataplane.FailNextRestore).To(BeFalse()) // Flag should be reset
// 			checkFinalState()
// 		})
// 		Describe("with a persistent iptables-restore error", func() {
// 			BeforeEach(func() {
// 				dataplane.FailAllRestores = true
// 			})
// 			It("it should panic", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 			}, 1)
// 			It("it should do exponential backoff", func() {
// 				Expect(func() {
// 					table.Apply()
// 				}).To(Panic())
// 				Expect(dataplane.CumulativeSleep).To(Equal(
// 					(1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512) * time.Millisecond))
// 			}, 1)
// 		})
//
// 		Describe("with a simulated clobber of chains before first write", func() {
// 			BeforeEach(func() {
// 				// After the iptables-save call but before the iptables-restore, another
// 				// process comes in and clobbers the dataplane, causing a failure.  It
// 				// should reload and do the right thing.
// 				dataplane.OnPreRestore = func() {
// 					dataplane.Chains = map[string][]string{
// 						"FORWARD": {},
// 						"INPUT":   {},
// 						"OUTPUT":  {},
// 					}
// 				}
// 				dataplane.FailNextRestore = true
// 				table.Apply()
// 			})
// 			It("should get to correct final state", func() {
// 				Expect(dataplane.Chains).To(Equal(map[string][]string{
// 					"FORWARD": {
// 						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
// 						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
// 						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
// 					},
// 					"cali-foobar": {
// 						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
// 						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
// 						"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
// 					},
// 					"INPUT": {},
// 					"OUTPUT": {
// 						"-m comment --comment \"cali:RtPHXnCQBd3uyJfJ\" --jump DROP",
// 						"-m comment --comment \"cali:Eq8toINAJuMTNYmX\" --jump cali-correct",
// 					},
// 					"cali-correct": {
// 						"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
// 					},
// 				}))
// 			})
// 			It("should sleep for correct time", func() {
// 				Expect(dataplane.CumulativeSleep).To(Equal(1 * time.Millisecond))
// 			})
// 		})
//
// 		Describe("with a clobber after initial write", func() {
// 			// These tests allow the first write to succeed so that the Table's cache
// 			// of the dataplane state is primed with the Calico chains.  Then they
// 			// simulate another process clobbering our chains and restoring them back to
// 			// the old state.
// 			BeforeEach(func() {
// 				// First write, should succeed normally.
// 				table.Apply()
// 				checkFinalState()
// 				// Then another process trashes the state, restoring it to the old
// 				// state.
// 				dataplane.Chains = initialChains()
// 				// Explicitly invalidate the cache to simulate a timer refresh.
// 				table.InvalidateDataplaneCache("test")
// 			})
// 			It("should get to correct state", func() {
// 				// Next Apply() should fix it.
// 				table.Apply()
// 				checkFinalState()
// 			})
// 			It("it shouldn't sleep", func() {
// 				table.Apply()
// 				Expect(dataplane.CumulativeSleep).To(BeZero())
// 			})
// 			It("and pending updates, should get to correct state", func() {
// 				// And we make some updates in the same batch.
// 				table.InsertOrAppendRules("OUTPUT", []generictables.Rule{
// 					{Action: AcceptAction{}},
// 					{Action: JumpAction{Target: "cali-correct"}},
// 				})
// 				table.UpdateChains([]*generictables.Chain{
// 					{Name: "cali-foobar", Rules: []generictables.Rule{
// 						{Action: AcceptAction{}},
// 						{Action: ReturnAction{}},
// 					}},
// 				})
// 				// Next Apply() should refresh then put everything in sync.
// 				table.Apply()
//
// 				expChains := map[string][]string{
// 					"cali-foobar": {
// 						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
// 						"-m comment --comment \"cali:ilM9uz5oPwfm0FE-\" --jump RETURN",
// 					},
// 					"unexpected-insert": {
// 						"--jump ACCEPT",
// 						"--jump DROP",
// 					},
// 					"INPUT": {},
// 					"OUTPUT": {
// 						"-m comment --comment \"cali:CZ70AKmne2ck3c5b\" --jump ACCEPT",
// 						"-m comment --comment \"cali:7XdOSW_DYWLuCNDD\" --jump cali-correct",
// 					},
// 					"non-calico": {
// 						"--jump ACCEPT",
// 					},
// 					"cali-correct": {
// 						"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
// 					},
// 				}
//
// 				if appendMode {
// 					expChains["FORWARD"] = []string{
// 						"--jump RETURN",
// 						"--jump ACCEPT",
// 						"--jump foo-bar",
// 						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
// 						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
// 						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
// 					}
// 				} else {
// 					expChains["FORWARD"] = []string{
// 						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
// 						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
// 						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
// 						"--jump RETURN",
// 						"--jump ACCEPT",
// 						"--jump foo-bar",
// 						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
// 						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
// 					}
// 				}
//
// 				Expect(dataplane.Chains).To(Equal(expChains))
// 			})
// 		})
// 	})
// }

// var _ = Describe("Table with inserts and a non-Calico chain (legacy)", func() {
// 	describeInsertAndNonCalicoChainTests("legacy")
// })
//
// var _ = Describe("Table with inserts and a non-Calico chain (nft)", func() {
// 	describeInsertAndNonCalicoChainTests("nft")
// })
//
// func describeInsertAndNonCalicoChainTests(dataplaneMode string) {
// 	var dataplane *testutils.MockDataplane
// 	var table generictables.Table
// 	BeforeEach(func() {
// 		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
// 			"FORWARD":    {},
// 			"non-calico": {"-m comment \"foo\""},
// 		}, dataplaneMode)
// 		featureDetector := environment.NewFeatureDetector(nil)
// 		featureDetector.NewCmd = dataplane.NewCmd
// 		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
// 		table = NewTable(
// 			"filter",
// 			6,
// 			rules.RuleHashPrefix,
// 			featureDetector,
// 			TableOptions{
// 				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
// 				NewCmdOverride:        dataplane.NewCmd,
// 				SleepOverride:         dataplane.Sleep,
// 				NowOverride:           dataplane.Now,
// 				LookPathOverride:      testutils.LookPathNoLegacy,
// 				OpRecorder:            logutils.NewSummarizer("test loop"),
// 			},
// 		)
// 		table.InsertOrAppendRules("FORWARD", []generictables.Rule{
// 			{Action: DropAction{}},
// 		})
// 		table.Apply()
// 	})
//
// 	It("should do the insertion", func() {
// 		Expect(dataplane.Chains).To(Equal(map[string][]string{
// 			"FORWARD":    {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
// 			"non-calico": {"-m comment \"foo\""},
// 		}))
// 	})
//
// 	Describe("after removing the other chain", func() {
// 		BeforeEach(func() {
// 			dataplane.Chains = map[string][]string{
// 				"FORWARD": {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
// 			}
// 			dataplane.ResetCmds()
// 			table.Apply()
// 		})
//
// 		It("should ignore the deletion", func() {
// 			Expect(dataplane.Chains).To(Equal(map[string][]string{
// 				"FORWARD": {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
// 			}))
// 		})
// 		It("should make no changes to the dataplane", func() {
// 			Expect(dataplane.CmdNames).To(BeEmpty())
// 		})
// 	})
// }

// var _ = Describe("Insert early rules (legacy)", func() {
// 	describeInsertEarlyRules("legacy")
// })
//
// var _ = Describe("Insert early rules (nft)", func() {
// 	describeInsertEarlyRules("nft")
// })
//
// func describeInsertEarlyRules(dataplaneMode string) {
// 	var dataplane *testutils.MockDataplane
// 	var table generictables.Table
// 	var featureDetector *environment.FeatureDetector
// 	BeforeEach(func() {
// 		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
// 			"FORWARD": {"-m comment --comment \"some rule\""},
// 		}, dataplaneMode)
// 		featureDetector = environment.NewFeatureDetector(nil)
// 		featureDetector.NewCmd = dataplane.NewCmd
// 		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
// 		table = NewTable(
// 			"cali-filter",
// 			4,
// 			rules.RuleHashPrefix,
// 			featureDetector,
// 			TableOptions{
// 				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
// 				NewCmdOverride:        dataplane.NewCmd,
// 				SleepOverride:         dataplane.Sleep,
// 				NowOverride:           dataplane.Now,
// 				LookPathOverride:      testutils.LookPathNoLegacy,
// 				OpRecorder:            logutils.NewSummarizer("test loop"),
// 			},
// 		)
// 	})
//
// 	It("should insert rules immediately without Apply", func() {
// 		rls := []generictables.Rule{
// 			{Action: DropAction{}, Comment: []string{"my rule"}},
// 			{Action: AcceptAction{}, Comment: []string{"my other rule"}},
// 		}
//
// 		hashes := CalculateRuleHashes("FORWARD", rls, featureDetector.GetFeatures())
//
// 		err := table.InsertRulesNow("FORWARD", rls)
// 		Expect(err).NotTo(HaveOccurred())
//
// 		Expect(dataplane.Chains).To(Equal(map[string][]string{
// 			"FORWARD": {
// 				"-m comment --comment \"" + rules.RuleHashPrefix + hashes[0] +
// 					"\" -m comment --comment \"my rule\" --jump DROP",
// 				"-m comment --comment \"" + rules.RuleHashPrefix + hashes[1] +
// 					"\" -m comment --comment \"my other rule\" --jump ACCEPT",
// 				"-m comment --comment \"some rule\"",
// 			},
// 		}))
// 	})
//
// 	It("should find out if rules already present", func() {
// 		rls := []generictables.Rule{
// 			{Action: DropAction{}, Comment: []string{"my rule"}},
// 			{Action: AcceptAction{}, Comment: []string{"my other rule"}},
// 		}
//
// 		hashes := CalculateRuleHashes("FORWARD", rls, featureDetector.GetFeatures())
//
// 		// Init chains
// 		dataplane.Chains = map[string][]string{
// 			"FORWARD": {
// 				"-m comment --comment \"" + rules.RuleHashPrefix + hashes[0] +
// 					"\" -m comment --comment \"my rule\" --jump DROP",
// 				"-m comment --comment \"" + rules.RuleHashPrefix + hashes[1] +
// 					"\" -m comment --comment \"my other rule\" --jump ACCEPT",
// 				"-m comment --comment \"some rule\"",
// 			},
// 		}
//
// 		res := table.CheckRulesPresent("FORWARD", rls)
//
// 		Expect(res).To(HaveLen(2))
// 	})
// }

// 	Describe("with nftables returning an nft error", func() {
// 		BeforeEach(func() {
// 			dataplane.Prologue = "# Table `nat' is incompatible, use 'nft' tool.\n"
// 		})
//
// 		It("should fail", func() {
// 			Expect(func() {
// 				table.Apply()
// 			}).To(Panic())
// 		})
// 	})
//
//
//
//
