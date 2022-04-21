// Copyright (c) 2017-2022 Tigera, Inc. All rights reserved.
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

package iptables_test

import (
	"time"

	"github.com/projectcalico/calico/felix/environment"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/iptables/testutils"
	"github.com/projectcalico/calico/felix/logutils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/rules"

	log "github.com/sirupsen/logrus"
)

var _ = Describe("Table with an empty dataplane (nft)", func() {
	describeEmptyDataplaneTests("nft")
})
var _ = Describe("Table with an empty dataplane (legacy)", func() {
	describeEmptyDataplaneTests("legacy")

	It("should find the iptables-legacy-* iptables binaries", func() {
		dataplane := testutils.NewMockDataplane("filter", map[string][]string{
			"FORWARD": {},
			"INPUT":   {},
			"OUTPUT":  {},
		}, "legacy")
		iptLock := &mockMutex{}
		featureDetector := environment.NewFeatureDetector(nil)
		featureDetector.NewCmd = dataplane.NewCmd
		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
		table := NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			iptLock,
			featureDetector,
			TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				NewCmdOverride:        dataplane.NewCmd,
				SleepOverride:         dataplane.Sleep,
				NowOverride:           dataplane.Now,
				BackendMode:           "legacy",
				LookPathOverride:      testutils.LookPathAll,
				OpRecorder:            logutils.NewSummarizer("test loop"),
			},
		)

		table.InsertOrAppendRules("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.Apply()
		Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-legacy-save", "iptables-legacy-restore"))
	})
})

func describeEmptyDataplaneTests(dataplaneMode string) {
	var dataplane *testutils.MockDataplane
	var table *Table
	var iptLock *mockMutex
	var featureDetector *environment.FeatureDetector
	BeforeEach(func() {
		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
			"FORWARD": {},
			"INPUT":   {},
			"OUTPUT":  {},
		}, dataplaneMode)
		iptLock = &mockMutex{}
		featureDetector = environment.NewFeatureDetector(nil)
		featureDetector.NewCmd = dataplane.NewCmd
		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
		table = NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			iptLock,
			featureDetector,
			TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				NewCmdOverride:        dataplane.NewCmd,
				SleepOverride:         dataplane.Sleep,
				NowOverride:           dataplane.Now,
				BackendMode:           dataplaneMode,
				LookPathOverride:      testutils.LookPathNoLegacy,
				OpRecorder:            logutils.NewSummarizer("test loop"),
			},
		)
	})

	Describe("with iptables returning an nft error", func() {
		BeforeEach(func() {
			dataplane.Prologue = "# Table `nat' is incompatible, use 'nft' tool.\n"
		})

		It("should fail", func() {
			Expect(func() {
				table.Apply()
			}).To(Panic())
		})
	})

	It("should load the dataplane state on first Apply()", func() {
		Expect(dataplane.CmdNames).To(BeEmpty())
		table.Apply()
		// Should only load, since there's nothing to so.
		if dataplaneMode == "nft" {
			Expect(dataplane.CmdNames).To(Equal([]string{
				"iptables",
				"iptables-nft-save",
			}))
		} else {
			Expect(dataplane.CmdNames).To(Equal([]string{
				"iptables",
				"iptables-save",
			}))
		}
		Expect(iptLock.Held).To(BeFalse())
		Expect(iptLock.WasTaken).To(BeFalse())
	})

	It("should have a refresh scheduled at start-of-day", func() {
		Expect(table.Apply()).To(Equal(50 * time.Millisecond))
	})

	It("Should defer updates until Apply is called", func() {
		table.InsertOrAppendRules("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.UpdateChains([]*Chain{
			{Name: "cali-foobar", Rules: []Rule{{Action: AcceptAction{}}}},
		})
		Expect(dataplane.CmdNames).To(BeEmpty())
		table.Apply()
		if dataplaneMode == "nft" {
			Expect(dataplane.CmdNames).To(Equal([]string{
				"iptables",
				"iptables-nft-save",
				"iptables-nft-restore",
			}))
		} else {
			Expect(dataplane.CmdNames).To(Equal([]string{
				"iptables",
				"iptables-save",
				"iptables-restore",
			}))
		}
	})

	It("should ignore delete of non-existent chain", func() {
		table.RemoveChains([]*Chain{
			{Name: "cali-foobar", Rules: []Rule{{Action: AcceptAction{}}}},
		})
		table.Apply()
		Expect(dataplane.DeletedChains).To(BeEmpty())
	})

	It("should police the insert mode", func() {
		Expect(func() {
			NewTable(
				"filter",
				4,
				rules.RuleHashPrefix,
				&mockMutex{},
				featureDetector,
				TableOptions{
					HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
					NewCmdOverride:        dataplane.NewCmd,
					SleepOverride:         dataplane.Sleep,
					InsertMode:            "unknown",
					BackendMode:           dataplaneMode,
					LookPathOverride:      testutils.LookPathAll,
					OpRecorder:            logutils.NewSummarizer("test loop"),
				},
			)
		}).To(Panic())
	})

	Describe("after inserting a rule", func() {
		BeforeEach(func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: DropAction{}},
			})
			table.Apply()
		})
		It("should acquire the iptables lock", func() {
			Expect(iptLock.WasTaken).To(BeTrue())
		})
		It("should release the iptables lock", func() {
			Expect(iptLock.Held).To(BeFalse())
		})
		It("should be in the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
				"INPUT":   {},
				"OUTPUT":  {},
			}))
		})
		It("further inserts should be idempotent", func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: DropAction{}},
			})
			dataplane.ResetCmds()
			table.Apply()
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
				"INPUT":   {},
				"OUTPUT":  {},
			}))
			// Should do a save but then figure out that there's nothing to do
			if dataplaneMode == "nft" {
				Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save"))
			} else {
				Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save"))
			}
		})

		Describe("after inserting a rule then updating the insertions", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: DropAction{}},
					{Action: AcceptAction{}},
					{Action: DropAction{}},
					{Action: AcceptAction{}},
				})
				table.Apply()
			})
			It("should update the dataplane", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
						"-m comment --comment \"cali:BMJ7gfua-eMLZ8Gu\" --jump DROP",
						"-m comment --comment \"cali:rmnR1gc8haxMy_0W\" --jump ACCEPT",
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})

		Describe("after another process removes the insertion (empty chain)", func() {
			BeforeEach(func() {
				dataplane.Chains = map[string][]string{
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
				}
			})
			expectDataplaneFixed := func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
					"INPUT":   {},
					"OUTPUT":  {},
				}))
			}
			expectDataplaneUntouched := func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
				}))
			}
			It("should put it back on the next explicit refresh", func() {
				table.InvalidateDataplaneCache("test")
				table.Apply()
				expectDataplaneFixed()
			})
			shouldNotBeFixedAfter := func(delay time.Duration) func() {
				return func() {
					dataplane.AdvanceTimeBy(delay)
					table.Apply()
					expectDataplaneUntouched()
				}
			}
			shouldBeFixedAfter := func(delay time.Duration) func() {
				return func() {
					dataplane.AdvanceTimeBy(delay)
					table.Apply()
					expectDataplaneFixed()
				}
			}
			It("should defer recheck of the dataplane until after first recheck time",
				shouldNotBeFixedAfter(49*time.Millisecond))
			It("should recheck the dataplane if time has advanced far enough",
				shouldBeFixedAfter(50*time.Millisecond))
			It("should recheck the dataplane even if one of the recheck steps was missed",
				shouldBeFixedAfter(500*time.Millisecond))
			It("should recheck the dataplane even if one of the recheck steps was missed",
				shouldBeFixedAfter(2000*time.Millisecond))
		})
		Describe("after another process replaces the insertion (non-empty chain)", func() {
			BeforeEach(func() {
				dataplane.Chains = map[string][]string{
					"FORWARD": {
						`-A FORWARD -j ufw-before-logging-forward`,
						`-A FORWARD -j ufw-before-forward`,
						`-A FORWARD -j ufw-after-forward`,
					},
					"INPUT":  {},
					"OUTPUT": {},
				}
			})
			It("should put it back on the next refresh", func() {
				table.InvalidateDataplaneCache("test")
				table.Apply()
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`,
						`-A FORWARD -j ufw-before-logging-forward`,
						`-A FORWARD -j ufw-before-forward`,
						`-A FORWARD -j ufw-after-forward`,
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})
	})

	Describe("after adding a chain", func() {
		BeforeEach(func() {
			table.UpdateChains([]*Chain{
				{Name: "cali-foobar", Rules: []Rule{
					{Action: AcceptAction{}},
					{Action: DropAction{}},
				}},
			})
			table.Apply()
		})

		It("it should not get programmed because it's not referenced", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {},
				"INPUT":   {},
				"OUTPUT":  {},
			}))
		})

		Describe("after adding a reference from another chain", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: JumpAction{Target: "cali-FORWARD"}},
				})
				table.UpdateChain(&Chain{
					Name: "cali-FORWARD",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-foobar"}},
					}})
				table.Apply()
			})
			It("it should get programmed", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:wUHhoiAYhphO9Mso\" --jump cali-FORWARD",
					},
					"INPUT":  {},
					"OUTPUT": {},
					"cali-FORWARD": {
						"-m comment --comment \"cali:WiiHgeRwfPX6Ol7d\" --jump cali-foobar",
					},
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
					},
				}))
			})

			Describe("after adding a reference from an insert", func() {
				BeforeEach(func() {
					table.InsertOrAppendRules("FORWARD", []Rule{
						{Action: JumpAction{Target: "cali-foobar"}},
					})
					table.Apply()
				})
				It("intermediate chain should be removed", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {
							"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
						},
						"INPUT":  {},
						"OUTPUT": {},
						"cali-foobar": {
							"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
							"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
						},
					}))
				})

				Describe("after deleting the intermediate chain", func() {
					BeforeEach(func() {
						table.RemoveChainByName("cali-FORWARD")
						table.Apply()
					})
					It("should make no change", func() {
						Expect(dataplane.Chains).To(Equal(map[string][]string{
							"FORWARD": {
								"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
							},
							"INPUT":  {},
							"OUTPUT": {},
							"cali-foobar": {
								"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
								"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
							},
						}))
					})

					Describe("after removing the insert", func() {
						BeforeEach(func() {
							table.InsertOrAppendRules("FORWARD", []Rule{})
							table.Apply()
						})
						It("chain should be removed", func() {
							Expect(dataplane.Chains).To(Equal(map[string][]string{
								"FORWARD": {},
								"INPUT":   {},
								"OUTPUT":  {},
							}))
						})
					})
				})
			})
		})

		Describe("after adding a reference from an insert", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: JumpAction{Target: "cali-foobar"}},
				})
				table.Apply()
			})
			It("it should get programmed", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
					},
					"INPUT":  {},
					"OUTPUT": {},
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
					},
				}))
			})

			Describe("after removing the reference", func() {
				BeforeEach(func() {
					table.InsertOrAppendRules("FORWARD", []Rule{})
					table.Apply()
				})
				It("it should get removed", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {},
						"INPUT":   {},
						"OUTPUT":  {},
					}))
				})
			})

			Describe("then updating the chain", func() {
				BeforeEach(func() {
					table.UpdateChains([]*Chain{
						{Name: "cali-foobar", Rules: []Rule{
							// We swap the rules.
							{Action: DropAction{}},
							{Action: AcceptAction{}},
						}},
					})
					table.Apply()
				})
				It("should be updated", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {
							"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
						},
						"INPUT":  {},
						"OUTPUT": {},
						"cali-foobar": {
							"-m comment --comment \"cali:I9LKcIJU9vtw4suw\" --jump DROP",
							"-m comment --comment \"cali:2XsaWB87aQT7Fxgc\" --jump ACCEPT",
						},
					}))
				})
				It("shouldn't get written more than once", func() {
					dataplane.ResetCmds()
					table.Apply()
					Expect(dataplane.CmdNames).To(BeEmpty())
				})
				It("should squash idempotent updates", func() {
					table.UpdateChains([]*Chain{
						{Name: "cali-foobar", Rules: []Rule{
							// Same data as above.
							{Action: DropAction{}},
							{Action: AcceptAction{}},
						}},
					})
					dataplane.ResetCmds()
					table.Apply()
					// Should do a save but then figure out that there's nothing to do
					if dataplaneMode == "nft" {
						Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save"))
					} else {
						Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save"))
					}
				})
			})
			Describe("then extending the chain", func() {
				BeforeEach(func() {
					table.UpdateChains([]*Chain{
						{Name: "cali-foobar", Rules: []Rule{
							{Action: AcceptAction{}},
							{Action: DropAction{}},
							{Action: ReturnAction{}},
						}},
					})
					table.Apply()
				})
				It("should be updated", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {
							"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
						},
						"INPUT":  {},
						"OUTPUT": {},
						"cali-foobar": {
							"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
							"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
							"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
						},
					}))
				})

				Describe("then truncating the chain", func() {
					BeforeEach(func() {
						table.UpdateChains([]*Chain{
							{Name: "cali-foobar", Rules: []Rule{
								{Action: AcceptAction{}},
							}},
						})
						table.Apply()
					})
					It("should be updated", func() {
						Expect(dataplane.Chains).To(Equal(map[string][]string{
							"FORWARD": {
								"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
							},
							"INPUT":  {},
							"OUTPUT": {},
							"cali-foobar": {
								"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
							},
						}))
					})
				})
				Describe("then replacing the chain", func() {
					BeforeEach(func() {
						table.UpdateChains([]*Chain{
							{Name: "cali-foobar", Rules: []Rule{
								{Action: ReturnAction{}},
							}},
						})
						table.Apply()
					})
					It("should be updated", func() {
						Expect(dataplane.Chains).To(Equal(map[string][]string{
							"FORWARD": {
								"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
							},
							"INPUT":  {},
							"OUTPUT": {},
							"cali-foobar": {
								"-m comment --comment \"cali:ZqwJQBzCmuABAOQt\" --jump RETURN",
							},
						}))
					})
				})
			})
			Describe("then removing the chain by name", func() {
				BeforeEach(func() {
					table.RemoveChainByName("cali-foobar")
					table.Apply()
				})
				It("should be gone from the dataplane", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {
							"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
						},
						"INPUT":  {},
						"OUTPUT": {},
					}))
				})
			})
			Describe("then removing the chain", func() {
				BeforeEach(func() {
					table.RemoveChains([]*Chain{
						{Name: "cali-foobar", Rules: []Rule{
							{Action: AcceptAction{}},
							{Action: DropAction{}},
						}},
					})
					table.Apply()
				})
				It("should be gone from the dataplane", func() {
					Expect(dataplane.Chains).To(Equal(map[string][]string{
						"FORWARD": {
							"-m comment --comment \"cali:JttcEuxbGad9jG6N\" --jump cali-foobar",
						},
						"INPUT":  {},
						"OUTPUT": {},
					}))
				})
			})
		})
	})

	Describe("applying updates when underlying iptables have changed in a whitelisted chain", func() {
		BeforeEach(func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: AcceptAction{}},
				{Action: DropAction{}},
				{Action: JumpAction{Target: "cali-foobar"}},
			})
			table.UpdateChains([]*Chain{
				{Name: "cali-foobar", Rules: []Rule{
					{Action: AcceptAction{}},
					{Action: DropAction{}},
				}},
			})
			table.Apply()
		})
		It("should be in the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {
					"-m comment --comment \"cali:3gUkOfVeYRgMeHF4\" --jump ACCEPT",
					"-m comment --comment \"cali:8MgbRleZ5Rc5cBEf\" --jump DROP",
					"-m comment --comment \"cali:Ox1x6pjEMCqtMxFb\" --jump cali-foobar",
				},
				"INPUT":  {},
				"OUTPUT": {},
				"cali-foobar": {
					"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
					"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
				},
			}))
		})
		Describe("then truncating the chain, with the iptables changed before iptables-restore", func() {
			BeforeEach(func() {
				dataplane.OnPreRestore = func() {
					log.Warn("Simulating an insert in FORWARD chain before iptables-restore happens")
					if chain, found := dataplane.Chains["FORWARD"]; found {
						log.Warn("FORWARD chain exists; inserting random rule in FORWARD chain")
						lines := testutils.PrependLine(chain, "-j randomly-inserted-rule")
						dataplane.Chains["FORWARD"] = lines
					}
				}

				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"new drop rule"}},
					{Action: JumpAction{Target: "cali-foobar"}},
				})
				table.Apply()
			})
			It("should be updated", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:67cGS74-1PBXlOtK\" -m comment --comment \"new drop rule\" --jump DROP",
						"-m comment --comment \"cali:RA5Tbu3HSwkGWuZM\" --jump cali-foobar",
						"-j randomly-inserted-rule",
					},
					"INPUT":  {},
					"OUTPUT": {},
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
					},
				}))
			})
		})
	})

	Describe("applying updates when underlying iptables have changed in a non-whitelisted chain", func() {
		BeforeEach(func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: JumpAction{Target: "non-cali-chain"}},
				{Action: JumpAction{Target: "cali-foobar"}},
			})
			table.UpdateChains([]*Chain{
				{Name: "non-cali-chain", Rules: []Rule{
					{Action: AcceptAction{}, Comment: []string{"non-cali 1"}},
					{Action: DropAction{}, Comment: []string{"non-cali 2"}},
				}},
				{Name: "cali-foobar", Rules: []Rule{
					{Action: AcceptAction{}, Comment: []string{"cali 1"}},
					{Action: DropAction{}, Comment: []string{"cali 2"}},
				}},
			})
			table.Apply()
		})
		It("should be in the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {
					"-m comment --comment \"cali:ta5MhgrxEtcvsaNe\" --jump non-cali-chain",
					"-m comment --comment \"cali:jBG6MfhPnbAhthUp\" --jump cali-foobar",
				},
				"INPUT":  {},
				"OUTPUT": {},
				"non-cali-chain": {
					"-m comment --comment \"cali:Z-OWODLe_LbHxmqg\" -m comment --comment \"non-cali 1\" --jump ACCEPT",
					"-m comment --comment \"cali:tq-yEo1_1XQHZnMs\" -m comment --comment \"non-cali 2\" --jump DROP",
				},
				"cali-foobar": {
					"-m comment --comment \"cali:cxE-1zsuD12R9YEG\" -m comment --comment \"cali 1\" --jump ACCEPT",
					"-m comment --comment \"cali:1cpbPOGLTROlH4Sj\" -m comment --comment \"cali 2\" --jump DROP",
				},
			}))
		})
		Describe("then truncating the chain, with the iptables changed before iptables-restore", func() {
			BeforeEach(func() {
				dataplane.OnPreRestore = func() {
					log.Warn("Simulating an insert in non-cali-chain before iptables-restore happens")
					if chain, found := dataplane.Chains["non-cali-chain"]; found {
						log.Warn("non-cali-chain exists; inserting random rule in non-cali-chain")
						lines := testutils.PrependLine(chain, "-j randomly-inserted-rule")
						dataplane.Chains["non-cali-chain"] = lines
					}
				}

				table.InsertOrAppendRules("non-cali-chain", []Rule{
					{Action: DropAction{}, Comment: []string{"new drop rule"}},
				})
				table.Apply()
			})
			It("should be updated", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:ta5MhgrxEtcvsaNe\" --jump non-cali-chain",
						"-m comment --comment \"cali:jBG6MfhPnbAhthUp\" --jump cali-foobar",
					},
					"INPUT":  {},
					"OUTPUT": {},
					"non-cali-chain": {
						"-m comment --comment \"cali:O9yEP97Dd2y-EskM\" -m comment --comment \"new drop rule\" --jump DROP",
						"-j randomly-inserted-rule"},
					"cali-foobar": {
						"-m comment --comment \"cali:cxE-1zsuD12R9YEG\" -m comment --comment \"cali 1\" --jump ACCEPT",
						"-m comment --comment \"cali:1cpbPOGLTROlH4Sj\" -m comment --comment \"cali 2\" --jump DROP",
					},
				}))
			})
		})
	})

	Describe("inserting into a non-Calico chain results in the expected writes", func() {
		BeforeEach(func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: DropAction{}, Comment: []string{"a drop rule"}},
				{Action: AcceptAction{}, Comment: []string{"an accept rule"}},
			})
			table.Apply()
		})
		It("should update the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {
					"-m comment --comment \"cali:upaItQyFMdN7MTTl\" -m comment --comment \"a drop rule\" --jump DROP",
					"-m comment --comment \"cali:EpCg3AYNp_DftVFS\" -m comment --comment \"an accept rule\" --jump ACCEPT",
				},
				"INPUT":  {},
				"OUTPUT": {},
			}))
			if dataplaneMode == "nft" {
				Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save", "iptables-nft-restore"))
			} else {
				Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save", "iptables-restore"))
			}
		})
		Describe("then inserting the same rules", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"a drop rule"}},
					{Action: AcceptAction{}, Comment: []string{"an accept rule"}},
				})
				dataplane.ResetCmds()
				table.Apply()
			})
			It("should result in no inserts", func() {
				// Do an iptables-save but not a iptables-restore.
				if dataplaneMode == "nft" {
					Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save"))
				} else {
					Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save"))
				}

				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:upaItQyFMdN7MTTl\" -m comment --comment \"a drop rule\" --jump DROP",
						"-m comment --comment \"cali:EpCg3AYNp_DftVFS\" -m comment --comment \"an accept rule\" --jump ACCEPT",
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})
		Describe("then inserting different rules", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"a drop rule"}},
					{Action: AcceptAction{}, Comment: []string{"an accept rule"}},
					{Action: DropAction{}, Comment: []string{"a second drop rule"}},
				})
				dataplane.ResetCmds()
				table.Apply()
			})
			It("should result in modifications", func() {
				// Do an iptables-save and, this time, an iptables-restore.
				if dataplaneMode == "nft" {
					Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save", "iptables-nft-restore"))
				} else {
					Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save", "iptables-restore"))
				}

				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:upaItQyFMdN7MTTl\" -m comment --comment \"a drop rule\" --jump DROP",
						"-m comment --comment \"cali:EpCg3AYNp_DftVFS\" -m comment --comment \"an accept rule\" --jump ACCEPT",
						"-m comment --comment \"cali:-rA8o5kyVSTHJMe8\" -m comment --comment \"a second drop rule\" --jump DROP",
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})
	})

	Describe("inserting and appending into a non-Calico chain results in the expected writes", func() {
		BeforeEach(func() {
			table.AppendRules("FORWARD", []Rule{
				{Action: DropAction{}, Comment: []string{"append drop rule"}},
				{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
			})
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: DropAction{}, Comment: []string{"insert drop rule"}},
				{Action: AcceptAction{}, Comment: []string{"insert accept rule"}},
			})

			table.Apply()
		})
		It("should update the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {
					"-m comment --comment \"cali:sP8Ctm6vRqum19h-\" -m comment --comment \"insert drop rule\" --jump DROP",
					"-m comment --comment \"cali:b-zvHycxSRrp53xL\" -m comment --comment \"insert accept rule\" --jump ACCEPT",
					"-m comment --comment \"cali:qNsBylRkftPwO3XF\" -m comment --comment \"append drop rule\" --jump DROP",
					"-m comment --comment \"cali:IQ9H0Scq00rF0w4S\" -m comment --comment \"append accept rule\" --jump ACCEPT",
				},
				"INPUT":  {},
				"OUTPUT": {},
			}))
		})

		Describe("then appending the same rules", func() {
			BeforeEach(func() {
				table.AppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"append drop rule"}},
					{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
				})
				dataplane.ResetCmds()
				table.Apply()
			})
			It("should result in no inserts", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:sP8Ctm6vRqum19h-\" -m comment --comment \"insert drop rule\" --jump DROP",
						"-m comment --comment \"cali:b-zvHycxSRrp53xL\" -m comment --comment \"insert accept rule\" --jump ACCEPT",
						"-m comment --comment \"cali:qNsBylRkftPwO3XF\" -m comment --comment \"append drop rule\" --jump DROP",
						"-m comment --comment \"cali:IQ9H0Scq00rF0w4S\" -m comment --comment \"append accept rule\" --jump ACCEPT",
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})

		Describe("then inserting and appending different rules", func() {
			BeforeEach(func() {
				table.InsertOrAppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"insert drop rule"}},
					{Action: AcceptAction{}, Comment: []string{"insert accept rule"}},
					{Action: DropAction{}, Comment: []string{"second insert drop rule"}},
				})
				table.AppendRules("FORWARD", []Rule{
					{Action: DropAction{}, Comment: []string{"append drop rule"}},
					{Action: AcceptAction{}, Comment: []string{"append accept rule"}},
					{Action: DropAction{}, Comment: []string{"second append drop rule"}},
				})
				dataplane.ResetCmds()
				table.Apply()
			})
			It("should result in modifications", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:sP8Ctm6vRqum19h-\" -m comment --comment \"insert drop rule\" --jump DROP",
						"-m comment --comment \"cali:b-zvHycxSRrp53xL\" -m comment --comment \"insert accept rule\" --jump ACCEPT",
						"-m comment --comment \"cali:qvt6MzuJGZqS1aQt\" -m comment --comment \"second insert drop rule\" --jump DROP",
						"-m comment --comment \"cali:qNsBylRkftPwO3XF\" -m comment --comment \"append drop rule\" --jump DROP",
						"-m comment --comment \"cali:IQ9H0Scq00rF0w4S\" -m comment --comment \"append accept rule\" --jump ACCEPT",
						"-m comment --comment \"cali:Ss37kzq4-zQ2tbFp\" -m comment --comment \"second append drop rule\" --jump DROP",
					},
					"INPUT":  {},
					"OUTPUT": {},
				}))
			})
		})
	})
}

var _ = Describe("Tests of post-update recheck behaviour with refresh timer (nft)", func() {
	describePostUpdateCheckTests(true, "nft")
})
var _ = Describe("Tests of post-update recheck behaviour with no refresh timer (nft)", func() {
	describePostUpdateCheckTests(false, "nft")
})
var _ = Describe("Tests of post-update recheck behaviour with refresh timer (legacy)", func() {
	describePostUpdateCheckTests(true, "legacy")
})
var _ = Describe("Tests of post-update recheck behaviour with no refresh timer (legacy)", func() {
	describePostUpdateCheckTests(false, "legacy")
})

func describePostUpdateCheckTests(enableRefresh bool, dataplaneMode string) {
	var dataplane *testutils.MockDataplane
	var table *Table
	var requestedDelay time.Duration

	BeforeEach(func() {
		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
			"FORWARD": {},
			"INPUT":   {},
			"OUTPUT":  {},
		}, dataplaneMode)
		options := TableOptions{
			HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
			NewCmdOverride:        dataplane.NewCmd,
			SleepOverride:         dataplane.Sleep,
			NowOverride:           dataplane.Now,
			BackendMode:           dataplaneMode,
			LookPathOverride:      testutils.LookPathNoLegacy,
			OpRecorder:            logutils.NewSummarizer("test loop"),
		}
		if enableRefresh {
			options.RefreshInterval = 30 * time.Second
		}
		featureDetector := environment.NewFeatureDetector(nil)
		featureDetector.NewCmd = dataplane.NewCmd
		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
		table = NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			&mockMutex{},
			featureDetector,
			options,
		)
		table.InsertOrAppendRules("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.Apply()
	})

	resetAndAdvance := func(amount time.Duration) func() {
		return func() {
			dataplane.ResetCmds()
			dataplane.AdvanceTimeBy(amount)
			requestedDelay = table.Apply()
		}
	}
	assertRecheck := func() {
		if dataplaneMode == "nft" {
			Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-nft-save"))
		} else {
			Expect(dataplane.CmdNames).To(ConsistOf("iptables", "iptables-save"))
		}
	}
	assertDelayMillis := func(delay int64) func() {
		return func() {
			Expect(requestedDelay).To(Equal(time.Duration(delay) * time.Millisecond))
		}
	}
	assertNoCheck := func() {
		Expect(dataplane.CmdNames).To(BeEmpty())
	}

	Describe("after advancing time 49ms", func() {
		BeforeEach(resetAndAdvance(49 * time.Millisecond))
		It("should not recheck", assertNoCheck)
		It("should request correct delay", assertDelayMillis(1))

		Describe("after advancing time to 50ms", func() {
			BeforeEach(resetAndAdvance(1 * time.Millisecond))
			It("should recheck", assertRecheck)
			It("should request correct delay", assertDelayMillis(50))

			Describe("after advancing time to 51ms", func() {
				BeforeEach(resetAndAdvance(1 * time.Millisecond))
				It("should not recheck", assertNoCheck)
				It("should request correct delay", assertDelayMillis(49))

				Describe("after advancing time to 100ms", func() {
					BeforeEach(resetAndAdvance(49 * time.Millisecond))
					It("should recheck", assertRecheck)
					It("should request correct delay", assertDelayMillis(100))
				})
			})
		})
		Describe("after advancing time to 999ms", func() {
			BeforeEach(resetAndAdvance(950 * time.Millisecond))
			It("should recheck", assertRecheck)
			It("should request correct delay", assertDelayMillis(601)) // i.e. at 1.6s

			if enableRefresh {
				Describe("after advancing time 60s", func() {
					BeforeEach(resetAndAdvance(60 * time.Second))
					It("should recheck", assertRecheck)

					// Now waiting for the next refresh interval.
					It("should request correct delay", assertDelayMillis(30000))
				})
				Describe("after advancing time by an hour", func() {
					BeforeEach(resetAndAdvance(time.Hour))
					It("should recheck", assertRecheck)

					// Now waiting for the next refresh interval.
					It("should request correct delay", assertDelayMillis(30000))

					Describe("after advancing time by an hour", func() {
						BeforeEach(resetAndAdvance(time.Hour))
						It("should recheck", assertRecheck)

						// Now waiting for the next refresh interval.
						It("should request correct delay", assertDelayMillis(30000))
					})
				})
			} else {
				Describe("after advancing time 60s", func() {
					BeforeEach(resetAndAdvance(60 * time.Second))
					It("should recheck", assertRecheck)

					// Refresh disabled, it just keeps increasing
					It("should request correct delay", assertDelayMillis(41401))
				})
				Describe("after advancing time by an hour", func() {
					BeforeEach(resetAndAdvance(time.Hour))
					// Last recheck due to the post-write check.
					It("should recheck", assertRecheck)

					// Then, it should give up.
					It("should request correct delay", assertDelayMillis(0))

					Describe("after advancing time by an hour", func() {
						BeforeEach(resetAndAdvance(time.Hour))
						It("should not recheck", assertNoCheck)
						It("should request correct delay", assertDelayMillis(0))
					})
				})
			}
		})
	})
}

var _ = Describe("Table with a dirty dataplane in append mode (nft)", func() {
	describeDirtyDataplaneTests(true, "nft")
})
var _ = Describe("Table with a dirty dataplane in insert mode (nft)", func() {
	describeDirtyDataplaneTests(false, "nft")
})
var _ = Describe("Table with a dirty dataplane in append mode (legacy)", func() {
	describeDirtyDataplaneTests(true, "legacy")
})
var _ = Describe("Table with a dirty dataplane in insert mode (legacy)", func() {
	describeDirtyDataplaneTests(false, "legacy")
})

func describeDirtyDataplaneTests(appendMode bool, dataplaneMode string) {
	// These tests all start with some rules already in the dataplane.  We include a mix of
	// Calico and non-Calico rules.  Within the Calico rules,we include:
	// - rules that match what we're going to ask the Table to program
	// - rules that differ and need to be detected/replaced
	// - rules that are unexpected (in chains that need to be removed)
	// - rules from previous Calico versions, using different chain name prefixes
	// - rules that only match the special-case regex.
	var dataplane *testutils.MockDataplane
	var table *Table
	initialChains := func() map[string][]string {
		return map[string][]string{
			"FORWARD": {
				// Non-calico rule
				"--jump RETURN",
				// Stale calico rules
				"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
				"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
				// Non-calico rule
				"--jump ACCEPT",
				// Old calico rule.  should be cleaned up.
				"-j felix-FORWARD",
				"--jump felix-FORWARD",
				// Regex-matched rule.  should be cleaned up.
				"--jump sneaky-rule",
				// Non-calico rule
				"--jump foo-bar",
			},
			"INPUT": {
				// This rule will get cleaned up because we don't insert any rules
				// into the INPUT chain in this test.
				"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
			},
			"OUTPUT": {
				// This rule will get rewritten because its hash is incorrect.
				"-m comment --comment \"cali:1234567890ksamdl\" --jump DROP",
			},
			"unexpected-insert": {
				"--jump ACCEPT",
				// This rule will get cleaned up because it looks like a Calico
				// insert rule but it's in a chain that we don't insert anything
				// into.
				"-m comment --comment \"cali:hecdSCslEjdBPfds\" --jump DROP",
				"--jump DROP",
			},
			// Calico chain from previous version.  Should be cleaned up.
			"felix-FORWARD": {
				"--jump ACCEPT",
			},
			"cali-correct": {
				"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
			},
			"cali-foobar": {
				"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
				"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
				"-m comment --comment \"cali:deadbeef09238384\" --jump RETURN",
			},
			"cali-stale": {
				"-m comment --comment \"cali:qwebjbdfjadfndns\" --jump ACCEPT",
				"-m comment --comment \"cali:abcdeflakdjfladj\" --jump DROP",
			},
			"non-calico": {
				"--jump ACCEPT",
			},
		}
	}

	BeforeEach(func() {
		dataplane = testutils.NewMockDataplane("filter", initialChains(), dataplaneMode)
		insertMode := ""
		if appendMode {
			insertMode = "append"
		}
		featureDetector := environment.NewFeatureDetector(nil)
		featureDetector.NewCmd = dataplane.NewCmd
		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
		table = NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			&mockMutex{},
			featureDetector,
			TableOptions{
				HistoricChainPrefixes:    rules.AllHistoricChainNamePrefixes,
				ExtraCleanupRegexPattern: "sneaky-rule",
				NewCmdOverride:           dataplane.NewCmd,
				SleepOverride:            dataplane.Sleep,
				InsertMode:               insertMode,
				BackendMode:              dataplaneMode,
				LookPathOverride:         testutils.LookPathNoLegacy,
				OpRecorder:               logutils.NewSummarizer("test loop"),
			},
		)
	})

	It("should clean up on first Apply()", func() {
		table.Apply()
		Expect(dataplane.Chains).To(Equal(map[string][]string{
			"FORWARD": {
				// Non-calico rule
				"--jump RETURN",
				// Non-calico rule
				"--jump ACCEPT",
				// Non-calico rule
				"--jump foo-bar",
			},
			"INPUT":  {},
			"OUTPUT": {},
			"non-calico": {
				"--jump ACCEPT",
			},
			"unexpected-insert": {
				"--jump ACCEPT",
				"--jump DROP",
			},
		}))
	})

	Describe("with pre-cleanup inserts, appends and updates", func() {
		// These tests inject some chains and insertions before the first call to Apply().
		// That should mean that the Table does a sync operation, avoiding updates to
		// chains/rules that haven't changed, for example.
		BeforeEach(func() {
			table.InsertOrAppendRules("FORWARD", []Rule{
				{Action: DropAction{}},
				{Action: AcceptAction{}},
				{Action: GotoAction{Target: "cali-foobar"}},
			})
			table.AppendRules("FORWARD", []Rule{
				{Action: ReturnAction{}},
				{Action: DropAction{}},
			})
			table.InsertOrAppendRules("OUTPUT", []Rule{
				{Action: DropAction{}},
				{Action: JumpAction{Target: "cali-correct"}},
			})
			table.UpdateChains([]*Chain{
				{Name: "cali-foobar", Rules: []Rule{
					{Action: AcceptAction{}},
					{Action: DropAction{}},
					{Action: ReturnAction{}},
				}},
			})
			table.UpdateChains([]*Chain{
				{Name: "cali-correct", Rules: []Rule{
					{Action: AcceptAction{}},
				}},
			})
		})
		checkFinalState := func() {
			expChains := map[string][]string{
				"cali-foobar": {
					"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
					"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
					"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
				},
				"unexpected-insert": {
					"--jump ACCEPT",
					"--jump DROP",
				},
				"INPUT": {},
				"OUTPUT": {
					"-m comment --comment \"cali:RtPHXnCQBd3uyJfJ\" --jump DROP",
					"-m comment --comment \"cali:Eq8toINAJuMTNYmX\" --jump cali-correct",
				},
				"non-calico": {
					"--jump ACCEPT",
				},
				"cali-correct": {
					"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
				},
			}

			if appendMode {
				expChains["FORWARD"] = []string{
					"--jump RETURN",
					"--jump ACCEPT",
					"--jump foo-bar",
					"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
					"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
					"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
					"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
					"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
				}
			} else {
				expChains["FORWARD"] = []string{
					"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
					"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
					"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
					"--jump RETURN",
					"--jump ACCEPT",
					"--jump foo-bar",
					"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
					"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
				}
			}

			ExpectWithOffset(1, dataplane.Chains).To(Equal(expChains))
		}
		It("with no errors, it should get to correct final state", func() {
			table.Apply()
			checkFinalState()
			Expect(dataplane.Cmds).To(HaveLen(3)) // a version, save and a restore
		})
		It("with no errors, it shouldn't sleep", func() {
			table.Apply()
			Expect(dataplane.CumulativeSleep).To(BeZero())
		})
		assertOneRetry := func() {
			It("it should get to correct final state", func() {
				checkFinalState()
			})
			It("it should retry once", func() {
				Expect(dataplane.Cmds).To(HaveLen(4)) // a version, 2 saves and a restore
			})
			It("it should sleep", func() {
				Expect(dataplane.CumulativeSleep).To(Equal(100 * time.Millisecond))
			})
		}
		Describe("With a transient iptables-save failure", func() {
			BeforeEach(func() {
				dataplane.FailNextSaveRead = true
				table.Apply()
			})
			assertOneRetry()
		})
		Describe("With a transient iptables-save failure and a kill failure", func() {
			BeforeEach(func() {
				dataplane.FailNextSaveRead = true
				dataplane.FailNextKill = true
			})
			It("should panic", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
			})
		})
		Describe("With a transient iptables-save pipe-close failure", func() {
			BeforeEach(func() {
				dataplane.FailNextPipeClose = true
				table.Apply()
			})
			assertOneRetry()
		})
		Describe("With a transient iptables-save start failure", func() {
			BeforeEach(func() {
				dataplane.FailNextStart = true
				table.Apply()
			})
			assertOneRetry()
			It("should close the pipes", func() {
				Expect(dataplane.PipeBuffers).To(HaveLen(2))
				for _, pb := range dataplane.PipeBuffers {
					Expect(pb.Closed).To(BeTrue())
				}
			})
		})
		Describe("With a transient iptables-save start and pipe-close failure", func() {
			BeforeEach(func() {
				dataplane.FailNextStart = true
				dataplane.FailNextPipeClose = true
				table.Apply()
			})
			assertOneRetry()
			It("should close the pipes", func() {
				Expect(dataplane.PipeBuffers).To(HaveLen(2))
				for _, pb := range dataplane.PipeBuffers {
					Expect(pb.Closed).To(BeTrue())
				}
			})
		})
		Describe("With a persistent iptables-save failure", func() {
			BeforeEach(func() {
				dataplane.FailAllSaves = true
			})
			It("it should panic", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
			}, 1)
			It("it should do exponential backoff", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
				Expect(dataplane.CumulativeSleep).To(Equal((100 + 200 + 400) * time.Millisecond))
			}, 1)
			It("it should retry 3 times", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
				Expect(dataplane.Cmds).To(HaveLen(5))
			}, 1)
		})

		It("shouldn't touch already-correct chain", func() {
			table.Apply()
			Expect(dataplane.RuleTouched("cali-correct", 1)).To(BeFalse())
		})
		if dataplaneMode == "legacy" {
			It("shouldn't touch already-correct rules", func() {
				table.Apply()
				// First two rules are already correct...
				Expect(dataplane.RuleTouched("cali-foobar", 1)).To(BeFalse())
				Expect(dataplane.RuleTouched("cali-foobar", 2)).To(BeFalse())
				// Third rule is incorrect.
				Expect(dataplane.RuleTouched("cali-foobar", 3)).To(BeTrue())
			})
		} else {
			// In nft mode, we have to rewrite the whole chain if there's any change.
			It("should rewrite whole chain", func() {
				table.Apply()
				// First two rules are already correct...
				Expect(dataplane.RuleTouched("cali-foobar", 1)).To(BeTrue())
				Expect(dataplane.RuleTouched("cali-foobar", 2)).To(BeTrue())
				// Third rule is incorrect.
				Expect(dataplane.RuleTouched("cali-foobar", 3)).To(BeTrue())
			})
		}
		It("with a transient error, it should get to correct final state", func() {
			// First write to iptables fails; Table should simply retry.
			log.Info("About to do a failing Apply().")
			dataplane.FailNextRestore = true
			table.Apply()
			Expect(dataplane.FailNextRestore).To(BeFalse()) // Flag should be reset
			checkFinalState()
		})
		Describe("with a persistent iptables-restore error", func() {
			BeforeEach(func() {
				dataplane.FailAllRestores = true
			})
			It("it should panic", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
			}, 1)
			It("it should do exponential backoff", func() {
				Expect(func() {
					table.Apply()
				}).To(Panic())
				Expect(dataplane.CumulativeSleep).To(Equal(
					(1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512) * time.Millisecond))
			}, 1)
		})

		Describe("with a simulated clobber of chains before first write", func() {
			BeforeEach(func() {
				// After the iptables-save call but before the iptables-restore, another
				// process comes in and clobbers the dataplane, causing a failure.  It
				// should reload and do the right thing.
				dataplane.OnPreRestore = func() {
					dataplane.Chains = map[string][]string{
						"FORWARD": {},
						"INPUT":   {},
						"OUTPUT":  {},
					}
				}
				dataplane.FailNextRestore = true
				table.Apply()
			})
			It("should get to correct final state", func() {
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {
						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
					},
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
						"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
					},
					"INPUT": {},
					"OUTPUT": {
						"-m comment --comment \"cali:RtPHXnCQBd3uyJfJ\" --jump DROP",
						"-m comment --comment \"cali:Eq8toINAJuMTNYmX\" --jump cali-correct",
					},
					"cali-correct": {
						"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
					},
				}))
			})
			It("should sleep for correct time", func() {
				Expect(dataplane.CumulativeSleep).To(Equal(1 * time.Millisecond))
			})
		})

		Describe("with a clobber after initial write", func() {
			// These tests allow the first write to succeed so that the Table's cache
			// of the dataplane state is primed with the Calico chains.  Then they
			// simulate another process clobbering our chains and restoring them back to
			// the old state.
			BeforeEach(func() {
				// First write, should succeed normally.
				table.Apply()
				checkFinalState()
				// Then another process trashes the state, restoring it to the old
				// state.
				dataplane.Chains = initialChains()
				// Explicitly invalidate the cache to simulate a timer refresh.
				table.InvalidateDataplaneCache("test")
			})
			It("should get to correct state", func() {
				// Next Apply() should fix it.
				table.Apply()
				checkFinalState()
			})
			It("it shouldn't sleep", func() {
				table.Apply()
				Expect(dataplane.CumulativeSleep).To(BeZero())
			})
			It("and pending updates, should get to correct state", func() {
				// And we make some updates in the same batch.
				table.InsertOrAppendRules("OUTPUT", []Rule{
					{Action: AcceptAction{}},
					{Action: JumpAction{Target: "cali-correct"}},
				})
				table.UpdateChains([]*Chain{
					{Name: "cali-foobar", Rules: []Rule{
						{Action: AcceptAction{}},
						{Action: ReturnAction{}},
					}},
				})
				// Next Apply() should refresh then put everything in sync.
				table.Apply()

				expChains := map[string][]string{
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:ilM9uz5oPwfm0FE-\" --jump RETURN",
					},
					"unexpected-insert": {
						"--jump ACCEPT",
						"--jump DROP",
					},
					"INPUT": {},
					"OUTPUT": {
						"-m comment --comment \"cali:CZ70AKmne2ck3c5b\" --jump ACCEPT",
						"-m comment --comment \"cali:7XdOSW_DYWLuCNDD\" --jump cali-correct",
					},
					"non-calico": {
						"--jump ACCEPT",
					},
					"cali-correct": {
						"-m comment --comment \"cali:dCKeL4JtUEDC2GQu\" --jump ACCEPT",
					},
				}

				if appendMode {
					expChains["FORWARD"] = []string{
						"--jump RETURN",
						"--jump ACCEPT",
						"--jump foo-bar",
						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
					}
				} else {
					expChains["FORWARD"] = []string{
						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
						"-m comment --comment \"cali:vKEEfdy_QeXafpRE\" --goto cali-foobar",
						"--jump RETURN",
						"--jump ACCEPT",
						"--jump foo-bar",
						"-m comment --comment \"cali:TQaqIrW2HQal-sdp\" --jump RETURN",
						"-m comment --comment \"cali:EDon0sGIntr1CQga\" --jump DROP",
					}
				}

				Expect(dataplane.Chains).To(Equal(expChains))
			})
		})
	})
}

var _ = Describe("Table with inserts and a non-Calico chain (legacy)", func() {
	describeInsertAndNonCalicoChainTests("legacy")
})
var _ = Describe("Table with inserts and a non-Calico chain (nft)", func() {
	describeInsertAndNonCalicoChainTests("nft")
})

func describeInsertAndNonCalicoChainTests(dataplaneMode string) {
	var dataplane *testutils.MockDataplane
	var table *Table
	var iptLock *mockMutex
	BeforeEach(func() {
		dataplane = testutils.NewMockDataplane("filter", map[string][]string{
			"FORWARD":    {},
			"non-calico": {"-m comment \"foo\""},
		}, dataplaneMode)
		iptLock = &mockMutex{}
		featureDetector := environment.NewFeatureDetector(nil)
		featureDetector.NewCmd = dataplane.NewCmd
		featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader
		table = NewTable(
			"filter",
			6,
			rules.RuleHashPrefix,
			iptLock,
			featureDetector,
			TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				NewCmdOverride:        dataplane.NewCmd,
				SleepOverride:         dataplane.Sleep,
				NowOverride:           dataplane.Now,
				BackendMode:           dataplaneMode,
				LookPathOverride:      testutils.LookPathNoLegacy,
				OpRecorder:            logutils.NewSummarizer("test loop"),
			},
		)
		table.InsertOrAppendRules("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.Apply()
	})

	It("should do the insertion", func() {
		Expect(dataplane.Chains).To(Equal(map[string][]string{
			"FORWARD":    {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
			"non-calico": {"-m comment \"foo\""},
		}))
	})

	Describe("after removing the other chain", func() {
		BeforeEach(func() {
			dataplane.Chains = map[string][]string{
				"FORWARD": {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
			}
			dataplane.ResetCmds()
			iptLock.WasTaken = false
			iptLock.Held = false
			table.Apply()
		})

		It("should ignore the deletion", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP"},
			}))
		})
		It("should make no changes to the dataplane", func() {
			Expect(dataplane.CmdNames).To(BeEmpty())
		})
		It("should not take the lock", func() {
			Expect(iptLock.WasTaken).To(BeFalse())
		})
	})
}

type mockMutex struct {
	Held     bool
	WasTaken bool
}

func (m *mockMutex) Lock() {
	if m.Held {
		Fail("Mutex already held")
	}
	m.Held = true
	m.WasTaken = true
}

func (m *mockMutex) Unlock() {
	if !m.Held {
		Fail("Mutex not held")
	}
	m.Held = false
}
