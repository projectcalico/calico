// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/projectcalico/felix/iptables"

	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/rules"

	"time"

	log "github.com/Sirupsen/logrus"
)

var _ = Describe("Table with an empty dataplane", func() {
	var dataplane *mockDataplane
	var table *Table
	BeforeEach(func() {
		dataplane = newMockDataplane("filter", map[string][]string{
			"FORWARD": {},
			"INPUT":   {},
			"OUTPUT":  {},
		})
		table = NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				NewCmdOverride:        dataplane.newCmd,
				SleepOverride:         dataplane.sleep,
			},
		)
	})

	It("Should defer updates until Apply is called", func() {
		table.SetRuleInsertions("FORWARD", []Rule{
			{Action: DropAction{}},
		})
		table.UpdateChains([]*Chain{
			{Name: "cali-foobar", Rules: []Rule{{Action: AcceptAction{}}}},
		})
		Expect(len(dataplane.Cmds)).To(BeZero())
		table.Apply()
		Expect(len(dataplane.Cmds)).NotTo(BeZero())
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
				TableOptions{
					HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
					NewCmdOverride:        dataplane.newCmd,
					SleepOverride:         dataplane.sleep,
					InsertMode:            "unknown",
				},
			)
		}).To(Panic())
	})

	Describe("after inserting a rule", func() {
		BeforeEach(func() {
			table.SetRuleInsertions("FORWARD", []Rule{
				{Action: DropAction{}},
			})
			table.Apply()
		})
		It("should be in the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
				"INPUT":   {},
				"OUTPUT":  {},
			}))
		})
		It("further inserts should be idempotent", func() {
			table.SetRuleInsertions("FORWARD", []Rule{
				{Action: DropAction{}},
			})
			dataplane.Cmds = nil
			table.Apply()
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
				"INPUT":   {},
				"OUTPUT":  {},
			}))
			Expect(len(dataplane.Cmds)).To(BeZero(),
				fmt.Sprintf("Unexpected commands: %v", dataplane.Cmds))
		})

		Describe("after inserting a rule then updating the insertions", func() {
			BeforeEach(func() {
				table.SetRuleInsertions("FORWARD", []Rule{
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
			It("should put it back on the next refresh", func() {
				table.InvalidateDataplaneCache()
				table.Apply()
				Expect(dataplane.Chains).To(Equal(map[string][]string{
					"FORWARD": {`-m comment --comment "cali:hecdSCslEjdBPBPo" --jump DROP`},
					"INPUT":   {},
					"OUTPUT":  {},
				}))
			})
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
				table.InvalidateDataplaneCache()
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
		It("should be in the dataplane", func() {
			Expect(dataplane.Chains).To(Equal(map[string][]string{
				"FORWARD": {},
				"INPUT":   {},
				"OUTPUT":  {},
				"cali-foobar": {
					"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
					"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
				},
			}))
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
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
					"cali-foobar": {
						"-m comment --comment \"cali:I9LKcIJU9vtw4suw\" --jump DROP",
						"-m comment --comment \"cali:2XsaWB87aQT7Fxgc\" --jump ACCEPT",
					},
				}))
			})
			It("shouldn't get written more than once", func() {
				dataplane.Cmds = nil
				table.Apply()
				Expect(len(dataplane.Cmds)).To(BeZero(),
					fmt.Sprintf("Unexpected commands: %v", dataplane.Cmds))
			})
			It("should squash idempotent updates", func() {
				table.UpdateChains([]*Chain{
					{Name: "cali-foobar", Rules: []Rule{
						// Same data as above.
						{Action: DropAction{}},
						{Action: AcceptAction{}},
					}},
				})
				dataplane.Cmds = nil
				table.Apply()
				Expect(len(dataplane.Cmds)).To(BeZero(),
					fmt.Sprintf("Unexpected commands: %v", dataplane.Cmds))
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
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
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
						"FORWARD": {},
						"INPUT":   {},
						"OUTPUT":  {},
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
						"FORWARD": {},
						"INPUT":   {},
						"OUTPUT":  {},
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
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
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
					"FORWARD": {},
					"INPUT":   {},
					"OUTPUT":  {},
				}))
			})
		})
	})
})

func describeDirtyDataplaneTests(appendMode bool) {
	// These tests all start with some rules already in the dataplane.  We include a mix of
	// Calico and non-Calico rules.  Within the Calico rules,we include:
	// - rules that match what we're going to ask the Table to program
	// - rules that differ and need to be detected/replaced
	// - rules that are unexpected (in chains that need to be removed)
	// - rules from previous Calico versions, using different chain name prefixes
	// - rules that only match the special-case regex.
	var dataplane *mockDataplane
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
		dataplane = newMockDataplane("filter", initialChains())
		insertMode := ""
		if appendMode {
			insertMode = "append"
		}
		table = NewTable(
			"filter",
			4,
			rules.RuleHashPrefix,
			TableOptions{
				HistoricChainPrefixes:    rules.AllHistoricChainNamePrefixes,
				ExtraCleanupRegexPattern: "sneaky-rule",
				NewCmdOverride:           dataplane.newCmd,
				SleepOverride:            dataplane.sleep,
				InsertMode:               insertMode,
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

	Describe("with pre-cleanup inserts and updates", func() {
		// These tests inject some chains and insertions before the first call to Apply().
		// That should mean that the Table does a sync operation, avoiding updates to
		// chains/rules that haven't changed, for example.
		BeforeEach(func() {
			table.SetRuleInsertions("FORWARD", []Rule{
				{Action: DropAction{}},
				{Action: AcceptAction{}},
			})
			table.SetRuleInsertions("OUTPUT", []Rule{
				{Action: DropAction{}},
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
				}
			} else {
				expChains["FORWARD"] = []string{
					"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
					"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
					"--jump RETURN",
					"--jump ACCEPT",
					"--jump foo-bar",
				}
			}

			Expect(dataplane.Chains).To(Equal(expChains))
		}
		It("with no errors, it should get to correct final state", func() {
			table.Apply()
			checkFinalState()
			Expect(len(dataplane.Cmds)).To(Equal(2)) // a save and a restore
		})
		It("with no errors, it shouldn't sleep", func() {
			table.Apply()
			Expect(dataplane.CumulativeSleep).To(BeZero())
		})
		Describe("With a transient iptables-save failure", func() {
			BeforeEach(func() {
				dataplane.FailNextSave = true
				table.Apply()
			})
			It("it should get to correct final state", func() {
				checkFinalState()
			})
			It("it should retry once", func() {
				Expect(len(dataplane.Cmds)).To(Equal(3)) // 2 saves and a restore
			})
			It("it should sleep", func() {
				Expect(dataplane.CumulativeSleep).To(Equal(100 * time.Millisecond))
			})
		})
		Describe("With a persistent iptables-save failure", func() {
			BeforeEach(func() {
				dataplane.FailAllSaves = true
			})
			It("it should panic", func() {
				Expect(table.Apply).To(Panic())
			}, 1)
			It("it should do exponential backoff", func() {
				Expect(table.Apply).To(Panic())
				Expect(dataplane.CumulativeSleep).To(Equal((100 + 200 + 400) * time.Millisecond))
			}, 1)
			It("it should retry 3 times", func() {
				Expect(table.Apply).To(Panic())
				Expect(len(dataplane.Cmds)).To(Equal(4))
			}, 1)
		})

		It("shouldn't touch already-correct chain", func() {
			table.Apply()
			Expect(dataplane.RuleTouched("cali-correct", 1)).To(BeFalse())
		})
		It("shouldn't touch already-correct rules", func() {
			table.Apply()
			// First two rules are already correct...
			Expect(dataplane.RuleTouched("cali-foobar", 1)).To(BeFalse())
			Expect(dataplane.RuleTouched("cali-foobar", 2)).To(BeFalse())
			// Third rule is incorrect.
			Expect(dataplane.RuleTouched("cali-foobar", 3)).To(BeTrue())
		})
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
				Expect(table.Apply).To(Panic())
			}, 1)
			It("it should do exponential backoff", func() {
				Expect(table.Apply).To(Panic())
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
					},
					"cali-foobar": {
						"-m comment --comment \"cali:42h7Q64_2XDzpwKe\" --jump ACCEPT",
						"-m comment --comment \"cali:0sUFHicPNNqNyNx8\" --jump DROP",
						"-m comment --comment \"cali:yilSOZ62PxMhMnS9\" --jump RETURN",
					},
					"INPUT": {},
					"OUTPUT": {
						"-m comment --comment \"cali:RtPHXnCQBd3uyJfJ\" --jump DROP",
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
				table.InvalidateDataplaneCache()
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
				table.SetRuleInsertions("OUTPUT", []Rule{
					{Action: AcceptAction{}},
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
					}
				} else {
					expChains["FORWARD"] = []string{
						"-m comment --comment \"cali:hecdSCslEjdBPBPo\" --jump DROP",
						"-m comment --comment \"cali:plvr29-ZiKUwbzDV\" --jump ACCEPT",
						"--jump RETURN",
						"--jump ACCEPT",
						"--jump foo-bar",
					}
				}

				Expect(dataplane.Chains).To(Equal(expChains))
			})
		})
	})
}

var _ = Describe("Table with a dirty datatplane in append mode", func() { describeDirtyDataplaneTests(true) })
var _ = Describe("Table with a dirty datatplane in insert mode", func() { describeDirtyDataplaneTests(false) })
