// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package nftables

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/onsi/gomega/types"
	"sigs.k8s.io/knftables"
)

type containRule struct {
	expected knftables.Rule
}

func (c *containRule) Match(actual interface{}) (success bool, err error) {
	rules, ok := actual.([]*knftables.Rule)
	if !ok {
		return false, fmt.Errorf("Expected []*knftables.Rule, but got: %+v", reflect.TypeOf(actual).String())
	}

	// Nil out the handle since this is generated.
	for _, ar := range rules {
		// Make a copy so we don't modify the original.
		compare := *ar
		compare.Handle = nil
		if reflect.DeepEqual(compare, c.expected) {
			return true, nil
		}
	}
	return false, nil
}

func (c *containRule) FailureMessage(actual interface{}) (message string) {
	j, _ := json.MarshalIndent(actual, "", "  ")
	return fmt.Sprintf("Expected rules to contain %+v.\nRules: %s", c.expected, j)
}

func (c *containRule) NegatedFailureMessage(actual interface{}) (message string) {
	j, _ := json.MarshalIndent(actual, "", "  ")
	return fmt.Sprintf("Expected rules to not contain %+v.\nRules: %s", c.expected, j)
}

func ContainRule(rule knftables.Rule) types.GomegaMatcher {
	return &containRule{
		expected: rule,
	}
}

type equalRulesMatcher struct {
	expectComments bool
	expected       []knftables.Rule
}

// EqualRulesFuzzy is a matcher that compares two slices of knftables.Rule. It ignores the Handle field and the Comment field,
// since we don't need to verify the comments on every single test, and this makes writing and reading tests easier.
func EqualRulesFuzzy(expected []knftables.Rule) types.GomegaMatcher {
	return &equalRulesMatcher{
		expectComments: false,
		expected:       expected,
	}
}

func EqualRules(expected []knftables.Rule) types.GomegaMatcher {
	return &equalRulesMatcher{
		expectComments: true,
		expected:       expected,
	}
}

func (e *equalRulesMatcher) Match(actual interface{}) (success bool, err error) {
	rules, ok := actual.([]*knftables.Rule)
	if !ok {
		return false, fmt.Errorf("Expected []*knftables.Rule, but got: %+v", reflect.TypeOf(actual).String())
	}

	if len(rules) != len(e.expected) {
		return false, nil
	}

	for i := range rules {
		exp := e.expected[i]
		cp := *rules[i]
		cp.Handle = nil
		if !e.expectComments {
			cp.Comment = nil
		}
		if !reflect.DeepEqual(cp, exp) {
			return false, nil
		}
	}
	return true, nil
}

func (e *equalRulesMatcher) FailureMessage(actual interface{}) (message string) {
	exp, _ := json.MarshalIndent(e.expected, "", "  ")
	act, _ := json.MarshalIndent(actual, "", "  ")
	return fmt.Sprintf("Expected rules to equal %s, but got %s", exp, act)
}

func (e *equalRulesMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	exp, _ := json.MarshalIndent(e.expected, "", "  ")
	act, _ := json.MarshalIndent(actual, "", "  ")

	return fmt.Sprintf("Expected rules to not equal %s, but got %s", exp, act)
}
