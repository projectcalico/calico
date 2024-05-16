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
	expected []knftables.Rule
}

func EqualRules(expected []knftables.Rule) types.GomegaMatcher {
	return &equalRulesMatcher{
		expected: expected,
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
		cp := *rules[i]
		cp.Handle = nil
		if !reflect.DeepEqual(cp, e.expected[i]) {
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
