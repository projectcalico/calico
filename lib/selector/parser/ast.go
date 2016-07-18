// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package parser

import (
	_ "crypto/sha256"
	"strings"

	"github.com/tigera/libcalico-go/lib/hash"
)

type Selector interface {
	Evaluate(labels map[string]string) bool
	String() string
	UniqueId() string
}

type selectorRoot struct {
	root         node
	cachedString *string
	cachedHash   *string
}

func (sel selectorRoot) Evaluate(labels map[string]string) bool {
	return sel.root.Evaluate(labels)
}

func (sel selectorRoot) String() string {
	if sel.cachedString == nil {
		fragments := sel.root.collectFragments([]string{})
		joined := strings.Join(fragments, "")
		sel.cachedString = &joined
	}
	return *sel.cachedString
}

func (sel selectorRoot) UniqueId() string {
	if sel.cachedHash == nil {
		hash := hash.MakeUniqueID("s", sel.String())
		sel.cachedHash = &hash
	}
	return *sel.cachedHash
}

var _ Selector = (*selectorRoot)(nil)

type node interface {
	Evaluate(labels map[string]string) bool
	collectFragments(fragments []string) []string
}

type LabelEqValueNode struct {
	LabelName string
	Value     string
}

func (node LabelEqValueNode) Evaluate(labels map[string]string) bool {
	if val, ok := labels[node.LabelName]; ok {
		return val == node.Value
	} else {
		return false
	}
}

func (node LabelEqValueNode) collectFragments(fragments []string) []string {
	var quote string
	if strings.Contains(node.Value, `"`) {
		quote = `'`
	} else {
		quote = `"`
	}
	return append(fragments, node.LabelName, " == ", quote, node.Value, quote)
}

type LabelInSetNode struct {
	LabelName string
	Value     map[string]bool
}

func (node LabelInSetNode) Evaluate(labels map[string]string) bool {
	if val, ok := labels[node.LabelName]; ok {
		return node.Value[val]
	} else {
		return false
	}
}

func (node LabelInSetNode) collectFragments(fragments []string) []string {
	var quote string
	fragments = append(fragments, node.LabelName, " in {")
	first := true
	for s, _ := range node.Value {
		if strings.Contains(s, `"`) {
			quote = `'`
		} else {
			quote = `"`
		}
		if !first {
			fragments = append(fragments, ", ")
		} else {
			first = false
		}
		fragments = append(fragments, quote, s, quote)
	}
	fragments = append(fragments, "}")
	return fragments
}

type LabelNotInSetNode struct {
	LabelName string
	Value     map[string]bool
}

func (node LabelNotInSetNode) Evaluate(labels map[string]string) bool {
	if val, ok := labels[node.LabelName]; ok {
		return !node.Value[val]
	} else {
		return true
	}
}

func (node LabelNotInSetNode) collectFragments(fragments []string) []string {
	var quote string
	fragments = append(fragments, node.LabelName, " not in {")
	first := true
	for s, _ := range node.Value {
		if strings.Contains(s, `"`) {
			quote = `'`
		} else {
			quote = `"`
		}
		if !first {
			fragments = append(fragments, ", ")
		} else {
			first = false
		}
		fragments = append(fragments, quote, s, quote)
	}
	fragments = append(fragments, "}")
	return fragments
}

type LabelNeValueNode struct {
	LabelName string
	Value     string
}

func (node LabelNeValueNode) Evaluate(labels map[string]string) bool {
	if val, ok := labels[node.LabelName]; ok {
		return val != node.Value
	} else {
		return true
	}
}

func (node LabelNeValueNode) collectFragments(fragments []string) []string {
	var quote string
	if strings.Contains(node.Value, `"`) {
		quote = `'`
	} else {
		quote = `"`
	}
	return append(fragments, node.LabelName, " != ", quote, node.Value, quote)
}

type HasNode struct {
	LabelName string
}

func (node HasNode) Evaluate(labels map[string]string) bool {
	if _, ok := labels[node.LabelName]; ok {
		return true
	} else {
		return false
	}
}

func (node HasNode) collectFragments(fragments []string) []string {
	return append(fragments, "has(", node.LabelName, ")")
}

type NotNode struct {
	Operand node
}

func (node NotNode) Evaluate(labels map[string]string) bool {
	return !node.Operand.Evaluate(labels)
}

func (node NotNode) collectFragments(fragments []string) []string {
	fragments = append(fragments, "!")
	return node.Operand.collectFragments(fragments)
}

type AndNode struct {
	Operands []node
}

func (node AndNode) Evaluate(labels map[string]string) bool {
	for _, operand := range node.Operands {
		if !operand.Evaluate(labels) {
			return false
		}
	}
	return true
}

func (node AndNode) collectFragments(fragments []string) []string {
	fragments = append(fragments, "(")
	fragments = node.Operands[0].collectFragments(fragments)
	for _, op := range node.Operands[1:] {
		fragments = append(fragments, " && ")
		fragments = op.collectFragments(fragments)
	}
	fragments = append(fragments, ")")
	return fragments
}

type OrNode struct {
	Operands []node
}

func (node OrNode) Evaluate(labels map[string]string) bool {
	for _, operand := range node.Operands {
		if operand.Evaluate(labels) {
			return true
		}
	}
	return false
}

func (node OrNode) collectFragments(fragments []string) []string {
	fragments = append(fragments, "(")
	fragments = node.Operands[0].collectFragments(fragments)
	for _, op := range node.Operands[1:] {
		fragments = append(fragments, " || ")
		fragments = op.collectFragments(fragments)
	}
	fragments = append(fragments, ")")
	return fragments
}

type AllNode struct {
}

func (node AllNode) Evaluate(labels map[string]string) bool {
	return true
}

func (node AllNode) collectFragments(fragments []string) []string {
	return append(fragments, "all()")
}
