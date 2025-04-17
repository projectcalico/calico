// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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
	_ "crypto/sha256" // register hash func
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/hash"
)

// Labels defines the interface of labels that can be used by selector
type Labels interface {
	// Get returns value and presence of the given labelName
	Get(labelName string) (value string, present bool)
}

// MapAsLabels allows you use map as labels
type MapAsLabels map[string]string

// Get returns the value and presence of the given labelName key in the MapAsLabels
func (l MapAsLabels) Get(labelName string) (value string, present bool) {
	value, present = l[labelName]
	return
}

type LabelRestriction struct {
	// MustBePresent is true if this label must be present for the selector to
	// match. For example "has(labelName)" or "labelName == 'foo'"
	MustBePresent bool
	// MustBeAbsent is true if this label must be absent for this selector to
	// match. For example "!has(labelName)".
	MustBeAbsent bool
	// MustHaveOneOfValues if non-nil, indicates that the label must have one
	// of the listed values in order to match the selector.
	//
	// If nil, no such restriction is known.  For example "has(labelName)"
	//
	// Note: non-nil empty slice means "selector cannot match anything". For
	// example an inconsistent selector such as: "a == 'B' && a == 'C'"
	MustHaveOneOfValues []string
}

func (r LabelRestriction) PossibleToSatisfy() bool {
	if r.MustBePresent && r.MustBeAbsent {
		return false
	}
	if r.MustHaveOneOfValues != nil && len(r.MustHaveOneOfValues) == 0 {
		return false
	}
	return true
}

type Visitor interface {
	Visit(n interface{})
}

// PrefixVisitor implements the Visitor interface to allow prefixing of
// label names within a selector.
type PrefixVisitor struct {
	Prefix string
}

func (v PrefixVisitor) Visit(n interface{}) {
	log.Debugf("PrefixVisitor visiting node %#v", n)
	switch np := n.(type) {
	case *LabelEqValueNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelNeValueNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelContainsValueNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelStartsWithValueNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelEndsWithValueNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *HasNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelInSetNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	case *LabelNotInSetNode:
		np.LabelName = fmt.Sprintf("%s%s", v.Prefix, np.LabelName)
	default:
		log.Debug("Node is a no-op")
	}
}

type Selector struct {
	root              Node
	stringRep         string
	hash              string
	labelRestrictions map[string]LabelRestriction
}

func (sel *Selector) Evaluate(labels map[string]string) bool {
	return sel.EvaluateLabels(MapAsLabels(labels))
}

func (sel *Selector) EvaluateLabels(labels Labels) bool {
	return sel.root.Evaluate(labels)
}

func (sel *Selector) AcceptVisitor(v Visitor) {
	sel.root.AcceptVisitor(v)
	sel.updateFields()
}

func (sel *Selector) String() string {
	return sel.stringRep
}

func (sel *Selector) UniqueID() string {
	return sel.hash
}

func (sel *Selector) LabelRestrictions() map[string]LabelRestriction {
	return sel.labelRestrictions
}

func (sel *Selector) Equal(other *Selector) bool {
	if sel == nil || other == nil {
		return sel == other
	}
	return other.hash == sel.hash
}

func (sel *Selector) Root() Node {
	return sel.root
}

func (sel *Selector) updateFields() {
	fragments := sel.root.collectFragments([]string{})
	str := strings.Join(fragments, "")
	sel.stringRep = str
	sel.hash = hash.MakeUniqueID("s", str)
	sel.labelRestrictions = sel.root.LabelRestrictions()
}

type Node interface {
	Evaluate(labels Labels) bool
	AcceptVisitor(v Visitor)
	LabelRestrictions() map[string]LabelRestriction
	collectFragments(fragments []string) []string
}

type LabelEqValueNode struct {
	LabelName string
	Value     string
}

func (node *LabelEqValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return val == node.Value
	}
	return false
}

func (node *LabelEqValueNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent:       true,
			MustHaveOneOfValues: []string{node.Value},
		},
	}
}

func (node *LabelEqValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelEqValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName, " == ", node.Value)
}

type LabelContainsValueNode struct {
	LabelName string
	Value     string
}

func (node *LabelContainsValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return strings.Contains(val, node.Value)
	}
	return false
}

func (node *LabelContainsValueNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelContainsValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelContainsValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName, " contains ", node.Value)
}

type LabelStartsWithValueNode struct {
	LabelName string
	Value     string
}

func (node *LabelStartsWithValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return strings.HasPrefix(val, node.Value)
	}
	return false
}

func (node *LabelStartsWithValueNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelStartsWithValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelStartsWithValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName, " starts with ", node.Value)
}

type LabelEndsWithValueNode struct {
	LabelName string
	Value     string
}

func (node *LabelEndsWithValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return strings.HasSuffix(val, node.Value)
	}
	return false
}

func (node *LabelEndsWithValueNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelEndsWithValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelEndsWithValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName, " ends with ", node.Value)
}

type LabelInSetNode struct {
	LabelName string
	Value     StringSet
}

func (node *LabelInSetNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return node.Value.Contains(val)
	}
	return false
}

func (node *LabelInSetNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent:       true,
			MustHaveOneOfValues: node.Value.SliceCopy(),
		},
	}
}

func (node *LabelInSetNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelInSetNode) collectFragments(fragments []string) []string {
	return collectInOpFragments(fragments, node.LabelName, "in", node.Value)
}

type LabelNotInSetNode struct {
	LabelName string
	Value     StringSet
}

func (node *LabelNotInSetNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelNotInSetNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return !node.Value.Contains(val)
	}
	return true
}

func (node *LabelNotInSetNode) LabelRestrictions() map[string]LabelRestriction {
	return nil
}

func (node *LabelNotInSetNode) collectFragments(fragments []string) []string {
	return collectInOpFragments(fragments, node.LabelName, "not in", node.Value)
}

// collectInOpFragments is a shared implementation of collectFragments
// for the 'in' and 'not in' operators.
func collectInOpFragments(fragments []string, labelName, op string, values StringSet) []string {
	var quote string
	fragments = append(fragments, labelName, " ", op, " {")
	first := true
	for _, s := range values {
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

func (node *LabelNeValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.Get(node.LabelName)
	if ok {
		return val != node.Value
	}
	return true
}

func (node *LabelNeValueNode) LabelRestrictions() map[string]LabelRestriction {
	return nil
}

func (node *LabelNeValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelNeValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName, " != ", node.Value)
}

type HasNode struct {
	LabelName string
}

func (node *HasNode) Evaluate(labels Labels) bool {
	_, ok := labels.Get(node.LabelName)
	if ok {
		return true
	}
	return false
}

func (node *HasNode) LabelRestrictions() map[string]LabelRestriction {
	return map[string]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *HasNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *HasNode) collectFragments(fragments []string) []string {
	return append(fragments, "has(", node.LabelName, ")")
}

var _ Node = (*HasNode)(nil)

type NotNode struct {
	Operand Node
}

func (node *NotNode) Evaluate(labels Labels) bool {
	return !node.Operand.Evaluate(labels)
}

func (node *NotNode) LabelRestrictions() map[string]LabelRestriction {
	if hasNode, ok := node.Operand.(*HasNode); ok {
		// !has() explicitly forbids the labels.
		lr := hasNode.LabelRestrictions()
		for k := range lr {
			lr[k] = LabelRestriction{MustBeAbsent: true}
		}
		return lr
	}
	// Can't invert most types of match;
	// a == 'b' requires label "a"
	// but
	// !(a == 'b') does *not* require the absence of label "a"
	return nil
}

func (node *NotNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
	node.Operand.AcceptVisitor(v)
}

func (node *NotNode) collectFragments(fragments []string) []string {
	fragments = append(fragments, "!")
	return node.Operand.collectFragments(fragments)
}

type AndNode struct {
	Operands []Node
}

func (node *AndNode) Evaluate(labels Labels) bool {
	for _, operand := range node.Operands {
		if !operand.Evaluate(labels) {
			return false
		}
	}
	return true
}

func (node *AndNode) LabelRestrictions() map[string]LabelRestriction {
	lr := map[string]LabelRestriction{}
	for _, op := range node.Operands {
		opLR := op.LabelRestrictions()
		for ln, r := range opLR {
			base := lr[ln]
			base.MustBePresent = base.MustBePresent || r.MustBePresent
			base.MustBeAbsent = base.MustBeAbsent || r.MustBeAbsent
			if base.MustHaveOneOfValues == nil {
				base.MustHaveOneOfValues = r.MustHaveOneOfValues
			} else if r.MustHaveOneOfValues != nil {
				base.MustHaveOneOfValues = intersectStringSlicesInPlace(base.MustHaveOneOfValues, r.MustHaveOneOfValues)
			}
			lr[ln] = base
		}
	}
	if len(lr) == 0 {
		return nil
	}
	return lr
}

func intersectStringSlicesInPlace(a []string, b []string) []string {
	out := a[:0]
	bSet := ConvertToStringSetInPlace(b)
	for _, v1 := range a {
		if bSet.Contains(v1) {
			out = append(out, v1)
		}
	}
	return out
}

func (node *AndNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
	for _, op := range node.Operands {
		op.AcceptVisitor(v)
	}
}

func (node *AndNode) collectFragments(fragments []string) []string {
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
	Operands []Node
}

func (node *OrNode) Evaluate(labels Labels) bool {
	for _, operand := range node.Operands {
		if operand.Evaluate(labels) {
			return true
		}
	}
	return false
}

func (node *OrNode) LabelRestrictions() map[string]LabelRestriction {
	lr := node.Operands[0].LabelRestrictions()
	for _, op := range node.Operands[1:] {
		opLR := op.LabelRestrictions()
		for ln, r := range lr {
			opr := opLR[ln]
			r.MustBePresent = r.MustBePresent && opr.MustBePresent
			if !r.MustBePresent {
				r.MustHaveOneOfValues = nil
			} else {
				if r.MustHaveOneOfValues == nil || opr.MustHaveOneOfValues == nil {
					// At least one side is has(label) so we can't limit on value.
					r.MustHaveOneOfValues = nil
				} else {
					// Both sides place limits on the value, add them together since either is good enough.
					r.MustHaveOneOfValues = unionStringSlicesInPlace(r.MustHaveOneOfValues, opr.MustHaveOneOfValues)
				}
			}
			r.MustBeAbsent = r.MustBeAbsent && opr.MustBeAbsent
			if r.MustBePresent || r.MustBeAbsent {
				lr[ln] = r
			} else {
				delete(lr, ln)
			}
		}
	}
	if len(lr) == 0 {
		return nil
	}
	return lr
}

func unionStringSlicesInPlace(a []string, b []string) []string {
	// aSet will share storage with a, but when we append to a, it doesn't
	// affect aSet.
	aSet := ConvertToStringSetInPlace(a)
	for _, v := range b {
		if !aSet.Contains(v) {
			a = append(a, v)
		}
	}
	return a
}

func (node *OrNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
	for _, op := range node.Operands {
		op.AcceptVisitor(v)
	}
}

func (node *OrNode) collectFragments(fragments []string) []string {
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

func (node *AllNode) LabelRestrictions() map[string]LabelRestriction {
	return nil
}

func (node *AllNode) Evaluate(labels Labels) bool {
	return true
}

func (node *AllNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *AllNode) collectFragments(fragments []string) []string {
	return append(fragments, "all()")
}

func appendLabelOpAndQuotedString(fragments []string, label, op, s string) []string {
	var quote string
	if strings.Contains(s, `"`) {
		quote = `'`
	} else {
		quote = `"`
	}
	return append(fragments, label, op, quote, s, quote)
}

type GlobalNode struct {
}

func (node *GlobalNode) LabelRestrictions() map[string]LabelRestriction {
	return nil
}

func (node *GlobalNode) Evaluate(labels Labels) bool {
	return true
}

func (node *GlobalNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *GlobalNode) collectFragments(fragments []string) []string {
	return append(fragments, "global()")
}
