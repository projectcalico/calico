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
	"iter"
	"maps"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/hash"
)

// Labels defines the interface of labels that can be used by selector
type Labels interface {
	GetHandle(labelName uniquestr.Handle) (handle uniquestr.Handle, present bool)
}

// MapAsLabels allows you use a string map as the Labels interface.
// Useful for testing.
type MapAsLabels map[string]string

func (l MapAsLabels) GetHandle(labelName uniquestr.Handle) (handle uniquestr.Handle, present bool) {
	value, present := l[labelName.Value()]
	return uniquestr.Make(value), present
}

// LabelRestrictions wraps the label restriction map, preventing callers from
// modifying the underlying map (which may be cached).
type LabelRestrictions struct {
	m map[uniquestr.Handle]LabelRestriction
}

// MakeLabelRestrictions creates a LabelRestrictions wrapper around the given map.
// The caller should not modify the map after passing it to this function.
func MakeLabelRestrictions(m map[uniquestr.Handle]LabelRestriction) LabelRestrictions {
	return LabelRestrictions{m: m}
}

func (lr LabelRestrictions) All() iter.Seq2[uniquestr.Handle, LabelRestriction] {
	return maps.All(lr.m)
}

func (lr LabelRestrictions) Get(key uniquestr.Handle) (LabelRestriction, bool) {
	v, ok := lr.m[key]
	return v, ok
}

func (lr LabelRestrictions) Len() int {
	return len(lr.m)
}

func (lr LabelRestrictions) String() string {
	m := map[string]LabelRestriction{}
	for k, v := range lr.m {
		m[k.Value()] = v
	}
	return fmt.Sprint(m)
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
	MustHaveOneOfValues []uniquestr.Handle
}

func (l LabelRestriction) String() string {
	return fmt.Sprintf("{MustBePresent:%v, MustBeAbsent:%v, MustHaveOneOfValues:%v}",
		l.MustBePresent, l.MustBeAbsent, uniquestr.HandleSliceStringer(l.MustHaveOneOfValues))
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
	Visit(n any)
}

// PrefixVisitor implements the Visitor interface to allow prefixing of
// label names within a selector.
type PrefixVisitor struct {
	Prefix string
}

func (v PrefixVisitor) Visit(n any) {
	log.Debugf("PrefixVisitor visiting node %#v", n)
	switch np := n.(type) {
	case *LabelEqValueNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelNeValueNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelContainsValueNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelStartsWithValueNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelEndsWithValueNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *HasNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelInSetNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	case *LabelNotInSetNode:
		np.LabelName = uniquestr.Make(fmt.Sprintf("%s%s", v.Prefix, np.LabelName.Value()))
	default:
		log.Debug("Node is a no-op")
	}
}

type Selector struct {
	root      Node
	stringRep string
	hash      string
}

// Evaluate the selector against the given labels map.
// Deprecated: use EvaluateLabels instead. Evaluate is slow because it calculates unique.Handles on the fly.
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

var (
	lastRestrictionMutex    sync.Mutex
	lastRestrictionSelector *Selector
	lastLabelRestrictions   map[uniquestr.Handle]LabelRestriction
)

// LabelRestrictions returns a set of lower bound restrictions on the labels
// that would match this selector.  For example, for "a == 'b' && has(c)", the
// label restrictions would be "a must be present and have value 'b', c must be
// present".
//
// Since it's common to call LabelRestrictions multiple times for the same
// selector in quick succession, we cache the most recently calculated value
// at package level.  The cache is thread safe and deals with the calculation
// graph's common usage pattern.
func (sel *Selector) LabelRestrictions() LabelRestrictions {
	// We used to store the label restrictions in a field, but, if there are many selectors active
	// the maps really add up.  Calculate them on demand, but cache the most recently calculated
	// one because the LabelRestrictions are used multiple times when adding a particular selector
	// to the named port index. (Since that is single threaded, caching exactly 1 gives a big win.)
	//
	// The LabelRestrictions struct wraps the map to prevent callers from accidentally modifying
	// the cached map.
	lastRestrictionMutex.Lock()
	defer lastRestrictionMutex.Unlock()
	if lastRestrictionSelector != sel {
		lastRestrictionSelector = sel
		lastLabelRestrictions = sel.root.LabelRestrictions()
	}
	return MakeLabelRestrictions(lastLabelRestrictions)
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
}

type Node interface {
	Evaluate(labels Labels) bool
	AcceptVisitor(v Visitor)
	LabelRestrictions() map[uniquestr.Handle]LabelRestriction
	collectFragments(fragments []string) []string
}

type LabelEqValueNode struct {
	LabelName uniquestr.Handle
	Value     uniquestr.Handle
}

func (node *LabelEqValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return val == node.Value
	}
	return false
}

func (node *LabelEqValueNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
		node.LabelName: {
			MustBePresent:       true,
			MustHaveOneOfValues: []uniquestr.Handle{node.Value},
		},
	}
}

func (node *LabelEqValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelEqValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName.Value(), " == ", node.Value.Value())
}

type LabelContainsValueNode struct {
	LabelName uniquestr.Handle
	Value     uniquestr.Handle
}

func (node *LabelContainsValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return strings.Contains(val.Value(), node.Value.Value())
	}
	return false
}

func (node *LabelContainsValueNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelContainsValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelContainsValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName.Value(), " contains ", node.Value.Value())
}

type LabelStartsWithValueNode struct {
	LabelName uniquestr.Handle
	Value     uniquestr.Handle
}

func (node *LabelStartsWithValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return strings.HasPrefix(val.Value(), node.Value.Value())
	}
	return false
}

func (node *LabelStartsWithValueNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelStartsWithValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelStartsWithValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName.Value(), " starts with ", node.Value.Value())
}

type LabelEndsWithValueNode struct {
	LabelName uniquestr.Handle
	Value     uniquestr.Handle
}

func (node *LabelEndsWithValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return strings.HasSuffix(val.Value(), node.Value.Value())
	}
	return false
}

func (node *LabelEndsWithValueNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *LabelEndsWithValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelEndsWithValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName.Value(), " ends with ", node.Value.Value())
}

type LabelInSetNode struct {
	LabelName uniquestr.Handle
	Value     StringSet
}

func (node *LabelInSetNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return node.Value.Contains(val)
	}
	return false
}

func (node *LabelInSetNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
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
	return collectInOpFragments(fragments, node.LabelName.Value(), "in", node.Value)
}

type LabelNotInSetNode struct {
	LabelName uniquestr.Handle
	Value     StringSet
}

func (node *LabelNotInSetNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelNotInSetNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return !node.Value.Contains(val)
	}
	return true
}

func (node *LabelNotInSetNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return nil
}

func (node *LabelNotInSetNode) collectFragments(fragments []string) []string {
	return collectInOpFragments(fragments, node.LabelName.Value(), "not in", node.Value)
}

// collectInOpFragments is a shared implementation of collectFragments
// for the 'in' and 'not in' operators.
func collectInOpFragments(fragments []string, labelName, op string, values StringSet) []string {
	var quote string
	fragments = append(fragments, labelName, " ", op, " {")
	first := true
	for _, h := range values {
		s := h.Value()
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
	LabelName uniquestr.Handle
	Value     uniquestr.Handle
}

func (node *LabelNeValueNode) Evaluate(labels Labels) bool {
	val, ok := labels.GetHandle(node.LabelName)
	if ok {
		return val != node.Value
	}
	return true
}

func (node *LabelNeValueNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return nil
}

func (node *LabelNeValueNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *LabelNeValueNode) collectFragments(fragments []string) []string {
	return appendLabelOpAndQuotedString(fragments, node.LabelName.Value(), " != ", node.Value.Value())
}

type HasNode struct {
	LabelName uniquestr.Handle
}

func (node *HasNode) Evaluate(labels Labels) bool {
	_, ok := labels.GetHandle(node.LabelName)
	if ok {
		return true
	}
	return false
}

func (node *HasNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return map[uniquestr.Handle]LabelRestriction{
		node.LabelName: {
			MustBePresent: true,
		},
	}
}

func (node *HasNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *HasNode) collectFragments(fragments []string) []string {
	return append(fragments, "has(", node.LabelName.Value(), ")")
}

var _ Node = (*HasNode)(nil)

type NotNode struct {
	Operand Node
}

func (node *NotNode) Evaluate(labels Labels) bool {
	return !node.Operand.Evaluate(labels)
}

func (node *NotNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
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

func (node *AndNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	lr := map[uniquestr.Handle]LabelRestriction{}
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

func intersectStringSlicesInPlace(a, b []uniquestr.Handle) []uniquestr.Handle {
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

func (node *OrNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
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

func unionStringSlicesInPlace(a, b []uniquestr.Handle) []uniquestr.Handle {
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

func (node *AllNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return nil
}

func (node *AllNode) Evaluate(_ Labels) bool {
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

func (node *GlobalNode) LabelRestrictions() map[uniquestr.Handle]LabelRestriction {
	return nil
}

func (node *GlobalNode) Evaluate(_ Labels) bool {
	return true
}

func (node *GlobalNode) AcceptVisitor(v Visitor) {
	v.Visit(node)
}

func (node *GlobalNode) collectFragments(fragments []string) []string {
	return append(fragments, "global()")
}
