// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package cluster

import (
	"errors"
	"fmt"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	. "github.com/onsi/gomega"
)

// The two custom huh fields are driven here through their Update/Focus methods
// rather than a real terminal: everything worth pinning down (filtering,
// toggling, lazy loading, scrolling, scaffold re-seeding) is plain state
// machinery that needs no TTY.

// press sends a printable character.
func press(m huh.Model, r rune) huh.Model {
	next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	return next
}

// pressKey sends a special key (space, enter, backspace, …).
func pressKey(m huh.Model, code rune) huh.Model {
	next, _ := m.Update(tea.KeyPressMsg{Code: code})
	return next
}

// typeText sends each character of s in turn.
func typeText(m huh.Model, s string) huh.Model {
	for _, r := range s {
		m = press(m, r)
	}
	return m
}

func testNodes() []nodeInfo {
	return []nodeInfo{
		{Name: "control-1", Roles: []string{"control-plane"}, Zone: "z1", Ready: true},
		{Name: "worker-1", Roles: []string{"worker"}, Zone: "z1", Ready: true},
		{Name: "worker-2", Roles: []string{"worker"}, Zone: "z2", Ready: true},
		{Name: "worker-3", Roles: []string{"worker"}, Zone: "z2", Ready: false},
	}
}

func TestNodeMultiSelect_KeyNamesAreAsExpected(t *testing.T) {
	RegisterTestingT(t)
	// The widget dispatches on msg.String(), so the names it switches on must be
	// the ones bubbletea actually produces. If an upgrade renames any of these,
	// the rest of the tests below would silently pass through the default branch.
	Expect(tea.KeyPressMsg{Code: tea.KeySpace}.String()).To(Equal("space"))
	Expect(tea.KeyPressMsg{Code: tea.KeyEnter}.String()).To(Equal("enter"))
	Expect(tea.KeyPressMsg{Code: tea.KeyBackspace}.String()).To(Equal("backspace"))
	Expect(tea.KeyPressMsg{Code: tea.KeyEscape}.String()).To(Equal("esc"))
	Expect(tea.KeyPressMsg{Code: tea.KeyUp}.String()).To(Equal("up"))
	Expect(tea.KeyPressMsg{Code: tea.KeyEnd}.String()).To(Equal("end"))
	Expect(tea.KeyPressMsg{Code: 'w', Text: "w"}.String()).To(Equal("w"))
}

func TestNodeMultiSelect_ToggleWritesThroughToBoundValue(t *testing.T) {
	RegisterTestingT(t)
	var got []string
	m := newNodeMultiSelect().Options(nodeOptions(testNodes())...).Value(&got)

	// Space toggles the row under the cursor, which starts at the top.
	pressKey(m, tea.KeySpace)
	Expect(got).To(Equal([]string{"control-1"}))

	// Move down and select a second row.
	pressKey(m, tea.KeyDown)
	pressKey(m, tea.KeySpace)
	Expect(got).To(Equal([]string{"control-1", "worker-1"}))

	// Space again on the same row deselects it.
	pressKey(m, tea.KeySpace)
	Expect(got).To(Equal([]string{"control-1"}))
}

func TestNodeMultiSelect_SelectionOrderFollowsOptionsNotClickOrder(t *testing.T) {
	RegisterTestingT(t)
	var got []string
	m := newNodeMultiSelect().Options(nodeOptions(testNodes())...).Value(&got)

	// Select the last row first, then the first row.
	pressKey(m, tea.KeyEnd)
	pressKey(m, tea.KeySpace)
	pressKey(m, tea.KeyHome)
	pressKey(m, tea.KeySpace)

	Expect(got).To(Equal([]string{"control-1", "worker-3"}), "display order, not selection order")
}

func TestNodeMultiSelect_FilterIsCaseInsensitiveAndKeepsSelection(t *testing.T) {
	RegisterTestingT(t)
	var got []string
	ms := newNodeMultiSelect().Options(nodeOptions(testNodes())...).Value(&got)

	// Select a node that a later filter will exclude.
	pressKey(ms, tea.KeySpace)
	Expect(got).To(Equal([]string{"control-1"}))

	// Typing filters; matching is case-insensitive against the rendered label.
	typeText(ms, "WORKER-2")
	Expect(ms.filtered).To(HaveLen(1))
	Expect(ms.options[ms.filtered[0]].Value).To(Equal("worker-2"))

	// The out-of-view selection survives, and a new one joins it.
	pressKey(ms, tea.KeySpace)
	Expect(got).To(Equal([]string{"control-1", "worker-2"}))

	// Backspace narrows back out; ctrl+u clears the filter entirely.
	pressKey(ms, tea.KeyBackspace)
	Expect(ms.filter).To(Equal("WORKER-"))
	ms.Update(tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl})
	Expect(ms.filter).To(BeEmpty())
	Expect(ms.filtered).To(HaveLen(4))
	Expect(got).To(Equal([]string{"control-1", "worker-2"}), "clearing the filter keeps selections")
}

func TestNodeMultiSelect_FilterResetsCursorAndScroll(t *testing.T) {
	RegisterTestingT(t)
	ms := newNodeMultiSelect().Options(nodeOptions(testNodes())...)

	pressKey(ms, tea.KeyEnd)
	Expect(ms.cursor).To(Equal(3))

	// A filter change must not leave the cursor pointing past the new matches.
	typeText(ms, "worker")
	Expect(ms.cursor).To(BeZero())
	Expect(ms.offset).To(BeZero())
	Expect(ms.filtered).To(HaveLen(3))
}

func TestNodeMultiSelect_EscClearsFilterRatherThanAborting(t *testing.T) {
	RegisterTestingT(t)
	ms := newNodeMultiSelect().Options(nodeOptions(testNodes())...)

	typeText(ms, "worker")
	Expect(ms.filter).To(Equal("worker"))

	// Esc is consumed to clear the filter — it is not an abort key here.
	_, cmd := ms.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	Expect(ms.filter).To(BeEmpty())
	Expect(cmd).To(BeNil())
}

func TestNodeMultiSelect_ToggleIgnoresNoMatchAndDisabledRows(t *testing.T) {
	RegisterTestingT(t)
	var got []string
	ms := newNodeMultiSelect().
		Options(nodeOptions(testNodes())...).
		Disabled(func(v string) bool { return v == "control-1" }).
		Value(&got)

	// The cursor starts on the disabled row, so space is a no-op.
	pressKey(ms, tea.KeySpace)
	Expect(got).To(BeEmpty())

	// A filter that matches nothing leaves toggling and movement harmless.
	typeText(ms, "nosuchnode")
	Expect(ms.filtered).To(BeEmpty())
	pressKey(ms, tea.KeySpace)
	pressKey(ms, tea.KeyDown)
	pressKey(ms, tea.KeyEnd)
	Expect(got).To(BeEmpty())
	Expect(ms.cursor).To(BeZero())
}

func TestNodeMultiSelect_RowDisabledAfterSelectionDropsOutOfValue(t *testing.T) {
	RegisterTestingT(t)
	// Mirrors the real back-navigation case: a node is picked for comparison, then
	// promoted to a problem node, which locks its row in the comparison picker.
	problem := []string{}
	var comparison []string
	ms := newNodeMultiSelect().
		Options(nodeOptions(testNodes())...).
		Disabled(func(v string) bool {
			for _, p := range problem {
				if p == v {
					return true
				}
			}
			return false
		}).
		Value(&comparison)

	pressKey(ms, tea.KeySpace) // select control-1
	Expect(comparison).To(Equal([]string{"control-1"}))
	Expect(ms.warningText()).To(BeEmpty())

	// control-1 becomes a problem node: it must stop contributing to this field,
	// so it is neither double-counted nor returned as a comparison node.
	problem = []string{"control-1"}
	Expect(ms.selectedValues()).To(BeEmpty())
	ms.Blur()
	Expect(comparison).To(BeEmpty())
}

func TestNodeMultiSelect_EnterValidatesBeforeAdvancing(t *testing.T) {
	RegisterTestingT(t)
	var got []string
	wantErr := errors.New("select at least one node (space to toggle)")
	ms := newNodeMultiSelect().
		Options(nodeOptions(testNodes())...).
		Validate(func(s []string) error {
			if len(s) == 0 {
				return wantErr
			}
			return nil
		}).
		Value(&got)

	// Nothing selected: enter is refused and the error surfaces on the field.
	_, cmd := ms.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	Expect(cmd).To(BeNil())
	Expect(ms.Error()).To(MatchError(wantErr))

	// The next keypress clears the stale error; a valid selection then advances.
	pressKey(ms, tea.KeySpace)
	Expect(ms.Error()).To(BeNil())
	_, cmd = ms.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	Expect(cmd).NotTo(BeNil(), "enter should emit huh.NextField once valid")
}

func TestNodeMultiSelect_LazyOptionsLoadOnceOnFocus(t *testing.T) {
	RegisterTestingT(t)
	calls := 0
	ms := newNodeMultiSelect().Noun("pod").OptionsFunc(func() ([]huh.Option[string], error) {
		calls++
		return podOptions([]podInfo{
			{Namespace: "calico-system", Name: "p1", Node: "nodeA", Phase: "Running"},
		}), nil
	})

	// Options are not fetched until the field is focused — the whole point is that
	// by-node operators never pay to list every pod in the cluster.
	Expect(calls).To(BeZero())
	Expect(ms.options).To(BeEmpty())

	ms.Focus()
	Expect(calls).To(Equal(1))
	Expect(ms.options).To(HaveLen(1))

	// Re-focusing (e.g. after back-navigation) reuses the loaded list.
	ms.Blur()
	ms.Focus()
	Expect(calls).To(Equal(1))
}

func TestNodeMultiSelect_LazyOptionsErrorIsRecoverable(t *testing.T) {
	RegisterTestingT(t)
	loadErr := errors.New("connection refused")
	ms := newNodeMultiSelect().Noun("pod").OptionsFunc(func() ([]huh.Option[string], error) {
		return nil, loadErr
	})

	ms.Focus()
	Expect(ms.loadErr).To(MatchError(loadErr))
	Expect(ms.options).To(BeEmpty())
	// The failure is shown in place, telling the operator how to back out, rather
	// than killing the form.
	Expect(ms.View()).To(ContainSubstring("could not list pods"))
	Expect(ms.View()).To(ContainSubstring("shift+tab to go back"))
}

func TestNodeMultiSelect_VisibleRowsLeavesRoomForChrome(t *testing.T) {
	RegisterTestingT(t)
	ms := newNodeMultiSelect().Options(nodeOptions(testNodes())...).Height(20)

	// title + filter + card borders + a one-line footer.
	Expect(ms.visibleRows()).To(Equal(20 - 2 - 2 - 1))

	// A warning takes a second footer line, costing one option row.
	ms.Warning(func(int) string { return "over budget" })
	Expect(ms.visibleRows()).To(Equal(20 - 2 - 2 - 2))

	// Absurdly small heights still leave one row to render.
	Expect(newNodeMultiSelect().Height(1).visibleRows()).To(Equal(1))
}

func TestNodeMultiSelect_ScrollFollowsCursor(t *testing.T) {
	RegisterTestingT(t)
	var many []nodeInfo
	for i := 0; i < 100; i++ {
		many = append(many, nodeInfo{Name: fmt.Sprintf("node-%03d", i), Ready: true})
	}
	ms := newNodeMultiSelect().Options(nodeOptions(many)...).Height(12)
	rows := ms.visibleRows()

	// Scrolling past the bottom of the window drags the viewport along.
	for i := 0; i < rows+3; i++ {
		pressKey(ms, tea.KeyDown)
	}
	ms.View() // scrolling is settled at render time, when the geometry is known
	Expect(ms.cursor).To(Equal(rows + 3))
	Expect(ms.offset).To(Equal(ms.cursor - rows + 1))

	// Coming back up drags it the other way.
	pressKey(ms, tea.KeyHome)
	ms.View()
	Expect(ms.cursor).To(BeZero())
	Expect(ms.offset).To(BeZero())

	// End jumps to the last row and the window contains it.
	pressKey(ms, tea.KeyEnd)
	ms.View()
	Expect(ms.cursor).To(Equal(99))
	Expect(ms.offset).To(BeNumerically("<=", 99))
	Expect(ms.offset + rows).To(BeNumerically(">", 99))
}

func TestSeededTextArea_SeedsOnFirstFocus(t *testing.T) {
	RegisterTestingT(t)
	var got string
	selected := []string{"worker-1", "worker-2"}
	ta := newSeededTextArea().
		SeedFunc(func() string { return roleScaffold(false, nil, selected) }).
		Value(&got)

	// Nothing is seeded until the field is focused, so the scaffold can reflect
	// choices made later in the form.
	Expect(got).To(BeEmpty())

	ta.Focus()
	Expect(got).To(ContainSubstring("Node worker-1: "))
	Expect(got).To(ContainSubstring("Node worker-2: "))
	Expect(got).To(ContainSubstring(externalEndpointsPrompt))
}

func TestSeededTextArea_UntouchedScaffoldRefreshesOnRevisit(t *testing.T) {
	RegisterTestingT(t)
	var got string
	selected := []string{"worker-1"}
	ta := newSeededTextArea().
		SeedFunc(func() string { return roleScaffold(false, nil, selected) }).
		Value(&got)

	ta.Focus()
	Expect(got).To(ContainSubstring("Node worker-1: "))
	ta.Blur()

	// The operator steps back and changes the node selection. Because the box was
	// left untouched, the scaffold must follow the new selection.
	selected = []string{"worker-9"}
	ta.Focus()
	Expect(got).To(ContainSubstring("Node worker-9: "))
	Expect(got).NotTo(ContainSubstring("Node worker-1: "))
}

func TestSeededTextArea_TypedTextSurvivesRevisit(t *testing.T) {
	RegisterTestingT(t)
	var got string
	selected := []string{"worker-1"}
	ta := newSeededTextArea().
		SeedFunc(func() string { return roleScaffold(false, nil, selected) }).
		Value(&got)

	ta.Focus()
	typeText(ta, "BGP flapping")
	Expect(got).To(ContainSubstring("Node worker-1: BGP flapping"))
	ta.Blur()

	// A changed selection must not clobber what the operator wrote.
	selected = []string{"worker-9"}
	ta.Focus()
	Expect(got).To(ContainSubstring("BGP flapping"))
	Expect(got).NotTo(ContainSubstring("Node worker-9: "))
}

func TestSeededTextArea_PreexistingValueIsNotClobbered(t *testing.T) {
	RegisterTestingT(t)
	// Both wizard paths bind the same value, so the by-node field must not wipe
	// what the by-pod field already collected.
	got := "Pod ns/frontend: source, can't reach the database"
	ta := newSeededTextArea().
		SeedFunc(func() string { return roleScaffold(false, nil, []string{"worker-1"}) }).
		Value(&got)

	ta.Focus()
	Expect(got).To(Equal("Pod ns/frontend: source, can't reach the database"))
}

func TestSeededTextArea_TabMovesToContinueButtonThenAdvances(t *testing.T) {
	RegisterTestingT(t)
	var got string
	ta := newSeededTextArea().
		SeedFunc(func() string { return roleScaffold(false, nil, []string{"worker-1"}) }).
		Value(&got)
	ta.Focus()

	// Tab does not insert a tab character: it hands focus to the Continue button.
	before := got
	pressKey(ta, tea.KeyTab)
	Expect(ta.buttonFocused).To(BeTrue())
	Expect(got).To(Equal(before))

	// Up returns to editing; tab goes back to the button; enter then advances.
	pressKey(ta, tea.KeyUp)
	Expect(ta.buttonFocused).To(BeFalse())
	pressKey(ta, tea.KeyTab)
	_, cmd := ta.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	Expect(cmd).NotTo(BeNil(), "enter on the button should emit huh.NextField")
}

func TestSeededTextArea_EnterInsertsNewlineWhileEditing(t *testing.T) {
	RegisterTestingT(t)
	var got string
	ta := newSeededTextArea().Value(&got)
	ta.Focus()

	typeText(ta, "one")
	pressKey(ta, tea.KeyEnter)
	typeText(ta, "two")
	Expect(got).To(Equal("one\ntwo"), "enter is a newline, not a submit, while editing")
}
