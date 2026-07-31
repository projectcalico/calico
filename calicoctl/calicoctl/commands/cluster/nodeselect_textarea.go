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
	"io"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// seededTextArea is a custom huh.Field wrapping a bubbles textarea. Unlike huh's
// built-in Text field — whose value is seeded only once, at build time — this one
// can seed its content lazily the first time it is focused, via SeedFunc. That
// lets the wizard pre-populate the per-resource role lines from the node/pod
// selection while keeping everything in a single, back-navigable form.
//
// Editing keys go to the textarea (Enter inserts a newline); tab moves down to a
// Continue button, which is the way on, and shift+tab steps back to the previous
// field as it does in the other custom field.
type seededTextArea struct {
	key   string
	title string
	desc  string

	area  textarea.Model
	value *string

	// seedFunc supplies the initial content lazily on first focus. lastSeed is
	// the text it last produced, so a revisit can refresh the scaffold when the
	// box is still untouched without clobbering anything the operator has typed.
	seedFunc func() string
	lastSeed string
	seeded   bool

	// focused is whether the whole field has focus; buttonFocused is whether the
	// "Continue" button (rather than the textarea) is the active element within it.
	focused       bool
	buttonFocused bool
	width         int
	height        int
	theme         huh.Theme
	hasDarkBg     bool
}

// newSeededTextArea returns a textarea field; configure it with the builders.
func newSeededTextArea() *seededTextArea {
	ta := textarea.New()
	ta.ShowLineNumbers = false
	ta.Prompt = ""
	ta.CharLimit = 0
	m := &seededTextArea{area: ta, height: 8}
	ta.SetHeight(m.height)
	return m
}

func (m *seededTextArea) Title(t string) *seededTextArea           { m.title = t; return m }
func (m *seededTextArea) Description(d string) *seededTextArea     { m.desc = d; return m }
func (m *seededTextArea) Key(k string) *seededTextArea             { m.key = k; return m }
func (m *seededTextArea) SeedFunc(f func() string) *seededTextArea { m.seedFunc = f; return m }

func (m *seededTextArea) Value(p *string) *seededTextArea {
	m.value = p
	if p != nil && *p != "" {
		m.area.SetValue(*p)
		m.seeded = true
	}
	return m
}

// --- value plumbing ---

func (m *seededTextArea) writeValue() {
	if m.value != nil {
		*m.value = m.area.Value()
	}
}

// --- huh.Field / huh.Model implementation ---

// textAreaKeys are this field's keybindings, published through KeyBinds so the
// help renders in the group footer like the built-in fields'. They are the
// field's own rather than huh's Text keymap (so WithKeyMap is ignored) because
// this field puts a Continue button below the box: Enter inserts a newline as
// huh's Text does, but tab moves to the button rather than leaving the field.
var textAreaKeys = struct {
	newLine, toButton, prev key.Binding
	continueBtn, backToEdit key.Binding
}{
	newLine:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "new line")),
	toButton:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "→ Continue")),
	prev:        key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "back")),
	continueBtn: key.NewBinding(key.WithKeys("enter", "space", "tab"), key.WithHelp("enter", "continue")),
	backToEdit:  key.NewBinding(key.WithKeys("shift+tab", "up"), key.WithHelp("shift+tab/↑", "back to editing")),
}

// KeyBinds reports the keys for whichever element is active, so the footer help
// changes with the focus like the inline hints used to.
func (m *seededTextArea) KeyBinds() []key.Binding {
	if m.buttonFocused {
		return []key.Binding{textAreaKeys.continueBtn, textAreaKeys.backToEdit}
	}
	return []key.Binding{textAreaKeys.newLine, textAreaKeys.toButton, textAreaKeys.prev}
}

func (m *seededTextArea) Init() tea.Cmd { return nil }

func (m *seededTextArea) Update(msg tea.Msg) (huh.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.hasDarkBg = msg.IsDark()
		var cmd tea.Cmd
		m.area, cmd = m.area.Update(msg)
		return m, cmd
	case tea.KeyPressMsg:
		// While the Continue button is focused, the textarea is inert: Enter/Tab
		// advance, shift+tab/Up return to editing, everything else is ignored.
		if m.buttonFocused {
			switch {
			case key.Matches(msg, textAreaKeys.continueBtn):
				m.writeValue()
				return m, huh.NextField
			case key.Matches(msg, textAreaKeys.backToEdit):
				m.buttonFocused = false
				return m, m.area.Focus()
			}
			return m, nil
		}
		// Editing the textarea. Tab steps down to the Continue button (rather than
		// inserting a tab); shift+tab leaves the field; Enter inserts a newline.
		switch {
		case key.Matches(msg, textAreaKeys.toButton):
			m.writeValue()
			m.buttonFocused = true
			m.area.Blur()
			return m, nil
		case key.Matches(msg, textAreaKeys.prev):
			m.writeValue()
			return m, huh.PrevField
		}
	}
	var cmd tea.Cmd
	m.area, cmd = m.area.Update(msg)
	m.writeValue()
	return m, cmd
}

func (m *seededTextArea) View() string {
	st := m.activeStyles()
	m.themeTextArea(st)
	var b strings.Builder
	b.WriteString(st.Title.Render(m.title))
	b.WriteByte('\n')
	if m.desc != "" {
		b.WriteString(st.Description.Render(m.desc))
		b.WriteByte('\n')
	}
	// An inner box around just the textarea (inside the field's card border) so the
	// editable area is clearly distinct from the title, button and help text.
	// Orange while the textarea is the active element, grey otherwise.
	boxColor := lipgloss.Color("240")
	if m.focused && !m.buttonFocused {
		boxColor = tigeraOrange
	}
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(boxColor)
	b.WriteString(box.Render(m.area.View()))
	b.WriteString("\n\n")

	// Continue button — the obvious way out of the textarea. Highlighted when it,
	// rather than the textarea, holds focus.
	btnStyle := st.BlurredButton
	if m.buttonFocused {
		btnStyle = st.FocusedButton
	}
	button := btnStyle.Render(" Continue ")
	if m.width > 0 {
		inner := m.width
		if f := st.Base.GetHorizontalFrameSize(); m.width > f {
			inner = m.width - f
		}
		button = lipgloss.NewStyle().Width(inner).Align(lipgloss.Center).Render(button)
	}
	b.WriteString(button)
	return st.Base.Width(m.width).Render(b.String())
}

// themeTextArea maps the huh theme onto the bubbles textarea, which otherwise
// renders in bubbles' own palette while the rest of the card is themed. Mirrors
// huh's built-in Text field, except for the cursor: huh reads the cursor colour
// from the theme's background, which none of the shipped themes set — the
// foreground is where the colour is (as huh's Input field reads it).
func (m *seededTextArea) themeTextArea(st *huh.FieldStyles) {
	styles := m.area.Styles()
	state := &styles.Blurred
	if m.focused && !m.buttonFocused {
		state = &styles.Focused
	}
	state.Text = st.TextInput.Text
	state.Placeholder = st.TextInput.Placeholder
	state.Prompt = st.TextInput.Prompt
	state.CursorLine = st.TextInput.Text
	styles.Cursor.Color = st.TextInput.Cursor.GetForeground()
	m.area.SetStyles(styles)
}

func (m *seededTextArea) activeStyles() *huh.FieldStyles {
	theme := m.theme
	if theme == nil {
		theme = huh.ThemeFunc(huh.ThemeCharm)
	}
	s := theme.Theme(m.hasDarkBg)
	if m.focused {
		return &s.Focused
	}
	return &s.Blurred
}

func (m *seededTextArea) Focus() tea.Cmd {
	m.focused = true
	m.buttonFocused = false
	if m.seedFunc != nil {
		fresh := m.seedFunc()
		// Seed on first focus; on a revisit, only refresh if the operator hasn't
		// touched the scaffold (so changing the selection updates the lines but
		// typed roles are preserved).
		if !m.seeded || m.area.Value() == m.lastSeed {
			m.area.SetValue(fresh)
			m.lastSeed = fresh
			m.seeded = true
			lines := strings.Count(fresh, "\n") + 1
			m.area.SetHeight(clampInt(lines+1, 6, 16))
			// Land the cursor at the end of the first line — just past the
			// "Pod ns/name: " / "Node name: " prefix — so the operator types their
			// first answer without having to navigate up from the trailer.
			m.area.MoveToBegin()
			m.area.CursorEnd()
			m.writeValue()
		}
	}
	return m.area.Focus()
}

func (m *seededTextArea) Blur() tea.Cmd {
	m.focused = false
	m.writeValue()
	m.area.Blur()
	return nil
}

// Error is always nil: any answer here is a valid one, including none at all —
// the box asks how each node or pod is involved, and pressing for an answer would
// add friction to a form the operator is filling in mid-incident.
func (m *seededTextArea) Error() error { return nil }
func (m *seededTextArea) Skip() bool   { return false }
func (m *seededTextArea) Zoom() bool   { return false }

func (m *seededTextArea) Run() error { return huh.NewForm(huh.NewGroup(m)).Run() }

func (m *seededTextArea) RunAccessible(w io.Writer, _ io.Reader) error {
	return refuseAccessible(w, m.title)
}

func (m *seededTextArea) WithTheme(theme huh.Theme) huh.Field {
	if m.theme == nil {
		m.theme = theme
	}
	return m
}

// WithKeyMap is a no-op: this field binds its own keys (see textAreaKeys).
func (m *seededTextArea) WithKeyMap(*huh.KeyMap) huh.Field { return m }

func (m *seededTextArea) WithWidth(width int) huh.Field {
	m.width = width
	// Leave room for the themed card frame (border + horizontal padding = 4) and
	// the textarea's own inner border box (2).
	if width > 8 {
		m.area.SetWidth(width - 6)
	}
	return m
}

func (m *seededTextArea) WithHeight(int) huh.Field { return m }

// WithPosition is a no-op. huh's built-in fields use the position to relabel
// their exit key "submit" on the form's last field; the wizard always ends with
// the confirmation step, so neither custom field is ever last.
func (m *seededTextArea) WithPosition(huh.FieldPosition) huh.Field { return m }

func (m *seededTextArea) GetKey() string { return m.key }
func (m *seededTextArea) GetValue() any  { return m.area.Value() }
