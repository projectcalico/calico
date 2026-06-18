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
// Editing keys go to the textarea (Enter inserts a newline); tab advances to the
// next field and shift+tab steps back, mirroring the other custom field.
type seededTextArea struct {
	id    int
	key   string
	title string
	desc  string

	area     textarea.Model
	value    *string
	validate func(string) error

	// seedFunc supplies the initial content lazily on first focus. lastSeed is
	// the text it last produced, so a revisit can refresh the scaffold when the
	// box is still untouched without clobbering anything the operator has typed.
	seedFunc func() string
	lastSeed string
	seeded   bool

	err error
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

func (m *seededTextArea) Validate(f func(string) error) *seededTextArea {
	m.validate = f
	return m
}

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

func (m *seededTextArea) validateValue() error {
	if m.validate == nil {
		return nil
	}
	return m.validate(m.area.Value())
}

// --- huh.Field / huh.Model implementation ---

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
			switch msg.String() {
			case "enter", "space", "tab":
				return m, m.advance()
			case "shift+tab", "up":
				m.buttonFocused = false
				return m, m.area.Focus()
			}
			return m, nil
		}
		// Editing the textarea. Tab steps down to the Continue button (rather than
		// inserting a tab); shift+tab leaves the field; Enter inserts a newline.
		switch msg.String() {
		case "tab":
			m.writeValue()
			m.buttonFocused = true
			m.area.Blur()
			return m, nil
		case "shift+tab":
			m.writeValue()
			return m, huh.PrevField
		}
		m.err = nil
	}
	var cmd tea.Cmd
	m.area, cmd = m.area.Update(msg)
	m.writeValue()
	return m, cmd
}

// advance validates and moves to the next field, or — if validation fails —
// drops focus back into the textarea so the operator can fix it.
func (m *seededTextArea) advance() tea.Cmd {
	m.writeValue()
	if err := m.validateValue(); err != nil {
		m.err = err
		m.buttonFocused = false
		return m.area.Focus()
	}
	return huh.NextField
}

func (m *seededTextArea) View() string {
	st := m.activeStyles()
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
	b.WriteByte('\n')

	switch {
	case m.err != nil:
		b.WriteString(st.ErrorMessage.Render(m.err.Error()))
	case m.buttonFocused:
		b.WriteString(st.Description.Render("enter continue · shift+tab / ↑ back to editing"))
	default:
		b.WriteString(st.Description.Render("enter new line · tab → Continue · shift+tab back"))
	}
	return st.Base.Width(m.width).Render(b.String())
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
			m.area.MoveToEnd()
			m.writeValue()
		}
	}
	return m.area.Focus()
}

func (m *seededTextArea) Blur() tea.Cmd {
	m.focused = false
	m.writeValue()
	m.err = m.validateValue()
	m.area.Blur()
	return nil
}

func (m *seededTextArea) Error() error { return m.err }
func (m *seededTextArea) Skip() bool   { return false }
func (m *seededTextArea) Zoom() bool   { return false }

func (m *seededTextArea) KeyBinds() []key.Binding { return nil }

func (m *seededTextArea) Run() error { return huh.NewForm(huh.NewGroup(m)).Run() }

func (m *seededTextArea) RunAccessible(w io.Writer, _ io.Reader) error {
	_, _ = io.WriteString(w, m.title+"\n")
	return nil
}

func (m *seededTextArea) WithTheme(theme huh.Theme) huh.Field {
	if m.theme == nil {
		m.theme = theme
	}
	return m
}

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

func (m *seededTextArea) WithPosition(huh.FieldPosition) huh.Field { return m }

func (m *seededTextArea) GetKey() string { return m.key }
func (m *seededTextArea) GetValue() any  { return m.area.Value() }
