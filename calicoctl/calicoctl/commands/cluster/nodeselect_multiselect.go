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
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// nodeMultiSelect is a custom huh.Field: a filterable, checkbox multi-select
// that, unlike huh's built-in MultiSelect, is virtualized — it only renders the
// rows visible in the viewport, so it stays responsive with thousands of nodes.
//
// It also fixes two ergonomics problems of the built-in widget for this use
// case: the filter box is always visible (type to filter, no "/" mode), and
// because spaces can't appear in node names, space always toggles the current
// row rather than being captured by the filter.
//
// It plugs into the same huh.Form as the other steps, so back-navigation
// (shift+tab), theming and the confirmation step all still work.
type nodeMultiSelect struct {
	id    int
	key   string
	title string

	options   []huh.Option[string] // Value = item name, Key = display label
	lowerKeys []string             // pre-lowered labels for fast filtering
	value     *[]string            // bound external value (live)

	// noun names the items for help/empty text ("node", "pod", …). Defaults to
	// "node".
	noun string

	// optionsFunc, when set, lazily supplies the options the first time the field
	// is focused. Used for the pod picker so by-node operators never pay to list
	// every pod in the cluster.
	optionsFunc   func() ([]huh.Option[string], error)
	optionsLoaded bool
	loadErr       error

	// Optional over-budget warning, given the current selection count.
	warning  func(selected int) string
	validate func([]string) error

	// Optional: reports whether an option value is non-selectable. Disabled
	// rows are rendered greyed out and space does not toggle them (used to lock
	// out nodes already chosen as problem nodes).
	disabled func(value string) bool

	// Runtime state.
	filter   string
	filtered []int           // indices into options matching the filter
	cursor   int             // index into filtered
	offset   int             // first visible index into filtered
	selected map[string]bool // by node name
	err      error

	focused   bool
	height    int
	width     int
	theme     huh.Theme
	hasDarkBg bool
}

// newNodeMultiSelect returns an empty picker; configure it with the builder
// methods below.
func newNodeMultiSelect() *nodeMultiSelect {
	return &nodeMultiSelect{selected: map[string]bool{}}
}

func (m *nodeMultiSelect) Title(t string) *nodeMultiSelect { m.title = t; return m }

func (m *nodeMultiSelect) Options(opts ...huh.Option[string]) *nodeMultiSelect {
	m.setOptions(opts)
	return m
}

// setOptions stores the options, pre-lowers their labels for filtering and
// recomputes the filtered view. Shared by the eager Options builder and the
// lazy optionsFunc path.
func (m *nodeMultiSelect) setOptions(opts []huh.Option[string]) {
	m.options = opts
	m.lowerKeys = make([]string, len(opts))
	for i, o := range opts {
		m.lowerKeys[i] = strings.ToLower(o.Key)
	}
	m.applyFilter()
}

// OptionsFunc registers a loader that supplies the options lazily, the first
// time the field is focused. Mutually exclusive with Options in practice.
func (m *nodeMultiSelect) OptionsFunc(f func() ([]huh.Option[string], error)) *nodeMultiSelect {
	m.optionsFunc = f
	return m
}

// loadOptions runs the lazy options loader once, the first time the field gains
// focus. On error it records loadErr (rendered in View) and leaves the option
// list empty so the operator can step back rather than being stuck.
func (m *nodeMultiSelect) loadOptions() {
	if m.optionsFunc == nil || m.optionsLoaded {
		return
	}
	m.optionsLoaded = true
	opts, err := m.optionsFunc()
	if err != nil {
		m.loadErr = err
		return
	}
	m.setOptions(opts)
	// Size to the freshly loaded list (the count wasn't known at build time).
	m.height = pickerHeight(len(opts))
}

// Noun sets the item noun used in help and empty-state text. Defaults to "node".
func (m *nodeMultiSelect) Noun(n string) *nodeMultiSelect { m.noun = n; return m }

func (m *nodeMultiSelect) itemNoun() string {
	if m.noun == "" {
		return "node"
	}
	return m.noun
}

func (m *nodeMultiSelect) Value(p *[]string) *nodeMultiSelect {
	m.value = p
	if p != nil {
		for _, v := range *p {
			m.selected[v] = true
		}
	}
	return m
}

func (m *nodeMultiSelect) Warning(f func(selected int) string) *nodeMultiSelect {
	m.warning = f
	return m
}

func (m *nodeMultiSelect) Validate(f func([]string) error) *nodeMultiSelect { m.validate = f; return m }

func (m *nodeMultiSelect) Disabled(f func(value string) bool) *nodeMultiSelect {
	m.disabled = f
	return m
}

func (m *nodeMultiSelect) isDisabled(value string) bool {
	return m.disabled != nil && m.disabled(value)
}

func (m *nodeMultiSelect) Height(h int) *nodeMultiSelect { m.height = h; return m }

func (m *nodeMultiSelect) Key(k string) *nodeMultiSelect { m.key = k; return m }

// --- selection helpers ---

// selectedValues returns the selected node names in option (display) order.
func (m *nodeMultiSelect) selectedValues() []string {
	if len(m.selected) == 0 {
		return nil
	}
	out := make([]string, 0, len(m.selected))
	for _, o := range m.options {
		if m.selected[o.Value] {
			out = append(out, o.Value)
		}
	}
	return out
}

func (m *nodeMultiSelect) writeValue() {
	if m.value != nil {
		*m.value = m.selectedValues()
	}
}

func (m *nodeMultiSelect) toggleCurrent() {
	if len(m.filtered) == 0 {
		return
	}
	v := m.options[m.filtered[m.cursor]].Value
	if m.isDisabled(v) {
		return
	}
	if m.selected[v] {
		delete(m.selected, v)
	} else {
		m.selected[v] = true
	}
	m.writeValue()
}

func (m *nodeMultiSelect) move(d int) {
	if len(m.filtered) == 0 {
		return
	}
	m.cursor = clampInt(m.cursor+d, 0, len(m.filtered)-1)
}

// applyFilter recomputes the filtered index set against the current filter text
// and resets the cursor to the top of the matches.
func (m *nodeMultiSelect) applyFilter() {
	m.filtered = m.filtered[:0]
	if m.filter == "" {
		for i := range m.options {
			m.filtered = append(m.filtered, i)
		}
	} else {
		f := strings.ToLower(m.filter)
		for i, lk := range m.lowerKeys {
			if strings.Contains(lk, f) {
				m.filtered = append(m.filtered, i)
			}
		}
	}
	m.cursor = 0
	m.offset = 0
}

// --- huh.Field / huh.Model implementation ---

func (m *nodeMultiSelect) Init() tea.Cmd { return nil }

func (m *nodeMultiSelect) Update(msg tea.Msg) (huh.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.hasDarkBg = msg.IsDark()
	case tea.KeyPressMsg:
		m.err = nil
		switch msg.String() {
		case "up", "ctrl+p":
			m.move(-1)
		case "down", "ctrl+n":
			m.move(1)
		case "pgup":
			m.move(-m.visibleRows())
		case "pgdown":
			m.move(m.visibleRows())
		case "home":
			m.cursor = 0
		case "end":
			m.cursor = len(m.filtered) - 1
		case "space":
			m.toggleCurrent()
		case "enter", "tab":
			if m.validate != nil {
				if err := m.validate(m.selectedValues()); err != nil {
					m.err = err
					return m, nil
				}
			}
			m.writeValue()
			return m, huh.NextField
		case "shift+tab":
			m.writeValue()
			return m, huh.PrevField
		case "esc":
			if m.filter != "" {
				m.filter = ""
				m.applyFilter()
			}
		case "ctrl+u":
			m.filter = ""
			m.applyFilter()
		case "backspace":
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
				m.applyFilter()
			}
		default:
			// Any other printable input extends the filter. Space is handled
			// above (toggle), so it never lands here.
			if msg.Text != "" {
				m.filter += msg.Text
				m.applyFilter()
			}
		}
	}
	return m, nil
}

func (m *nodeMultiSelect) View() string {
	st := m.activeStyles()
	rows := m.visibleRows()

	// Keep the cursor within the visible window.
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}

	var b strings.Builder
	b.WriteString(st.Title.Render(m.title))
	b.WriteByte('\n')

	// Always-visible filter line.
	filterView := m.filter
	if filterView == "" {
		filterView = st.TextInput.Placeholder.Render("type to filter")
	}
	b.WriteString(st.TextInput.Prompt.Render("Filter: ") + filterView)
	b.WriteByte('\n')

	// Virtualized option rows.
	end := minInt(m.offset+rows, len(m.filtered))
	if len(m.filtered) == 0 {
		empty := fmt.Sprintf("  (no %ss match the filter)", m.itemNoun())
		if m.loadErr != nil {
			empty = fmt.Sprintf("  (could not list %ss: %v — shift+tab to go back)", m.itemNoun(), m.loadErr)
		}
		b.WriteString(st.Description.Render(empty))
		b.WriteByte('\n')
		for i := 1; i < rows; i++ {
			b.WriteByte('\n')
		}
	} else {
		for i := m.offset; i < end; i++ {
			o := m.options[m.filtered[i]]
			b.WriteString(m.renderRow(o, i == m.cursor, m.selected[o.Value], m.isDisabled(o.Value), st))
			b.WriteByte('\n')
		}
		for i := end - m.offset; i < rows; i++ {
			b.WriteByte('\n')
		}
	}

	b.WriteString(st.Description.Render(m.statusText()))
	if w := m.warningText(); w != "" {
		b.WriteByte('\n')
		b.WriteString(warningStyle.Render(w))
	}
	return st.Base.Width(m.width).Render(b.String())
}

// warningStyle makes the over-budget warning prominent — bold Tigera orange —
// rather than blending into the muted help text.
var warningStyle = lipgloss.NewStyle().Foreground(tigeraOrange).Bold(true)

func (m *nodeMultiSelect) renderRow(o huh.Option[string], cursor, selected, disabled bool, st *huh.FieldStyles) string {
	var b strings.Builder
	if cursor {
		b.WriteString(st.MultiSelectSelector.String())
	} else {
		b.WriteString(strings.Repeat(" ", lipgloss.Width(st.MultiSelectSelector.String())))
	}
	switch {
	case disabled:
		b.WriteString(disabledRowStyle.Render("[–] " + o.Key + "  (problem " + m.itemNoun() + ")"))
	case selected:
		b.WriteString(st.SelectedPrefix.String())
		b.WriteString(st.SelectedOption.Render(o.Key))
	default:
		b.WriteString(st.UnselectedPrefix.String())
		b.WriteString(st.UnselectedOption.Render(o.Key))
	}
	return b.String()
}

// disabledRowStyle greys out non-selectable rows (e.g. nodes already chosen as
// problem nodes) so they read as locked rather than pickable.
var disabledRowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

// statusText is the muted position/help line under the options.
func (m *nodeMultiSelect) statusText() string {
	total := len(m.filtered)
	start, fin := 0, 0
	if total > 0 {
		start = m.offset + 1
		fin = minInt(m.offset+m.visibleRows(), total)
	}
	return fmt.Sprintf("%d–%d of %d · %d selected · space select · enter confirm · shift+tab back · type to filter",
		start, fin, total, len(m.selected))
}

// warningText is the over-budget warning, or "" when within budget.
func (m *nodeMultiSelect) warningText() string {
	if m.warning == nil {
		return ""
	}
	return m.warning(len(m.selected))
}

// visibleRows is the number of option rows that fit, leaving room for the title,
// the filter line, the footer (one line, or two when a warning is shown), and the
// themed card's top and bottom border.
func (m *nodeMultiSelect) visibleRows() int {
	h := m.height
	if h <= 0 {
		h = 15
	}
	footer := 1
	if m.warningText() != "" {
		footer = 2
	}
	const titleAndFilter, cardBorder = 2, 2
	return maxInt(1, h-titleAndFilter-cardBorder-footer)
}

func (m *nodeMultiSelect) activeStyles() *huh.FieldStyles {
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

func (m *nodeMultiSelect) Focus() tea.Cmd { m.focused = true; m.loadOptions(); return nil }
func (m *nodeMultiSelect) Blur() tea.Cmd  { m.focused = false; m.writeValue(); return nil }
func (m *nodeMultiSelect) Error() error   { return m.err }
func (m *nodeMultiSelect) Skip() bool     { return false }
func (m *nodeMultiSelect) Zoom() bool     { return false }

func (m *nodeMultiSelect) KeyBinds() []key.Binding { return nil }

func (m *nodeMultiSelect) Run() error { return huh.NewForm(huh.NewGroup(m)).Run() }

func (m *nodeMultiSelect) RunAccessible(w io.Writer, _ io.Reader) error {
	_, _ = io.WriteString(w, m.title+"\n")
	return nil
}

func (m *nodeMultiSelect) WithTheme(theme huh.Theme) huh.Field {
	if m.theme == nil {
		m.theme = theme
	}
	return m
}

func (m *nodeMultiSelect) WithKeyMap(*huh.KeyMap) huh.Field { return m }

func (m *nodeMultiSelect) WithWidth(width int) huh.Field { m.width = width; return m }

func (m *nodeMultiSelect) WithHeight(height int) huh.Field {
	if height > 0 {
		m.height = height
	}
	return m
}

func (m *nodeMultiSelect) WithPosition(huh.FieldPosition) huh.Field { return m }

func (m *nodeMultiSelect) GetKey() string { return m.key }
func (m *nodeMultiSelect) GetValue() any  { return m.selectedValues() }

// --- small numeric helpers (kept local to avoid name clashes) ---

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
