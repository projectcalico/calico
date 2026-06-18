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
	"os"
	"sort"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// defaultComparisonNodeCount is how many healthy nodes the picker suggests for
// contrast by default.
const defaultComparisonNodeCount = 2

// stdinIsInteractive reports whether we should drive the interactive picker:
// both stdin and stdout must be a real terminal. This is the gate that keeps CI,
// pipes and redirected runs on the unchanged flag-driven path.
func stdinIsInteractive() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

// Comparison-node choices on the by-node comparison step.
const (
	cmpAccept = "accept"
	cmpEdit   = "edit"
	cmpNone   = "none"
)

// Comparison-pod choices on the by-pod comparison step.
const (
	cmpPodsYes = "yes"
	cmpPodsNo  = "no"
)

// runInteractiveSelection walks the operator through a single, back-navigable
// form: how to identify the problem, which nodes (or pods), whether to include
// comparison nodes, and a final confirmation. shift+tab steps back through the
// groups. Groups that don't apply to the chosen path are hidden. It returns the
// selection with proceed=true only if the operator confirmed; aborting
// (Ctrl-C / Esc) returns proceed=false with a nil error.
//
// The node list is gathered up front; pods (for the by-pod path) are listed
// lazily so by-node users never pay for them, and the pod→node resolution
// happens once after the form is submitted.
func runInteractiveSelection(kubeClient kubernetes.Interface) (selection, bool, error) {
	listCtx, cancel := shortContext()
	nodes, err := gatherNodeInfo(listCtx, kubeClient)
	cancel()
	if err != nil {
		return selection{}, false, fmt.Errorf("listing cluster nodes: %w", err)
	}
	if len(nodes) == 0 {
		return selection{}, false, errors.New("no nodes found in cluster")
	}
	sortNodeInfos(nodes)

	const (
		byNode = "node"
		byPod  = "pod"
	)

	// Form-bound state.
	method := byPod
	var problemNodeSel []string
	var problemPodSel []string
	comparisonChoice := cmpAccept // by-node path
	cmpPodChoice := cmpPodsYes    // by-pod path
	var comparisonSel []string    // by-node manual comparison nodes
	var comparisonPodSel []string // by-pod manual comparison pods
	var problemStarted string     // "when did it start?" answer
	var problemDetails string     // per-resource role description
	confirm := true

	// podNodeByRef maps each pod's "namespace/name" ref to the node hosting it,
	// populated when the by-pod picker lazily lists pods. This lets the comparison
	// step resolve the selected pods to nodes live — no extra API call — so the
	// locking and warnings work on the by-pod path too. The option list is cached
	// alongside it so the problem-pod and comparison-pod pickers share one lookup.
	podNodeByRef := map[string]string{}
	var podOpts []huh.Option[string]
	podsLoaded := false
	loadPodOptions := func() ([]huh.Option[string], error) {
		if podsLoaded {
			return podOpts, nil
		}
		ctx, c := shortContext()
		defer c()
		pods, err := gatherPodInfo(ctx, kubeClient)
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			podNodeByRef[p.Ref()] = p.Node
		}
		podOpts = podOptions(pods)
		podsLoaded = true
		return podOpts, nil
	}

	// currentProblemNames is the problem-node set known without a fresh K8s
	// round-trip: the live multi-select value on the by-node path, or — on the
	// by-pod path — the selected pods mapped through podNodeByRef.
	currentProblemNames := func() []string {
		if method == byNode {
			return problemNodeSel
		}
		return nodesForPods(problemPodSel, podNodeByRef)
	}

	// currentComparison resolves the comparison nodes for the active path against
	// the given problem nodes: the node-path choice (suggested/manual/none), or —
	// on the by-pod path — the nodes hosting the chosen comparison pods.
	currentComparison := func(problem []string) []string {
		if method == byPod {
			if cmpPodChoice != cmpPodsYes {
				return nil
			}
			return comparisonNodesFromPods(comparisonPodSel, podNodeByRef, problem)
		}
		return resolveComparison(nodes, problem, comparisonChoice, comparisonSel)
	}

	form := huh.NewForm(
		// 1. How to identify the problem.
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Does the problem affect particular pods?").
				Options(
					huh.NewOption("Yes — choose the involved pods from a list", byPod),
					huh.NewOption("No — choose a subset of nodes to collect from", byNode),
				).
				Value(&method),
		),

		// 2a. Problem nodes — by-node path. Custom virtualized picker so it
		// stays responsive with thousands of nodes.
		huh.NewGroup(
			newNodeMultiSelect().
				Title("Select the problem nodes").
				Options(nodeOptions(nodes)...).
				Height(pickerHeight(len(nodes))).
				Warning(overBudgetWarning).
				Validate(func(s []string) error {
					if len(s) == 0 {
						return errors.New("select at least one node (space to toggle)")
					}
					return nil
				}).
				Value(&problemNodeSel),
		).WithHideFunc(func() bool { return method != byNode }),

		// 2b. Problem pods — by-pod path. Same virtualized picker as the node
		// path; options are listed lazily the first time it's focused. We resolve
		// the chosen pods to their nodes after the form.
		huh.NewGroup(
			newNodeMultiSelect().
				Title("Select the pods that are having trouble").
				Noun("pod").
				OptionsFunc(loadPodOptions).
				Validate(func(s []string) error {
					if len(s) == 0 {
						return errors.New("select at least one pod (space to toggle)")
					}
					return nil
				}).
				Value(&problemPodSel),
		).WithHideFunc(func() bool { return method != byPod }),

		// 3. Comparison nodes — by-node path. Framed as a mini-confirmation: recap
		// the problem nodes just chosen, then explain the suggested comparison nodes
		// are *additional*, healthy nodes — so the suggestions don't read as a
		// non-sequitur ("why are you suggesting P and Q when I picked X and Y?").
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Also collect from comparison (healthy) nodes?").
				DescriptionFunc(func() string {
					return describeComparisonChoice(currentProblemNames(),
						suggestComparisonNodes(nodes, currentProblemNames(), defaultComparisonNodeCount))
				}, &problemNodeSel).
				Options(
					huh.NewOption("Use suggested nodes", cmpAccept),
					huh.NewOption("Choose comparison nodes myself", cmpEdit),
					huh.NewOption("No comparison nodes", cmpNone),
				).
				Value(&comparisonChoice),
		).WithHideFunc(func() bool { return method != byNode }),

		// 3b. Manual comparison-node picker. Problem nodes are shown greyed out
		// and locked (they're already collected in full); the rest are pickable.
		huh.NewGroup(
			newNodeMultiSelect().
				Title("Select comparison nodes").
				Options(nodeOptions(nodes)...).
				Height(pickerHeight(len(nodes))).
				Disabled(func(v string) bool {
					for _, p := range currentProblemNames() {
						if p == v {
							return true
						}
					}
					return false
				}).
				Warning(func(n int) string {
					return comparisonWarning(len(currentProblemNames()), n, len(nodes))
				}).
				Value(&comparisonSel),
		).WithHideFunc(func() bool { return method != byNode || comparisonChoice != cmpEdit }),

		// 3c. Comparison pods — by-pod path. Comparison is expressed in the same
		// terms the operator chose the problem in: similar pods that are healthy.
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Are there similar pods that are not hitting the problem?").
				Description("Detailed diagnostics will be collected from the nodes hosting the pods you "+
					"selected. Picking some healthy pods of the same kind gives a baseline to compare against.").
				Options(
					huh.NewOption("Yes — select some similar pods for comparison", cmpPodsYes),
					huh.NewOption("No comparison pods", cmpPodsNo),
				).
				Value(&cmpPodChoice),
		).WithHideFunc(func() bool { return method != byPod }),

		// 3d. Comparison-pod picker. The problem pods are greyed out and locked
		// (their nodes are already collected in full); the rest are pickable.
		huh.NewGroup(
			newNodeMultiSelect().
				Title("Select pods to compare against").
				Noun("pod").
				OptionsFunc(loadPodOptions).
				Disabled(func(v string) bool {
					for _, p := range problemPodSel {
						if p == v {
							return true
						}
					}
					return false
				}).
				Warning(func(int) string {
					problem := currentProblemNames()
					cmp := comparisonNodesFromPods(comparisonPodSel, podNodeByRef, problem)
					return comparisonWarning(len(problem), len(cmp), len(nodes))
				}).
				Value(&comparisonPodSel),
		).WithHideFunc(func() bool { return method != byPod || cmpPodChoice != cmpPodsYes }),

		// 4. When did it start? Mandatory — a precise-as-possible anchor for the
		// timeline that an open-ended box tends not to elicit.
		huh.NewGroup(
			huh.NewInput().
				Title("When did the problem start?").
				Description("Please be as precise as you can — a date and time, or relative such "+
					"as \"3 days ago\" or \"10:30am today\".").
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New("please say when the problem started")
					}
					return nil
				}).
				Value(&problemStarted),
		),

		// 5. The role of each affected pod/node. The custom textarea seeds itself
		// from the live selection the first time it's focused, so the operator just
		// fills in each pre-listed resource — and back-nav still works.
		huh.NewGroup(
			newSeededTextArea().
				Title("What is the role of each pod/node in the problem?").
				Description("Fill in the role of each item below. For a connectivity problem, say "+
					"which pod is the source and which is the destination, and the traffic affected "+
					"— e.g. \"TCP via service ns/example-service ClusterIP on port 8080\".").
				SeedFunc(func() string {
					return roleScaffold(method == byPod, problemPodSel, problemNodeSel)
				}).
				Value(&problemDetails),
		),

		// 6. Confirm. The plan is the Confirm field's own description (rather than a
		// separate Note) so the whole confirmation sits inside one bordered card.
		huh.NewGroup(
			huh.NewConfirm().
				Title("Confirm diagnostics collection").
				DescriptionFunc(func() string {
					problem := currentProblemNames()
					return describeInteractive(method == byPod, problemPodSel, problem, currentComparison(problem)) +
						"\n\nCollect diagnostics with this selection?"
				}, []any{&method, &problemNodeSel, &problemPodSel, &comparisonChoice, &comparisonSel, &cmpPodChoice, &comparisonPodSel}).
				Affirmative("Collect").
				Negative("Cancel").
				Value(&confirm),
		),
	)

	if aborted, err := runForm(form); err != nil || aborted {
		return selection{}, false, err
	}

	// Authoritative pod→node resolution now the UI is done (its warnings print to
	// the terminal).
	problemNodes := problemNodeSel
	if method == byPod {
		refs := parsePodRefs(strings.Join(problemPodSel, ","))
		ctx, c := shortContext()
		resolved, notFound, rerr := resolvePodsToNodes(ctx, kubeClient, refs)
		c()
		if rerr != nil {
			return selection{}, false, fmt.Errorf("resolving pods to nodes: %w", rerr)
		}
		for _, nf := range notFound {
			fmt.Fprintf(os.Stderr, "WARNING: could not resolve pod %s to a node; skipping.\n", podRefString(nf))
		}
		if len(resolved) == 0 {
			return selection{}, false, errors.New("none of the named pods could be resolved to a node")
		}
		fmt.Printf("Resolved %d pod(s) to nodes: %s\n", len(refs), strings.Join(resolved, ", "))
		problemNodes = resolved
	}
	if len(problemNodes) == 0 {
		return selection{}, false, errors.New("no problem nodes selected")
	}

	comparison := currentComparison(problemNodes)
	return selection{
		ProblemNodes:    problemNodes,
		ComparisonNodes: comparison,
		ProblemPods:     problemPodSel, // empty on the by-node path
		StartedAt:       strings.TrimSpace(problemStarted),
		Description:     strings.TrimSpace(problemDetails),
	}, confirm, nil
}

// roleScaffold builds the pre-populated body of the "role of each pod/node"
// field: one "Pod ns/name: " (or "Node name: ") line per selected resource, for
// the operator to complete. Returns "" when nothing is selected.
func roleScaffold(byPod bool, pods, nodes []string) string {
	prefix, items := "Node ", nodes
	if byPod {
		prefix, items = "Pod ", pods
	}
	lines := make([]string, 0, len(items))
	for _, it := range items {
		lines = append(lines, prefix+it+": ")
	}
	return strings.Join(lines, "\n")
}

// describeComparisonChoice renders the mini-confirmation shown above the
// comparison-node choice: a recap of the problem nodes just selected, then the
// suggested comparison nodes framed as *additional* healthy nodes. This makes it
// clear the suggestions are extra baseline collection, not a replacement for the
// operator's own selection.
func describeComparisonChoice(problemNames, suggested []string) string {
	var b strings.Builder
	b.WriteString("Problem nodes selected:\n")
	writeNodeBullets(&b, problemNames)
	if len(suggested) > 0 {
		b.WriteString("\nFor comparison, healthy nodes can also be collected — suggested (similar role/zone):\n")
		writeNodeBullets(&b, suggested)
	} else {
		b.WriteString("\nHealthy nodes collected alongside the problem nodes help spot what's different.")
	}
	// Trailing blank line to separate the recap from the choice options below.
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// resolveComparison turns the comparison choice into the final node list:
// auto-suggested, the operator's manual picks (minus any that are also problem
// nodes), or none.
func resolveComparison(nodes []nodeInfo, problemNodes []string, choice string, manual []string) []string {
	switch choice {
	case cmpNone:
		return nil
	case cmpEdit:
		problemSet := set.FromArray(problemNodes)
		var out []string
		for _, n := range manual {
			if n != "" && !problemSet.Contains(n) {
				out = append(out, n)
			}
		}
		return out
	default: // cmpAccept
		return suggestComparisonNodes(nodes, problemNodes, defaultComparisonNodeCount)
	}
}

// describeInteractive renders the live confirmation summary as a bulleted plan
// of what the run will collect. The problem nodes are known on both paths — on
// the by-pod path the picker has already mapped the selected pods to their nodes
// — so the plan and the over-budget warning are the same for both; the by-pod
// path additionally notes which pods those nodes came from.
func describeInteractive(byPod bool, problemPods, problemNames, comparison []string) string {
	var b strings.Builder
	if w := fullCollectionWarning(selection{ProblemNodes: problemNames, ComparisonNodes: comparison}); w != "" {
		b.WriteString(w)
		b.WriteString("\n\n")
	}

	b.WriteString("These diagnostics will be collected:\n\n")
	b.WriteString("- General cluster diagnostics.\n")
	b.WriteString("- Logs and diagnostics from all cluster-scoped Calico components.\n")

	if byPod {
		b.WriteString("- Detailed per-node diagnostics from the nodes hosting the problem pods:\n")
	} else {
		b.WriteString("- Detailed per-node diagnostics from the problem nodes:\n")
	}
	writeNodeBullets(&b, problemNames)
	if byPod && len(problemPods) > 0 {
		fmt.Fprintf(&b, "  (pods: %s)\n", joinCapped(problemPods))
	}

	if len(comparison) > 0 {
		b.WriteString("- Detailed per-node diagnostics from the comparison nodes:\n")
		writeNodeBullets(&b, comparison)
	}

	return strings.TrimRight(b.String(), "\n")
}

// joinCapped joins names with ", ", truncating to maxListedNodes with a trailing
// "and N more" so a long pod list stays compact in the confirmation note.
func joinCapped(names []string) string {
	if len(names) <= maxListedNodes {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:maxListedNodes], ", ") +
		fmt.Sprintf(", and %d more", len(names)-maxListedNodes)
}

// maxListedNodes caps how many names the confirmation lists inline before
// summarising the remainder, so a large selection doesn't flood the note.
const maxListedNodes = 15

// writeNodeBullets writes an indented sub-bullet list of names under a plan
// item, truncating to maxListedNodes with an "... and N more" line.
func writeNodeBullets(b *strings.Builder, names []string) {
	if len(names) == 0 {
		b.WriteString("  - (none)\n")
		return
	}
	shown := names
	if len(shown) > maxListedNodes {
		shown = shown[:maxListedNodes]
	}
	for _, n := range shown {
		fmt.Fprintf(b, "  - %s\n", n)
	}
	if rest := len(names) - len(shown); rest > 0 {
		fmt.Fprintf(b, "  - ... and %d more\n", rest)
	}
}

// podOptions renders each pod as a picker option whose value is the
// "namespace/pod" ref (parsed back by parsePodRefs) and whose label carries the
// ref, hosting node and lifecycle phase in aligned columns. Unscheduled pods
// show "(no node)"; the phase column makes finished pods stand out.
func podOptions(pods []podInfo) []huh.Option[string] {
	var refW, nodeW int
	nodeLabel := func(p podInfo) string {
		if p.Node == "" {
			return "(no node)"
		}
		return p.Node
	}
	for _, p := range pods {
		refW = max(refW, len(p.Ref()))
		nodeW = max(nodeW, len(nodeLabel(p)))
	}
	opts := make([]huh.Option[string], 0, len(pods))
	for _, p := range pods {
		label := fmt.Sprintf("%-*s   %-*s   %s", refW, p.Ref(), nodeW, nodeLabel(p), p.Phase)
		opts = append(opts, huh.NewOption(strings.TrimRight(label, " "), p.Ref()))
	}
	return opts
}

// overBudgetWarning returns the live over-budget warning shown by the node
// pickers once the running full-collection count exceeds the recommended max,
// or "" when within budget.
func overBudgetWarning(fullCount int) string {
	if fullCount > recommendedMaxFullNodes {
		return fmt.Sprintf("⚠  %d nodes selected for full collection — slow and a large bundle; "+
			"%d or fewer is recommended.", fullCount, recommendedMaxFullNodes)
	}
	return ""
}

// comparisonWarning is the live warning for the comparison-node picker: an
// over-budget full-collection set takes priority, otherwise — when the cluster
// actually has enough nodes to choose from — it nudges the operator to pick at
// least a couple of comparison nodes for a useful baseline.
func comparisonWarning(problemCount, comparisonSelected, totalNodes int) string {
	if w := overBudgetWarning(problemCount + comparisonSelected); w != "" {
		return w
	}
	available := totalNodes - problemCount
	if available >= defaultComparisonNodeCount && comparisonSelected < defaultComparisonNodeCount {
		return fmt.Sprintf("⚠  %d comparison node(s) selected — %d or more give a more useful baseline.",
			comparisonSelected, defaultComparisonNodeCount)
	}
	return ""
}

// nodeOptions renders each node as a checkbox option whose label carries the
// role/zone/readiness metadata in aligned columns and whose value is the bare
// node name. Column widths are computed across the whole set so the rows line
// up regardless of node-name length.
func nodeOptions(nodes []nodeInfo) []huh.Option[string] {
	var nameW, rolesW, zoneW int
	for _, ni := range nodes {
		nameW = max(nameW, len(ni.Name))
		rolesW = max(rolesW, len(strings.Join(ni.Roles, ",")))
		zoneW = max(zoneW, len(ni.Zone))
	}
	opts := make([]huh.Option[string], 0, len(nodes))
	for _, ni := range nodes {
		opts = append(opts, huh.NewOption(nodeOptionLabel(ni, nameW, rolesW, zoneW), ni.Name))
	}
	return opts
}

// nodeOptionLabel formats a node into fixed-width columns: name, roles, zone,
// readiness. Empty role/zone columns across the whole set are dropped entirely
// so clusters without those labels don't carry dead whitespace.
func nodeOptionLabel(ni nodeInfo, nameW, rolesW, zoneW int) string {
	cols := []string{fmt.Sprintf("%-*s", nameW, ni.Name)}
	if rolesW > 0 {
		cols = append(cols, fmt.Sprintf("%-*s", rolesW, strings.Join(ni.Roles, ",")))
	}
	if zoneW > 0 {
		cols = append(cols, fmt.Sprintf("%-*s", zoneW, ni.Zone))
	}
	if ni.Ready {
		cols = append(cols, "Ready")
	} else {
		cols = append(cols, "NotReady")
	}
	return strings.Join(cols, "   ")
}

// sortNodeInfos sorts nodes by name for stable, predictable display.
func sortNodeInfos(nodes []nodeInfo) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
}

// podRefString renders a podRef for log/warning output.
func podRefString(ref podRef) string {
	if ref.Namespace == "" {
		return ref.Name
	}
	return ref.Namespace + "/" + ref.Name
}

// pickerKeyMap is huh's default keymap with the single-select "/" filter
// disabled. Filtering earns its keystroke on the long node multi-selects, but
// on the handful-of-options single selects (problem-by-node/pod, comparison
// accept/edit/none) it is just clutter in the help line.
func pickerKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Select.Filter.SetEnabled(false)
	km.Select.SetFilter.SetEnabled(false)
	km.Select.ClearFilter.SetEnabled(false)
	return km
}

// runForm runs a huh form with the Tigera theme and picker keymap applied,
// translating a user abort (Ctrl-C / Esc) into aborted=true rather than an
// error so callers can cancel cleanly.
func runForm(form *huh.Form) (aborted bool, err error) {
	if err := form.WithKeyMap(pickerKeyMap()).WithTheme(tigeraTheme()).Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// pickerHeight sizes a multi-select to fill most of the terminal so long node
// lists are scrollable rather than crammed into a couple of rows, while not
// reserving more rows than there are options (plus chrome for title, filter and
// help lines). Falls back to a sensible fixed height when the terminal size is
// unavailable (e.g. not a TTY).
func pickerHeight(optionCount int) int {
	const chrome = 6
	h := 20
	if _, termHeight, err := term.GetSize(int(os.Stdout.Fd())); err == nil && termHeight > chrome+4 {
		h = termHeight - 2
	}
	if needed := optionCount + chrome; h > needed {
		h = needed
	}
	if h < 10 {
		h = 10
	}
	return h
}

// tigeraOrange is the Tigera brand accent. The picker is otherwise greyscale,
// so this is the only colour — reserved for focused buttons, selectors, titles
// and the active cursor.
var tigeraOrange = lipgloss.Color("#FF6E1B")

// tigeraTheme is a mostly-greyscale huh theme with Tigera orange accents, in
// place of huh's default neon palette.
func tigeraTheme() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		t := huh.ThemeBase(isDark)

		var (
			title    = tigeraOrange
			normal   = lipgloss.Color("252")
			selected = lipgloss.Color("255")
			muted    = lipgloss.Color("245")
			faint    = lipgloss.Color("240")
			buttonFg = lipgloss.Color("232")
		)

		// A full rounded box around the focused field's card, so every control
		// reads as a distinct, framed box (huh's default is just a left accent
		// bar). Blurred fields hide the border but keep the footprint (set below).
		t.Focused.Base = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(faint).
			Padding(0, 1)
		t.Focused.Card = t.Focused.Base
		t.Focused.Title = t.Focused.Title.Foreground(title).Bold(true)
		t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(title).Bold(true).MarginBottom(1)
		t.Focused.Description = t.Focused.Description.Foreground(muted)
		t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(tigeraOrange)
		t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(tigeraOrange)
		t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(tigeraOrange)
		t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(tigeraOrange)
		t.Focused.Option = t.Focused.Option.Foreground(normal)
		t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(selected).Bold(true)
		t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(tigeraOrange).SetString("[✓] ")
		t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(faint).SetString("[ ] ")
		t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(normal)
		t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(buttonFg).Background(tigeraOrange).Bold(true)
		t.Focused.Next = t.Focused.FocusedButton
		t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(normal).Background(lipgloss.Color("237"))
		t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(tigeraOrange)
		t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(tigeraOrange)
		t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(tigeraOrange)
		t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(tigeraOrange)
		t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(faint)

		// Blurred mirrors focused but hides the border and selector accents.
		t.Blurred = t.Focused
		t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
		t.Blurred.Card = t.Blurred.Base
		t.Blurred.MultiSelectSelector = lipgloss.NewStyle().SetString("  ")
		t.Blurred.NextIndicator = lipgloss.NewStyle()
		t.Blurred.PrevIndicator = lipgloss.NewStyle()

		t.Group.Title = t.Focused.Title
		t.Group.Description = t.Focused.Description
		return t
	})
}
