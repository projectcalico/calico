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

// gen-chart-readme generates the configuration reference embedded in a Helm
// chart README. It documents two layers:
//
//  1. Chart-level values: parsed from comment blocks above each top-level key
//     in values.yaml. This covers helm-only knobs (manageCRDs, certs, the
//     tigeraOperator image, etc.) that have no corresponding CRD.
//  2. CRD spec references: walked from each --crd's openAPIv3 schema.
//     Subtrees listed in --truncate collapse to a placeholder so the output
//     doesn't drown in upstream Kubernetes types (component override
//     DaemonSet/Deployment specs, tolerations, node selectors, etc.).
//
// The result is spliced between BEGIN/END markers in the target README so the
// surrounding hand-written content is preserved. New CRD fields show up in
// the README automatically; CI's "did you commit generated files?" check then
// flags drift if the regenerated README differs from what's committed.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// schema is a minimal projection of the openAPIv3 schema fields we need.
type schema struct {
	Description          string             `json:"description,omitempty"`
	Type                 string             `json:"type,omitempty"`
	Properties           map[string]*schema `json:"properties,omitempty"`
	Items                *schema            `json:"items,omitempty"`
	Default              any                `json:"default,omitempty"`
	Enum                 []any              `json:"enum,omitempty"`
	Format               string             `json:"format,omitempty"`
	Required             []string           `json:"required,omitempty"`
	AdditionalProperties any                `json:"additionalProperties,omitempty"`
}

type crdDoc struct {
	Spec struct {
		Names struct {
			Kind string `json:"kind"`
		} `json:"names"`
		Versions []struct {
			Name   string `json:"name"`
			Schema struct {
				OpenAPIV3Schema *schema `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// crdInput pairs a CRD file path with the helm values key it should be
// rendered under in the README.
type crdInput struct {
	helmKey string
	path    string
}

// Markers used when splicing into an existing README.
const (
	beginMarker = "<!-- BEGIN AUTO-GENERATED CHART REFERENCE -->"
	endMarker   = "<!-- END AUTO-GENERATED CHART REFERENCE -->"
)

// defaultTruncate collapses subtrees that are either structurally identical
// to upstream Kubernetes types or otherwise too noisy to expand inline. Paths
// are dotted, relative to each CRD's spec.
var defaultTruncate = []string{
	// Installation
	"calicoKubeControllersDeployment",
	"calicoNodeDaemonSet",
	"calicoNodeWindowsDaemonSet",
	"calicoWindowsUpgradeDaemonSet",
	"csiNodeDriverDaemonSet",
	"typhaDeployment",
	"typhaAffinity",
	"componentResources", // deprecated
	"controlPlaneTolerations",
	"controlPlaneNodeSelector",
	"imagePullSecrets",
	"nodeUpdateStrategy",
	"proxy",
	"certificateManagement",
	// APIServer
	"apiServerDeployment",
	"l7AdmissionControllerDeployment",
	// Goldmane
	"goldmaneDeployment",
	// Whisker
	"whiskerDeployment",
}

// crdsFlag implements flag.Value for repeated --crd helmKey=path entries.
type crdsFlag []crdInput

func (c *crdsFlag) String() string { return fmt.Sprintf("%v", []crdInput(*c)) }
func (c *crdsFlag) Set(v string) error {
	k, p, ok := strings.Cut(v, "=")
	if !ok || k == "" || p == "" {
		return fmt.Errorf("expected helmKey=path, got %q", v)
	}
	*c = append(*c, crdInput{helmKey: k, path: p})
	return nil
}

func main() {
	var crds crdsFlag
	flag.Var(&crds, "crd", "repeatable; helmKey=path/to/crd.yaml")
	values := flag.String("values", "", "path to chart values.yaml")
	splice := flag.String("splice-into", "", "README path: rewrite content between BEGIN/END markers in place")
	out := flag.String("out", "-", "output path (`-` for stdout); ignored when --splice-into is set")
	truncate := flag.String("truncate", strings.Join(defaultTruncate, ","), "comma-separated dotted paths to truncate within each CRD")
	maxDepth := flag.Int("max-depth", 2, "max nesting depth to expand under each CRD spec (0 = unlimited); deeper fields collapse with a pointer to the operator API docs")
	flag.Parse()

	stop := map[string]bool{}
	for _, p := range strings.Split(*truncate, ",") {
		if p = strings.TrimSpace(p); p != "" {
			stop[p] = true
		}
	}

	var b strings.Builder
	fmt.Fprintln(&b, "<!-- Generated by hack/cmd/gen-chart-readme. DO NOT EDIT BETWEEN MARKERS. -->")
	fmt.Fprintln(&b, "<!-- Regenerate with `make gen-chart-readme`. -->")
	fmt.Fprintln(&b)

	if *values != "" {
		fmt.Fprintln(&b, "## Chart values")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Top-level keys accepted by this chart's `values.yaml`. Defaults below match the chart's shipped values.")
		fmt.Fprintln(&b, "For keys backed by an operator CRD (e.g. `installation`, `apiServer`), see the API references further down.")
		fmt.Fprintln(&b)
		entries, err := parseValuesComments(*values)
		if err != nil {
			die("parse values: %v", err)
		}
		writeChartValuesTable(&b, entries)
	}

	for _, c := range crds {
		writeCRDReference(&b, c, stop, *maxDepth)
	}

	data := b.String()
	if *splice != "" {
		if err := spliceInto(*splice, data); err != nil {
			die("splice %s: %v", *splice, err)
		}
		return
	}
	if *out == "-" {
		fmt.Print(data)
		return
	}
	if err := os.WriteFile(*out, []byte(data), 0o644); err != nil {
		die("write %s: %v", *out, err)
	}
}

// ---------- chart values parsing ----------

type chartEntry struct {
	key, defaultVal, description string
}

// parseValuesComments walks values.yaml line-by-line and returns one entry
// per top-level key. The description is the contiguous run of comment lines
// directly preceding the key; the default is the rendered value (a single
// line for scalars, a placeholder for nested structures).
func parseValuesComments(path string) ([]chartEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")

	var (
		entries []chartEntry
		comment []string
	)
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			c := strings.TrimPrefix(trimmed, "#")
			c = strings.TrimPrefix(c, " ")
			comment = append(comment, c)
		case trimmed == "":
			// Blank lines decouple stray header comments from the next key.
			comment = nil
		case isTopLevelKey(ln):
			key, val := splitKeyValue(ln)
			defaultVal := val
			if defaultVal == "" {
				defaultVal = peekNestedDefault(lines, i+1)
			}
			entries = append(entries, chartEntry{
				key:         key,
				defaultVal:  defaultVal,
				description: strings.TrimSpace(strings.Join(comment, " ")),
			})
			comment = nil
		default:
			// Indented content (a nested key, list item, etc.) belongs to
			// the most recently emitted top-level key; reset comments.
			comment = nil
		}
	}
	return entries, nil
}

func isTopLevelKey(line string) bool {
	if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '-' {
		return false
	}
	return strings.Contains(line, ":")
}

func splitKeyValue(line string) (string, string) {
	k, v, _ := strings.Cut(line, ":")
	return strings.TrimSpace(k), strings.TrimSpace(v)
}

// peekNestedDefault returns "{...}" for an indented map, "[...]" for an
// indented list, or "{}" if the structure is empty.
func peekNestedDefault(lines []string, from int) string {
	for j := from; j < len(lines); j++ {
		ln := lines[j]
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "\t") {
			return "{}"
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			return "[...]"
		}
		return "{...}"
	}
	return "{}"
}

func writeChartValuesTable(b *strings.Builder, entries []chartEntry) {
	fmt.Fprintln(b, "| Key | Default | Description |")
	fmt.Fprintln(b, "|-----|---------|-------------|")
	for _, e := range entries {
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", e.key, mdCode(e.defaultVal), mdEscape(e.description))
	}
	fmt.Fprintln(b)
}

func mdCode(v string) string {
	if v == "" {
		return "—"
	}
	return "`" + v + "`"
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ---------- CRD reference emission ----------

func writeCRDReference(b *strings.Builder, c crdInput, stop map[string]bool, maxDepth int) {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		die("read crd %s: %v", c.path, err)
	}
	var d crdDoc
	if err := yaml.Unmarshal(raw, &d); err != nil {
		die("parse crd %s: %v", c.path, err)
	}
	var root *schema
	for _, v := range d.Spec.Versions {
		if v.Name == "v1" {
			root = v.Schema.OpenAPIV3Schema
			break
		}
	}
	if root == nil || root.Properties["spec"] == nil {
		die("crd %s missing v1 spec schema", c.path)
	}

	kind := d.Spec.Names.Kind
	if kind == "" {
		kind = c.helmKey
	}

	fmt.Fprintf(b, "## `%s` reference (%s)\n\n", c.helmKey, kind)
	if desc := strings.TrimSpace(root.Description); desc != "" {
		fmt.Fprintln(b, normalizeDesc(desc))
		fmt.Fprintln(b)
	}
	fmt.Fprintf(b, "Set these fields under `%s:` in your values.yaml.\n\n", c.helmKey)

	walkCRD(b, root.Properties["spec"], "", stop, maxDepth, 1)
}

// walkCRD emits one Markdown heading per nested object group and per leaf
// (or truncated) field. Heading level reflects path depth (depth 1 → ###,
// depth 2 → ####, etc.). When maxDepth is reached, deeper subtrees collapse
// to a pointer to the operator API docs.
func walkCRD(b *strings.Builder, s *schema, prefix string, stop map[string]bool, maxDepth, depth int) {
	if s == nil || s.Type != "object" || len(s.Properties) == 0 {
		return
	}
	keys := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		child := s.Properties[k]
		path := joinPath(prefix, k)

		isObject := child.Type == "object" && len(child.Properties) > 0
		isArrayOfObject := child.Type == "array" && child.Items != nil &&
			child.Items.Type == "object" && len(child.Items.Properties) > 0
		isComplex := isObject || isArrayOfObject

		// Decide whether we're allowed to recurse into the child. A child
		// is collapsed (rendered as a single entry with a "see API"
		// pointer) when its path is in the stop list, or when expanding
		// it would push children past maxDepth.
		canExpand := isComplex && !stop[path] && (maxDepth <= 0 || depth+1 <= maxDepth)

		if !canExpand {
			// Leaves emit plain; collapsed-complex nodes flag truncation
			// so readers know there's hidden detail in the API docs.
			emitField(b, path, child, isComplex || stop[path], depth)
			continue
		}

		if isObject {
			emitGroup(b, path, child, depth)
			walkCRD(b, child, path, stop, maxDepth, depth+1)
		} else { // array of object
			emitField(b, path, child, false, depth)
			walkCRD(b, child.Items, path+"[]", stop, maxDepth, depth+1)
		}
	}
}

// headingPrefix returns a string of '#' characters appropriate for a field
// at the given depth. Top-level CRD spec children are rendered at ### so
// they nest under the ## "<helmKey> reference" section.
func headingPrefix(depth int) string {
	level := depth + 2
	if level > 6 {
		level = 6
	}
	return strings.Repeat("#", level)
}

func emitGroup(b *strings.Builder, path string, s *schema, depth int) {
	fmt.Fprintf(b, "%s `%s`\n\n", headingPrefix(depth), path)
	if desc := strings.TrimSpace(s.Description); desc != "" {
		fmt.Fprintln(b, normalizeDesc(desc))
		fmt.Fprintln(b)
	}
}

func emitField(b *strings.Builder, path string, s *schema, truncated bool, depth int) {
	fmt.Fprintf(b, "%s `%s`\n\n", headingPrefix(depth), path)
	if desc := strings.TrimSpace(s.Description); desc != "" {
		fmt.Fprintln(b, normalizeDesc(desc))
		fmt.Fprintln(b)
	}

	var meta []string
	if t := schemaType(s); t != "" {
		meta = append(meta, "**Type**: "+t)
	}
	if def := formatDefault(s); def != "" {
		meta = append(meta, "**Default**: `"+def+"`")
	}
	if enum := formatEnum(s); enum != "" {
		meta = append(meta, "**Valid values**: "+enum)
	}
	if truncated {
		meta = append(meta, "_See the [operator API reference](https://docs.tigera.io/calico/latest/reference/installation/api) for this field's full schema._")
	}
	if len(meta) > 0 {
		fmt.Fprintln(b, strings.Join(meta, " · "))
		fmt.Fprintln(b)
	}
}

func schemaType(s *schema) string {
	switch s.Type {
	case "":
		return ""
	case "array":
		if s.Items != nil && s.Items.Type != "" {
			return "array of " + s.Items.Type
		}
		return "array"
	case "object":
		if len(s.Properties) == 0 {
			return "object (free-form)"
		}
		return "object"
	default:
		if s.Format != "" {
			return s.Type + " (" + s.Format + ")"
		}
		return s.Type
	}
}

func formatDefault(s *schema) string {
	if s.Default == nil {
		return ""
	}
	out, err := yaml.Marshal(s.Default)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

func formatEnum(s *schema) string {
	if len(s.Enum) == 0 {
		return ""
	}
	vs := make([]string, 0, len(s.Enum))
	for _, v := range s.Enum {
		vs = append(vs, "`"+fmt.Sprintf("%v", v)+"`")
	}
	return strings.Join(vs, ", ")
}

// normalizeDesc rejoins hard-wrapped CRD descriptions: each blank-line
// separated paragraph collapses to a single line so Markdown renders it as
// flowing prose rather than broken sentences.
func normalizeDesc(d string) string {
	paragraphs := strings.Split(d, "\n\n")
	for i, p := range paragraphs {
		fields := strings.Fields(p)
		paragraphs[i] = strings.Join(fields, " ")
	}
	return strings.Join(paragraphs, "\n\n")
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// ---------- splice ----------

func spliceInto(path, fragment string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")

	beginIdx, endIdx := -1, -1
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		switch {
		case trimmed == beginMarker && beginIdx < 0:
			beginIdx = i
		case trimmed == endMarker && beginIdx >= 0 && endIdx < 0:
			endIdx = i
		}
	}
	if beginIdx < 0 || endIdx < 0 {
		return fmt.Errorf("missing markers (expected %q and %q)", beginMarker, endMarker)
	}

	out := append([]string{}, lines[:beginIdx+1]...)
	out = append(out, "")
	out = append(out, strings.Split(strings.TrimRight(fragment, "\n"), "\n")...)
	out = append(out, "")
	out = append(out, lines[endIdx:]...)

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
