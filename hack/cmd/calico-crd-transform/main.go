// calico-crd-transform applies the rules in transforms.yaml to a directory
// of controller-gen-produced CRD YAMLs. Run after vanilla controller-gen.
//
// Usage:
//
//	go run ./hack/cmd/calico-crd-transform \
//	    --config ./hack/cmd/calico-crd-transform/transforms.yaml \
//	    --dir api/config/crd
//
// Each rule has a matcher (where: shape | path) and a patch (apply.patch).
// Patches are key-merges: a value sets the key; an explicit null deletes it
// (RFC 7396 JSON Merge Patch).  Rules with zero matches across the input
// directory cause a non-zero exit, so config drift fails loud.
//
// We walk and edit the file as a yaml.Node tree (rather than round-tripping
// through map[string]any) so the output preserves controller-gen's original
// indentation and scalar styles for any subtree we don't touch.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Where       Where  `yaml:"where"`
	Apply       Apply  `yaml:"apply"`
}

// Where selects which schema nodes a rule applies to. Exactly one of Shape or
// Path must be set.
type Where struct {
	Shape *ShapeMatcher `yaml:"shape,omitempty"`
	CRD   string        `yaml:"crd,omitempty"`  // glob, only with Path
	Path  string        `yaml:"path,omitempty"` // dotted data-shape, e.g. .spec.foo[*].bar
}

// ShapeMatcher matches a JSONSchemaProps node by structural shape. Property
// and required-property sets must match exactly: a field added to the source
// struct fails the rule loudly.
type ShapeMatcher struct {
	Type               string   `yaml:"type"`
	Properties         []string `yaml:"properties"`
	RequiredProperties []string `yaml:"requiredProperties,omitempty"`
}

// Apply describes the edit. Patch is a key-merge: a non-nil value sets the
// key, a null value deletes it.  The patch is kept as a raw yaml.Node so
// it retains whatever style was used in transforms.yaml when emitted.
type Apply struct {
	Patch yaml.Node `yaml:"patch"`
}

func main() {
	configPath := flag.String("config", "", "path to transforms YAML")
	crdDir := flag.String("dir", "", "directory of CRD YAML files to patch in place")
	verbose := flag.Bool("v", false, "print per-rule match counts")
	flag.Parse()

	if *configPath == "" || *crdDir == "" {
		fmt.Fprintln(os.Stderr, "usage: calico-crd-transform --config <transforms.yaml> --dir <crd-dir>")
		os.Exit(2)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fail("load config:", err)
	}
	counts, err := applyToDir(*crdDir, cfg)
	if *verbose || err != nil {
		printCounts(counts, cfg)
	}
	if err != nil {
		fail(err)
	}
}

func fail(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}

func printCounts(counts map[string]int, cfg *Config) {
	for _, r := range cfg.Rules {
		fmt.Fprintf(os.Stderr, "%4d  %s\n", counts[r.Name], r.Name)
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i, r := range cfg.Rules {
		if r.Name == "" {
			return nil, fmt.Errorf("rule[%d]: name is required", i)
		}
		hasShape := r.Where.Shape != nil
		hasPath := r.Where.Path != ""
		if hasShape == hasPath {
			return nil, fmt.Errorf("rule %q: where must set exactly one of shape or path", r.Name)
		}
		if r.Apply.Patch.Kind != yaml.MappingNode || len(r.Apply.Patch.Content) == 0 {
			return nil, fmt.Errorf("rule %q: apply.patch must be a non-empty mapping", r.Name)
		}
	}
	return &cfg, nil
}

// applyToDir transforms every *.yaml file in dir in place. Returns per-rule
// match counts and an error if any rule had zero matches.
func applyToDir(dir string, cfg *Config) (map[string]int, error) {
	counts := make(map[string]int, len(cfg.Rules))
	for _, r := range cfg.Rules {
		counts[r.Name] = 0
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return counts, err
	}
	sort.Strings(files)

	for _, file := range files {
		if err := applyToFile(file, cfg, counts); err != nil {
			return counts, fmt.Errorf("%s: %w", filepath.Base(file), err)
		}
	}

	var unmatched []string
	for _, r := range cfg.Rules {
		if counts[r.Name] == 0 {
			unmatched = append(unmatched, r.Name)
		}
	}
	if len(unmatched) > 0 {
		sort.Strings(unmatched)
		return counts, fmt.Errorf("rules with zero matches in %s (config drift?): %s",
			dir, strings.Join(unmatched, ", "))
	}
	return counts, nil
}

func applyToFile(path string, cfg *Config, counts map[string]int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	top := root.Content[0]
	crdName := scalarValue(mapGet(mapGet(top, "metadata"), "name"))

	// Track per-file match count so we only rewrite when a rule actually
	// fired.  yaml.v3's encoder doesn't preserve every scalar style that
	// yaml.v2 (controller-gen) produced — re-emitting an untouched file
	// would introduce gratuitous formatting churn.
	before := totalMatches(counts)
	versions := mapGet(mapGet(top, "spec"), "versions")
	if versions != nil && versions.Kind == yaml.SequenceNode {
		for _, v := range versions.Content {
			schema := mapGet(mapGet(v, "schema"), "openAPIV3Schema")
			if schema != nil {
				walk(schema, "", crdName, cfg, counts)
			}
		}
	}
	if totalMatches(counts) == before {
		return nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	out := buf.Bytes()
	// controller-gen emits a leading "---" doc separator on every file; the
	// downstream sed -i 1d step in api/Makefile and libcalico-go/Makefile
	// expects it.  yaml.Encoder doesn't emit one for a single document, so
	// add it back.
	if !bytes.HasPrefix(out, []byte("---\n")) {
		out = append([]byte("---\n"), out...)
	}
	return os.WriteFile(path, out, 0o644)
}

func totalMatches(counts map[string]int) int {
	n := 0
	for _, v := range counts {
		n += v
	}
	return n
}

// walk descends a JSONSchemaProps subtree and applies any matching rules.
// dataPath is the user-facing path (".spec.foo[*]") used by Path matchers.
func walk(node *yaml.Node, dataPath, crdName string, cfg *Config, counts map[string]int) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if !matches(node, dataPath, crdName, &r.Where) {
			continue
		}
		applyRule(node, r)
		counts[r.Name]++
	}

	if props := mapGet(node, "properties"); props != nil && props.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(props.Content); i += 2 {
			walk(props.Content[i+1], dataPath+"."+props.Content[i].Value, crdName, cfg, counts)
		}
	}
	if items := mapGet(node, "items"); items != nil {
		walk(items, dataPath+"[*]", crdName, cfg, counts)
	}
	if ap := mapGet(node, "additionalProperties"); ap != nil {
		walk(ap, dataPath+"[*]", crdName, cfg, counts)
	}
}

func matches(node *yaml.Node, dataPath, crdName string, w *Where) bool {
	if w.Shape != nil {
		return matchesShape(node, w.Shape)
	}
	if w.CRD != "" {
		ok, _ := filepath.Match(w.CRD, crdName)
		if !ok {
			return false
		}
	}
	return dataPath == w.Path
}

func matchesShape(node *yaml.Node, m *ShapeMatcher) bool {
	if scalarValue(mapGet(node, "type")) != m.Type {
		return false
	}
	if !sameStringSet(mapKeys(mapGet(node, "properties")), m.Properties) {
		return false
	}
	if m.RequiredProperties != nil {
		if !sameStringSet(seqValues(mapGet(node, "required")), m.RequiredProperties) {
			return false
		}
	}
	return true
}

// applyRule applies a JSON-Merge-Patch-style edit: a non-nil value in the
// patch sets the corresponding key on the node; an explicit null deletes
// the key.  Keys not mentioned in the patch are left alone.
func applyRule(node *yaml.Node, r *Rule) {
	patch := &r.Apply.Patch
	for i := 0; i+1 < len(patch.Content); i += 2 {
		key := patch.Content[i].Value
		val := patch.Content[i+1]
		if val.Tag == "!!null" {
			mapDelete(node, key)
		} else {
			mapSet(node, key, val)
		}
	}
}

// mapGet returns the value Node for key in a MappingNode, or nil if missing
// or if m isn't a mapping.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func mapKeys(m *yaml.Node) []string {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]string, 0, len(m.Content)/2)
	for i := 0; i < len(m.Content); i += 2 {
		out = append(out, m.Content[i].Value)
	}
	return out
}

// mapSet replaces the value for key, or appends a new key/value pair.
func mapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val,
	)
}

func mapDelete(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func seqValues(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind == yaml.ScalarNode {
			out = append(out, c.Value)
		}
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
