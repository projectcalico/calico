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
package main

import (
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
// key, a null value deletes it.
type Apply struct {
	Patch map[string]any `yaml:"patch"`
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
		if len(r.Apply.Patch) == 0 {
			return nil, fmt.Errorf("rule %q: apply.patch is required", r.Name)
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
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	crdName, _ := dig(doc, "metadata", "name").(string)

	versions, _ := dig(doc, "spec", "versions").([]any)
	for _, v := range versions {
		vm, _ := v.(map[string]any)
		schema, _ := dig(vm, "schema", "openAPIV3Schema").(map[string]any)
		if schema == nil {
			continue
		}
		walk(schema, "", crdName, cfg, counts)
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	// Prepend a YAML document separator. controller-gen emits one at the top
	// of every CRD it produces, and the Makefile post-processing chain
	// (notably `sed -i 1d`) expects it to be there to strip — without it,
	// downstream sed deletes the apiVersion line instead.
	out = append([]byte("---\n"), out...)
	return os.WriteFile(path, out, 0o644)
}

// walk descends a JSONSchemaProps subtree and applies any matching rules.
// dataPath is the user-facing path (".spec.foo[*]") used by Path matchers.
func walk(node map[string]any, dataPath, crdName string, cfg *Config, counts map[string]int) {
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if !matches(node, dataPath, crdName, &r.Where) {
			continue
		}
		applyRule(node, r)
		counts[r.Name]++
	}

	if props, ok := node["properties"].(map[string]any); ok {
		for key, child := range props {
			cm, ok := child.(map[string]any)
			if !ok {
				continue
			}
			walk(cm, dataPath+"."+key, crdName, cfg, counts)
		}
	}
	if items, ok := node["items"].(map[string]any); ok {
		walk(items, dataPath+"[*]", crdName, cfg, counts)
	}
	if ap, ok := node["additionalProperties"].(map[string]any); ok {
		walk(ap, dataPath+"[*]", crdName, cfg, counts)
	}
}

func matches(node map[string]any, dataPath, crdName string, w *Where) bool {
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

func matchesShape(node map[string]any, m *ShapeMatcher) bool {
	if t, _ := node["type"].(string); t != m.Type {
		return false
	}
	props, _ := node["properties"].(map[string]any)
	if !sameStringSet(mapKeys(props), m.Properties) {
		return false
	}
	if m.RequiredProperties != nil {
		req := stringsFromAny(node["required"])
		if !sameStringSet(req, m.RequiredProperties) {
			return false
		}
	}
	return true
}

// applyRule applies a JSON-Merge-Patch-style edit: a non-nil value in the
// patch sets the corresponding key on the node; an explicit null deletes
// the key.  Keys not mentioned in the patch are left alone — that's how
// field-level metadata like description and default survive.
func applyRule(node map[string]any, r *Rule) {
	for k, v := range r.Apply.Patch {
		if v == nil {
			delete(node, k)
		} else {
			node[k] = v
		}
	}
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func mapKeys(m map[string]any) []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func stringsFromAny(v any) []string {
	s, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(s))
	for _, x := range s {
		if str, ok := x.(string); ok {
			out = append(out, str)
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
