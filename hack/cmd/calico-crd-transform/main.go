// calico-crd-transform applies the rules in transforms.yaml to a directory
// of controller-gen-produced CRD YAMLs. Run after vanilla controller-gen.
//
// Usage:
//
//	go run ./hack/cmd/calico-crd-transform \
//	    --config ./hack/cmd/calico-crd-transform/transforms.yaml \
//	    --dir api/config/crd
//
// Each rule has either a shape matcher (any JSONSchema node with the listed
// properties/required) or a path matcher (a dotted data-shape JSON path
// inside a CRD whose metadata.name matches the optional crd glob), plus a
// patch.  The patch is a JSON-Merge-Patch: a value sets a key, an explicit
// null deletes it, omitted keys are preserved.
//
// Rules with zero matches across the input directory cause a non-zero exit
// so config drift fails loud.
//
// File parsing is yaml.Node-based so untouched subtrees are written back
// byte-for-byte; only files where a rule actually matched get re-emitted.
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
	Name  string    `yaml:"name"`
	Shape *Shape    `yaml:"shape,omitempty"` // shape matcher (mutually exclusive with path)
	CRD   string    `yaml:"crd,omitempty"`   // glob over metadata.name; only with path
	Path  string    `yaml:"path,omitempty"`  // dotted data-shape path
	Patch yaml.Node `yaml:"patch"`
}

type Shape struct {
	Type       string   `yaml:"type"`
	Properties []string `yaml:"properties"`
	Required   []string `yaml:"required,omitempty"`
}

func main() {
	var cfgPath, dir string
	flag.StringVar(&cfgPath, "config", "", "path to transforms YAML")
	flag.StringVar(&dir, "dir", "", "directory of CRD YAMLs to patch in place")
	flag.Parse()
	if cfgPath == "" || dir == "" {
		fmt.Fprintln(os.Stderr, "usage: calico-crd-transform --config <transforms.yaml> --dir <crd-dir>")
		os.Exit(2)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		die(err)
	}

	counts := make(map[string]int, len(cfg.Rules))
	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	sort.Strings(files)
	for _, f := range files {
		if err := apply(f, cfg, counts); err != nil {
			die(fmt.Errorf("%s: %w", filepath.Base(f), err))
		}
	}

	var miss []string
	for _, r := range cfg.Rules {
		if counts[r.Name] == 0 {
			miss = append(miss, r.Name)
		}
	}
	if len(miss) > 0 {
		sort.Strings(miss)
		die(fmt.Errorf("rules with zero matches in %s (config drift?): %s",
			dir, strings.Join(miss, ", ")))
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func apply(path string, cfg *Config, counts map[string]int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	top := doc.Content[0]
	crd := scalar(get(get(top, "metadata"), "name"))
	versions := get(get(top, "spec"), "versions")
	if versions == nil || versions.Kind != yaml.SequenceNode {
		return nil
	}

	dirty := false
	for _, v := range versions.Content {
		if schema := get(get(v, "schema"), "openAPIV3Schema"); schema != nil {
			walk(schema, "", crd, cfg, counts, &dirty)
		}
	}
	if !dirty {
		return nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	enc.Close()
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("---\n")) {
		out = append([]byte("---\n"), out...)
	}
	return os.WriteFile(path, out, 0o644)
}

func walk(node *yaml.Node, path, crd string, cfg *Config, counts map[string]int, dirty *bool) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if !ruleMatches(node, path, crd, r) {
			continue
		}
		applyPatch(node, &r.Patch)
		counts[r.Name]++
		*dirty = true
	}
	if p := get(node, "properties"); p != nil && p.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(p.Content); i += 2 {
			walk(p.Content[i+1], path+"."+p.Content[i].Value, crd, cfg, counts, dirty)
		}
	}
	for _, key := range []string{"items", "additionalProperties"} {
		if c := get(node, key); c != nil {
			walk(c, path+"[*]", crd, cfg, counts, dirty)
		}
	}
}

func ruleMatches(node *yaml.Node, path, crd string, r *Rule) bool {
	if r.Shape != nil {
		return scalar(get(node, "type")) == r.Shape.Type &&
			sameSet(keys(get(node, "properties")), r.Shape.Properties) &&
			(r.Shape.Required == nil || sameSet(seq(get(node, "required")), r.Shape.Required))
	}
	if r.CRD != "" {
		if ok, _ := filepath.Match(r.CRD, crd); !ok {
			return false
		}
	}
	return path == r.Path
}

// applyPatch is JSON-Merge-Patch on yaml.Nodes: non-null values set keys,
// null values delete them.
func applyPatch(node, patch *yaml.Node) {
	for i := 0; i+1 < len(patch.Content); i += 2 {
		key, val := patch.Content[i].Value, patch.Content[i+1]
		idx := indexKey(node, key)
		switch {
		case val.Tag == "!!null":
			if idx >= 0 {
				node.Content = append(node.Content[:idx], node.Content[idx+2:]...)
			}
		case idx >= 0:
			node.Content[idx+1] = val
		default:
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
				val)
		}
	}
}

// yaml.Node helpers — kept terse and inline-friendly.

func get(m *yaml.Node, key string) *yaml.Node {
	if i := indexKey(m, key); i >= 0 {
		return m.Content[i+1]
	}
	return nil
}

func indexKey(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func keys(m *yaml.Node) []string {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]string, 0, len(m.Content)/2)
	for i := 0; i < len(m.Content); i += 2 {
		out = append(out, m.Content[i].Value)
	}
	return out
}

func seq(n *yaml.Node) []string {
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

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
