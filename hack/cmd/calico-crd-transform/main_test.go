package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParseYAML(t *testing.T, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatal(err)
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) == 0 {
		t.Fatal("expected document with content")
	}
	return *n.Content[0]
}

const testCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ports.example.org
spec:
  versions:
    - schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                allocations:
                  type: array
                  items: {type: integer}
                portRange:
                  description: Specifies the range of ports.
                  default: {portName: ""}
                  type: object
                  required: [portName]
                  properties:
                    minPort: {type: integer}
                    maxPort: {type: integer}
                    portName: {type: string}
`

// TestApply covers shape matcher with delete-then-set patch (Port shape) and
// path matcher with simple set patch (allocations items). Also confirms
// description/default survive the shape swap.
func TestApply(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ports.yaml"), []byte(testCRD), 0o644)

	cfg := &Config{Rules: []Rule{
		{
			Name: "port-shape",
			Shape: &Shape{
				Type:       "object",
				Properties: []string{"minPort", "maxPort", "portName"},
				Required:   []string{"portName"},
			},
			Patch: mustParseYAML(t, `
type: null
properties: null
required: null
x-kubernetes-int-or-string: true
pattern: ^.*
`),
		},
		{
			Name:  "alloc-items-nullable",
			CRD:   "ports.*",
			Path:  ".spec.allocations[*]",
			Patch: mustParseYAML(t, `nullable: true`),
		},
	}}

	counts := make(map[string]int, len(cfg.Rules))
	if err := apply(filepath.Join(dir, "ports.yaml"), cfg, counts); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if counts["port-shape"] != 1 || counts["alloc-items-nullable"] != 1 {
		t.Errorf("counts: %v", counts)
	}

	body, _ := os.ReadFile(filepath.Join(dir, "ports.yaml"))
	out := string(body)
	for _, want := range []string{
		"x-kubernetes-int-or-string: true",
		"nullable: true",
		"Specifies the range of ports", // description preserved
		"default:",                     // default preserved
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	for _, dontWant := range []string{"minPort", "maxPort"} {
		if strings.Contains(out, dontWant) {
			t.Errorf("struct shape leaked through (%q):\n%s", dontWant, out)
		}
	}
}

// TestUntouchedFileNotRewritten ensures files where no rule matches are
// left byte-identical (so yaml.v3's emit-style differences don't introduce
// gratuitous churn).
func TestUntouchedFileNotRewritten(t *testing.T) {
	dir := t.TempDir()
	const crd = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: foo.example.org
spec:
  versions:
    - schema: {openAPIV3Schema: {type: object}}
`
	path := filepath.Join(dir, "foo.yaml")
	_ = os.WriteFile(path, []byte(crd), 0o644)
	original, _ := os.ReadFile(path)

	cfg := &Config{Rules: []Rule{{
		Name:  "never-matches-here",
		Path:  ".spec.bogus",
		Patch: mustParseYAML(t, `nullable: true`),
	}}}
	counts := make(map[string]int, len(cfg.Rules))
	if err := apply(path, cfg, counts); err != nil {
		t.Fatalf("apply: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(original) != string(after) {
		t.Errorf("untouched file was rewritten:\noriginal:\n%s\nafter:\n%s", original, after)
	}
}
