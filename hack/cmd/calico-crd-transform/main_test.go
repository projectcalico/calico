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

// TestApplyToDir_PatchSetAndDelete covers a patch that sets keys (path
// matcher → nullable) and one that deletes-and-sets (shape matcher → wholesale
// shape swap via null-deletes). Also confirms field-level metadata
// (description, default) survives because the patch doesn't touch those keys.
func TestApplyToDir_PatchSetAndDelete(t *testing.T) {
	dir := t.TempDir()
	const crd = `apiVersion: apiextensions.k8s.io/v1
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
	_ = os.WriteFile(filepath.Join(dir, "ports.yaml"), []byte(crd), 0o644)

	cfg := &Config{Rules: []Rule{
		{
			Name: "port-shape",
			Where: Where{Shape: &ShapeMatcher{
				Type:               "object",
				Properties:         []string{"minPort", "maxPort", "portName"},
				RequiredProperties: []string{"portName"},
			}},
			Apply: Apply{Patch: mustParseYAML(t, `
type: null
properties: null
required: null
x-kubernetes-int-or-string: true
pattern: ^.*
`)},
		},
		{
			Name:  "alloc-items-nullable",
			Where: Where{CRD: "ports.*", Path: ".spec.allocations[*]"},
			Apply: Apply{Patch: mustParseYAML(t, `nullable: true`)},
		},
	}}

	counts, err := applyToDir(dir, cfg)
	if err != nil {
		t.Fatalf("applyToDir: %v", err)
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

// TestApplyToDir_LoudFailOnZeroMatches ensures rules that match nothing
// are reported, not silently skipped (config drift safety net).
func TestApplyToDir_LoudFailOnZeroMatches(t *testing.T) {
	dir := t.TempDir()
	const crd = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: empty.example.org
spec:
  versions:
    - schema: {openAPIV3Schema: {type: object}}
`
	_ = os.WriteFile(filepath.Join(dir, "empty.yaml"), []byte(crd), 0o644)

	cfg := &Config{Rules: []Rule{{
		Name:  "never-matches",
		Where: Where{Path: ".spec.bogus"},
		Apply: Apply{Patch: mustParseYAML(t, `nullable: true`)},
	}}}
	if _, err := applyToDir(dir, cfg); err == nil || !strings.Contains(err.Error(), "never-matches") {
		t.Errorf("want zero-match error, got %v", err)
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	cases := map[string]string{
		"missing name": `rules:
- where: {path: .x}
  apply: {patch: {nullable: true}}`,
		"both matchers": `rules:
- name: x
  where: {path: .x, shape: {type: object, properties: [a]}}
  apply: {patch: {nullable: true}}`,
		"missing patch": `rules:
- name: x
  where: {path: .x}
  apply: {}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "c.yaml")
			_ = os.WriteFile(f, []byte(body), 0o644)
			if _, err := loadConfig(f); err == nil {
				t.Errorf("expected validation error")
			}
		})
	}
}
