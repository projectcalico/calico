package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A producer gated only on its own paths is dropped when a consumer needs it,
// taking the consumer with it, so the derived entry has to carry the consumer's
// triggers too.
func TestDependentGatesUnionsConsumerTriggers(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".argoci/ciworkflow.yaml"), `
includes:
  - path: .argoci/modules/producer.yaml
  - path: .argoci/modules/consumer.yaml
    changes:
      dependsOn: [kube-controllers]
      in: ['^extra/']
`)
	mustWrite(t, filepath.Join(root, ".argoci/modules/producer.yaml"), `
steps:
  - name: build-image
    changes:
      dependsOn: [cmd, dependents-of-build-image]
`)
	mustWrite(t, filepath.Join(root, ".argoci/modules/consumer.yaml"), `
steps:
  - name: use-image
    depends: [build-image]
`)
	steps, includes, err := loadArgoSteps(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	comps := map[string]argoCIComponent{"kube-controllers": {In: []string{"^kube-controllers/"}}}
	got := dependentGates(steps, comps, referencedDependentGates(steps, includes))

	entry, ok := got["dependents-of-build-image"]
	if !ok {
		t.Fatalf("no derived entry, got %v", got)
	}
	want := map[string]bool{"^kube-controllers/": false, "^extra/": false}
	for _, p := range entry.In {
		want[p] = true
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("derived entry missing %q; has %v", p, entry.In)
		}
	}
	if _, ok := got["dependents-of-use-image"]; ok {
		t.Error("a step nothing depends on should get no entry")
	}
}

// A step can be depended on for ordering alone. Deriving a gate for one of those
// would union every consumer's triggers into an entry nothing reads.
func TestUnreferencedDependentGateIsNotDerived(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".argoci/ciworkflow.yaml"), `
includes:
  - path: .argoci/modules/all.yaml
`)
	mustWrite(t, filepath.Join(root, ".argoci/modules/all.yaml"), `
steps:
  - name: check-go
    changes:
      in: ['^.*\.go$']
  - name: barrier
    depends: [check-go]
  - name: e2e
    depends: [barrier]
`)
	steps, includes, err := loadArgoSteps(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := dependentGates(steps, map[string]argoCIComponent{}, referencedDependentGates(steps, includes))
	for _, name := range []string{"dependents-of-check-go", "dependents-of-barrier"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s is referenced by nothing and must not be derived; got %v", name, got)
		}
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
