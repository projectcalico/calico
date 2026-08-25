// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A suite that requires BGP without the label runs on every lane, including the
// ones whose clusters use VXLAN, where the precondition fails every case.
func TestSuitesRequiringBGPCarryTheLabel(t *testing.T) {
	for _, path := range testFilesCalling(t, "RequireBGPEnabled") {
		if !fileContains(t, path, "RequiresBGP") {
			t.Errorf("%s: requires BGP but the suite has no describe.RequiresBGP label", path)
		}
	}
}

// The precondition belongs in RequireBGPEnabled, which names the label a lane
// should exclude. An inline assertion just reports that BGP is off.
func TestNoInlineBGPPreconditions(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("../tests", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "BGP" {
				return true
			}
			if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "CalicoNetwork" {
				t.Errorf("%s: use utils.RequireBGPEnabled instead of asserting on the Installation", fset.Position(sel.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the e2e tests: %v", err)
	}
}

func testFilesCalling(t *testing.T, fn string) []string {
	t.Helper()
	var matched []string
	err := filepath.WalkDir("../tests", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if fileContains(t, path, fn+"(") {
			matched = append(matched, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the e2e tests: %v", err)
	}
	if len(matched) == 0 {
		t.Fatalf("no e2e test calls %s, so this guard checks nothing", fn)
	}
	return matched
}

func fileContains(t *testing.T, path, s string) bool {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.Contains(string(body), s)
}
