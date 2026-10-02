// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// An impersonated request has to reach the apiserver as itself, so the calicoctl
// fallback would run as its own service account and void the RBAC assertions.
var impersonationCallers = map[string]bool{
	"tests/policy/tiered_rbac.go": true,
}

// TestNewAPIClientCallers keeps NewAPIClient out of the suites. It has no discovery wait
// and no calicoctl fallback, so a rolling or absent calico-apiserver fails the test
// instead of being waited out.
func TestNewAPIClientCallers(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve pkg root: %v", err)
	}

	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if impersonationCallers[filepath.ToSlash(rel)] {
			return nil
		}

		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, line := range findAPIClientCalls(fset, f) {
			t.Errorf("%s:%d calls NewAPIClient; use New so the suite waits for projectcalico.org/v3 and can fall back to calicoctl", filepath.ToSlash(rel), line)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

func TestFindAPIClientCallsMatchesOnlyNewAPIClient(t *testing.T) {
	for name, src := range map[string]string{
		"NewAPIClient": "package p\nfunc f() { client.NewAPIClient(cfg) }\n",
		"New":          "package p\nfunc f() { client.New(cfg) }\n",
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name+".go", src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		got := len(findAPIClientCalls(fset, f))
		want := 0
		if name == "NewAPIClient" {
			want = 1
		}
		if got != want {
			t.Errorf("%s: got %d calls, want %d", name, got, want)
		}
	}
}

// findAPIClientCalls returns the lines of every package-qualified NewAPIClient call.
func findAPIClientCalls(fset *token.FileSet, f *ast.File) []int {
	var lines []int
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "NewAPIClient" {
			lines = append(lines, fset.Position(sel.Pos()).Line)
		}
		return true
	})
	return lines
}
