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

package ipam

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Clusters installed with a named pool, on dual stack, or on a provider's IPAM
// have no pool by these names, so a lookup by name fails rather than finding the
// cluster's pool.
func TestNoHardcodedDefaultPoolNames(t *testing.T) {
	forEachSuiteFile(t, func(t *testing.T, fset *token.FileSet, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if strings.Contains(lit.Value, "default-ipv4-ippool") || strings.Contains(lit.Value, "default-ipv6-ippool") {
				t.Errorf("%s: IP pool names are not guaranteed; list the pools and select by address family instead", fset.Position(lit.Pos()))
			}
			return true
		})
	})
}

// A suite that reads Calico IPAM state has to carry the label, so the lanes
// running a provider's IPAM can exclude it.
func TestSuitesReadingCalicoIPAMCarryTheLabel(t *testing.T) {
	forEachSuiteFile(t, func(t *testing.T, fset *token.FileSet, f *ast.File) {
		for _, s := range calicoIPAMSuites(f) {
			if s.labelled || !callsCalicoIPAMCheck(s.body) {
				continue
			}
			t.Errorf("%s: suite reads Calico IPAM state, so it needs describe.RequiresCalicoIPAM", fset.Position(s.body.Pos()))
		}
	})
}

func forEachSuiteFile(t *testing.T, check func(*testing.T, *token.FileSet, *ast.File)) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve tests root: %v", err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		check(t, fset, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}
}

type calicoIPAMSuite struct {
	body     ast.Node
	labelled bool
}

// calicoIPAMSuites returns every CalicoDescribe body in the file, along with
// whether it declares the Calico IPAM label.
func calicoIPAMSuites(f *ast.File) []calicoIPAMSuite {
	var found []calicoIPAMSuite
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "describe", "CalicoDescribe") {
			return true
		}
		s := calicoIPAMSuite{}
		for _, arg := range call.Args {
			if inner, ok := arg.(*ast.CallExpr); ok && isSelector(inner.Fun, "describe", "RequiresCalicoIPAM") {
				s.labelled = true
			}
			if fn, ok := arg.(*ast.FuncLit); ok {
				s.body = fn
			}
		}
		if s.body != nil {
			found = append(found, s)
		}
		return true
	})
	return found
}

func callsCalicoIPAMCheck(body ast.Node) bool {
	calls := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isSelector(call.Fun, "utils", "UsesCalicoIPAM") {
			calls = true
		}
		return !calls
	})
	return calls
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkg && sel.Sel.Name == name
}
