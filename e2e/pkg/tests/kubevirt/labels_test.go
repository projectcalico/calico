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

package kubevirt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Lanes whose clusters have no KubeVirt exclude these suites by the Feature
// label, so a suite filed under another feature runs everywhere and fails.
func TestEveryKubeVirtSuiteDeclaresTheKubeVirtFeature(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the KubeVirt suites: %v", err)
	}
	var checked int
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isDescribeCall(call, "CalicoDescribe") {
				return true
			}
			checked++
			for _, arg := range call.Args {
				inner, ok := arg.(*ast.CallExpr)
				if !ok || !isDescribeCall(inner, "WithFeature") {
					continue
				}
				if len(inner.Args) == 0 {
					continue
				}
				if lit, ok := inner.Args[0].(*ast.BasicLit); ok && lit.Value == `"KubeVirt"` {
					return true
				}
			}
			t.Errorf("%s: suite is not labelled with the KubeVirt feature", fset.Position(call.Pos()))
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no KubeVirt suites, so this guard checks nothing")
	}
}

// The Feature label does not say which kind of KubeVirt a suite needs, and the
// lanes that run one kind exclude the other, so a suite declaring neither runs
// where it cannot pass.
func TestEveryKubeVirtSuiteDeclaresTheKubeVirtItNeeds(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing the KubeVirt suites: %v", err)
	}
	var checked int
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isDescribeCall(call, "CalicoDescribe") {
				return true
			}
			checked++
			for _, arg := range call.Args {
				inner, ok := arg.(*ast.CallExpr)
				if !ok {
					continue
				}
				if isDescribeCall(inner, "RequiresRealKubeVirt") || isDescribeCall(inner, "RequiresMockVirt") {
					return true
				}
			}
			t.Errorf("%s: suite declares neither RequiresRealKubeVirt nor RequiresMockVirt", fset.Position(call.Pos()))
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no KubeVirt suites, so this guard checks nothing")
	}
}

// isDescribeCall reports whether the call is describe.<name>(...).
func isDescribeCall(call *ast.CallExpr, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "describe" && sel.Sel.Name == name
}
