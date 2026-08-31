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

package describe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every suite has to declare a feature, or its cases land in no per-feature view
// of the CI dashboard and nobody notices them failing.
func TestEverySuiteDeclaresAFeature(t *testing.T) {
	root, err := filepath.Abs("../tests")
	if err != nil {
		t.Fatalf("resolve tests root: %v", err)
	}

	fset := token.NewFileSet()
	var undeclared []string
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
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isDescribeCall(call, "CalicoDescribe") {
				return true
			}
			for _, arg := range call.Args {
				if inner, ok := arg.(*ast.CallExpr); ok && isDescribeCall(inner, "WithFeature") {
					return true
				}
			}
			pos := fset.Position(call.Pos())
			undeclared = append(undeclared, pos.String())
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}

	for _, pos := range undeclared {
		t.Errorf("%s: suite has no describe.WithFeature label", pos)
	}
}

// isDescribeCall reports whether the call is describe.<name>(...) or, inside this
// package, a bare <name>(...).
func isDescribeCall(call *ast.CallExpr, name string) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		return ok && pkg.Name == "describe" && fn.Sel.Name == name
	case *ast.Ident:
		return fn.Name == name
	}
	return false
}
