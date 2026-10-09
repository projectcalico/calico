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

package policy

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A bare policy name in a non-default tier is only valid from v3.32, so a suite
// that uses one has to carry the label that older lanes skip on.
func TestBareNamesInACustomTierDeclareNoTierPrefix(t *testing.T) {
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
		for _, suite := range suites(f) {
			if suite.labelled {
				continue
			}
			for _, p := range policies(suite.body) {
				if isDefaultTier(p.tier) || prefixedWithTier(fset, p.name, p.tier) {
					continue
				}
				t.Errorf("%s: policy is named without its tier prefix, so its suite needs describe.WithNoTierPrefix", fset.Position(p.name.Pos()))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}
}

type suite struct {
	body     ast.Node
	labelled bool
}

// suites returns every CalicoDescribe body in the file, along with whether it
// declares the NoTierPrefix label.
func suites(f *ast.File) []suite {
	var found []suite
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isDescribeSelector(call.Fun, "CalicoDescribe") {
			return true
		}
		s := suite{}
		for _, arg := range call.Args {
			if inner, ok := arg.(*ast.CallExpr); ok && isDescribeSelector(inner.Fun, "WithNoTierPrefix") {
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

type policy struct {
	name ast.Expr
	tier ast.Expr
}

// policies returns the policies created in the node whose name and tier are both
// visible at the call site: the staged policy constructors, and composite
// literals that set an ObjectMeta name alongside a spec tier.
func policies(n ast.Node) []policy {
	var found []policy
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			fn, ok := n.Fun.(*ast.Ident)
			if !ok || len(n.Args) < 2 {
				return true
			}
			if fn.Name == "CreateStagedNetworkPolicy" || fn.Name == "CreateStagedGlobalNetworkPolicy" {
				found = append(found, policy{name: n.Args[0], tier: n.Args[1]})
			}
		case *ast.CompositeLit:
			name, tier := fieldValue(n, "Name"), fieldValue(n, "Tier")
			if name != nil && tier != nil {
				found = append(found, policy{name: name, tier: tier})
			}
		}
		return true
	})
	return found
}

// fieldValue finds a named field anywhere inside a composite literal, so a name
// under ObjectMeta and a tier under Spec both resolve from the outer literal.
func fieldValue(lit *ast.CompositeLit, field string) ast.Expr {
	var value ast.Expr
	ast.Inspect(lit, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == field && value == nil {
			value = kv.Value
		}
		return true
	})
	return value
}

func isDefaultTier(tier ast.Expr) bool {
	lit, ok := tier.(*ast.BasicLit)
	return ok && lit.Value == `"default"`
}

// prefixedWithTier reports whether the name is built from the tier, which is the
// other valid way to name a policy in a non-default tier.
func prefixedWithTier(fset *token.FileSet, name, tier ast.Expr) bool {
	return strings.Contains(render(fset, name), render(fset, tier))
}

func render(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return b.String()
}

// isDescribeSelector reports whether the expression is describe.<name>.
func isDescribeSelector(e ast.Expr, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "describe" && sel.Sel.Name == name
}
