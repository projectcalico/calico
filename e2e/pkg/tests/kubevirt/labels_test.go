// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package kubevirt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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

// Detection has to tell "no KubeVirt" apart from "real KubeVirt", so the Get
// error cannot go straight into an assertion.
func TestMockVirtDetectionToleratesAMissingCR(t *testing.T) {
	body, err := os.ReadFile("utils.go")
	if err != nil {
		t.Fatalf("reading utils.go: %v", err)
	}
	fn := string(body)
	start := strings.Index(fn, "func isMockVirtDeployed(")
	if start < 0 {
		t.Fatal("isMockVirtDeployed is gone; update this guard")
	}
	end := strings.Index(fn[start:], "\n}\n")
	if !strings.Contains(fn[start:start+end], "apierrors.IsNotFound(err)") {
		t.Error("isMockVirtDeployed must return false when the KubeVirt CR is absent")
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
