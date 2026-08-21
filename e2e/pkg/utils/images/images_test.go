// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package images

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestMirroredRewritesTheRegistryHost(t *testing.T) {
	for _, tc := range []struct {
		name, mirror, ref, want string
	}{
		{"no mirror set", "", "docker.io/alpine:3", "docker.io/alpine:3"},
		{"docker hub", "mirror.example.com", "docker.io/alpine:3", "mirror.example.com/alpine:3"},
		{"nested path", "mirror.example.com", "registry.k8s.io/e2e-test-images/agnhost:2.47", "mirror.example.com/e2e-test-images/agnhost:2.47"},
		{"implicit host", "mirror.example.com", "calico/porter", "mirror.example.com/calico/porter"},
		{"digest", "mirror.example.com", "mcas/ubuntu@sha256:abc", "mirror.example.com/mcas/ubuntu@sha256:abc"},
		{"mirror with a path", "mirror.example.com/proxy/", "docker.io/alpine:3", "mirror.example.com/proxy/alpine:3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("E2E_IMAGE_MIRROR", tc.mirror)
			if got := mirrored(tc.ref); got != tc.want {
				t.Errorf("mirrored(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// An image reference that skips the rewrite is pulled from its own registry, so
// it fails on the lanes whose clusters cannot reach that registry.
func TestEveryImageReferenceGoesThroughTheMirror(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "images.go", nil, 0)
	if err != nil {
		t.Fatalf("parse images.go: %v", err)
	}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, v := range value.Values {
				if _, ok := v.(*ast.Ident); ok {
					// An alias for another image in this block, already mirrored.
					continue
				}
				if call, ok := v.(*ast.CallExpr); ok {
					if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "mirrored" {
						continue
					}
				}
				t.Errorf("%s: image reference must be wrapped in mirrored()", fset.Position(v.Pos()))
			}
		}
	}
}
