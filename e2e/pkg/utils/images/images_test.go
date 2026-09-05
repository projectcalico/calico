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

package images

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// seedScript names the same images in shell, so nothing but this test stops the
// two lists drifting apart.
const seedScript = "../../../../.argoci/scripts/phases/seed_images.sh"

// notSeeded holds the images the seed script deliberately leaves out, with the
// reason. Anything else declared in images.go has to be in the script.
var notSeeded = map[string]string{
	"Porter":          "runs on Windows nodes, which the seed script does not reach",
	"KubeVirtUbuntu":  "a containerDisk, pulled only by the KubeVirt lane",
	"CalicoBIRD":      "run through docker on the external node, not as a pod",
	"rapidClientRepo": "built from source and side-loaded by phases/load_images.sh",
}

func TestWorkloadImagesAreSeeded(t *testing.T) {
	script, err := os.ReadFile(seedScript)
	if err != nil {
		t.Fatalf("read %s: %v", seedScript, err)
	}

	for name, ref := range declaredImages(t) {
		if reason, skip := notSeeded[name]; skip {
			if strings.Contains(string(script), ref) {
				t.Errorf("%s is listed in the seed script but recorded as not seeded (%s)", name, reason)
			}
			continue
		}
		if !strings.Contains(string(script), ref) {
			t.Errorf("%s (%s) is not in %s; add it there, or record why it is exempt in notSeeded",
				name, ref, seedScript)
		}
	}
}

// declaredImages returns the image reference declared by each string constant in
// images.go, keyed by constant name. Constants defined as another constant (the
// EchoServer alias) have no literal and are left out.
func declaredImages(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "images.go", nil, 0)
	if err != nil {
		t.Fatalf("parse images.go: %v", err)
	}

	refs := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			ref, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(ref, "/") {
				continue
			}
			refs[value.Names[0].Name] = ref
		}
	}
	if len(refs) == 0 {
		t.Fatal("no image constants found in images.go")
	}
	return refs
}
