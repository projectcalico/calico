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
	"Porter":         "runs on Windows nodes, which the seed script does not reach",
	"KubeVirtUbuntu": "a containerDisk, pulled only by the KubeVirt lane",
	"CalicoBIRD":     "run through docker on the external node, not as a pod",
	"RapidClient":    "pulled from quay, and side-loaded from source by phases/load_images.sh on the PR lane",
}

func TestWorkloadImagesAreSeeded(t *testing.T) {
	script, err := os.ReadFile(seedScript)
	if err != nil {
		t.Fatalf("read %s: %v", seedScript, err)
	}

	declared := declaredImages(t)
	for name := range notSeeded {
		if _, ok := declared[name]; !ok {
			t.Errorf("notSeeded lists %s, which images.go does not declare; drop the entry or correct the name", name)
		}
	}

	for name, ref := range declared {
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

func TestRapidClientImageIsConsistent(t *testing.T) {
	ref, ok := declaredImages(t)["RapidClient"]
	if !ok {
		t.Fatal("images.go no longer declares RapidClient")
	}
	repo, tag, ok := strings.Cut(ref, ":")
	if !ok {
		t.Fatalf("RapidClient %q has no tag", ref)
	}

	// The side-loaded copy is only used when every one of these names the same
	// reference the pods ask for.
	want := map[string][]string{
		"../../../../Makefile": {
			"RAPIDCLIENT_IMAGE := " + repo,
			"RAPIDCLIENT_TAG := " + tag,
		},
		"../../../../.argoci/scripts/phases/load_images.sh": {
			`_img="` + ref + `"`,
			`TAG_NAME="` + tag + `"`,
		},
	}
	for path, refs := range want {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, expected := range refs {
			if !strings.Contains(string(content), expected) {
				t.Errorf("%s does not contain %q, so its copy of the image no longer matches %s", path, expected, ref)
			}
		}
	}
}

// declaredImages returns the string literal bound by each top-level constant and
// variable in images.go, keyed by name. Every one counts as an image reference;
// anything else has to go in notSeeded.
func declaredImages(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "images.go", nil, 0)
	if err != nil {
		t.Fatalf("parse images.go: %v", err)
	}

	refs := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}

			// An alias for another name (EchoServer) has no literal to check.
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			ref, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			refs[value.Names[0].Name] = ref
		}
	}
	if len(refs) == 0 {
		t.Fatal("no image references found in images.go")
	}
	return refs
}
