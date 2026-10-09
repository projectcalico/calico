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
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
)

const testsDir = "../../tests"

func TestEncodeDropsDatastoreOwnedFields(t *testing.T) {
	RegisterTestingT(t)

	scheme, err := newScheme()
	Expect(err).NotTo(HaveOccurred())
	c := &calicoctlExecClient{scheme: scheme}

	data, err := c.encode(&v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "test-tier", ResourceVersion: "1234"}})
	Expect(err).NotTo(HaveOccurred())

	obj := map[string]any{}
	Expect(json.Unmarshal([]byte(data), &obj)).NotTo(HaveOccurred())
	Expect(obj).To(HaveKeyWithValue("kind", "Tier"))
	Expect(obj).To(HaveKeyWithValue("apiVersion", "projectcalico.org/v3"))
	Expect(obj).NotTo(HaveKey("status"))
	Expect(obj["metadata"]).To(HaveKeyWithValue("name", "test-tier"))
	Expect(obj["metadata"]).NotTo(HaveKey("creationTimestamp"))
	Expect(obj["metadata"]).NotTo(HaveKey("resourceVersion"))
}

// The exec client runs on clusters with no v3 API, so every kind the e2e tests reach
// for has to be one calicoctl can create, get, and delete.
func TestEveryKindTheTestsUseIsKnownToCalicoctl(t *testing.T) {
	RegisterTestingT(t)

	scheme, err := newScheme()
	Expect(err).NotTo(HaveOccurred())

	kinds := v3KindsUsedByTests(t, scheme)
	Expect(kinds).NotTo(BeEmpty(), "no v3 kind found under "+testsDir+", so this guard checks nothing")

	valid := resourcemgr.ValidResources()
	for _, kind := range kinds {
		if !slices.Contains(valid, kind) {
			t.Errorf("the e2e tests use %s but calicoctl has no resource manager for it", kind)
		}
	}
}

// v3KindsUsedByTests returns the projectcalico.org/v3 kinds the e2e tests name, ignoring
// the v3 types that are not resources of their own.
func v3KindsUsedByTests(t *testing.T, scheme interface {
	Recognizes(schema.GroupVersionKind) bool
},
) []string {
	t.Helper()

	var kinds []string
	err := filepath.WalkDir(testsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "v3" {
				return true
			}
			gvk := schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: sel.Sel.Name}
			if !scheme.Recognizes(gvk) {
				return true
			}
			// The exec client asks calicoctl for the kind itself, list or not.
			kind := strings.TrimSuffix(gvk.Kind, "List")
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
			return true
		})
		return nil
	})
	Expect(err).NotTo(HaveOccurred())

	slices.Sort(kinds)
	return kinds
}
