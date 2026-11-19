// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package helmtest pins what the operator renders from its embedded helm
// charts in golden files. The renderer mirrors helm internals instead of
// calling them, so a helm or chart upgrade that changes the output must show
// up as a reviewable diff rather than pass silently.
package helmtest

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// UpdateEnv set to "true" rewrites the golden files instead of comparing.
// The charts are downloaded by the operator build, so run `make embedded_charts`
// in operator/ first.
const UpdateEnv = "UPDATE_EXPECTED_DATA"

// ToYAML serializes the objects as one YAML stream, sorted by kind, namespace
// and name so that the output does not depend on the order helm emits them in.
func ToYAML(objs []client.Object) ([]byte, error) {
	sorted := make([]client.Object, len(objs))
	copy(sorted, objs)
	sort.SliceStable(sorted, func(i, j int) bool {
		ki, kj := kind(sorted[i]), kind(sorted[j])
		if ki != kj {
			return ki < kj
		}
		if sorted[i].GetNamespace() != sorted[j].GetNamespace() {
			return sorted[i].GetNamespace() < sorted[j].GetNamespace()
		}
		return sorted[i].GetName() < sorted[j].GetName()
	})

	var b bytes.Buffer
	for _, o := range sorted {
		out, err := yaml.Marshal(o)
		if err != nil {
			return nil, fmt.Errorf("marshal %s %s/%s: %w", kind(o), o.GetNamespace(), o.GetName(), err)
		}
		if kind(o) == "CustomResourceDefinition" {
			// helm copies CRDs from the chart verbatim and they make up most of
			// the output, so a digest pins them without bloating the file.
			fmt.Fprintf(&b, "---\n# %s %s sha256:%x\n", kind(o), o.GetName(), sha256.Sum256(out))
			continue
		}
		fmt.Fprintf(&b, "---\n# %s %s/%s\n%s", kind(o), o.GetNamespace(), o.GetName(), out)
	}
	return b.Bytes(), nil
}

// kind names the Go type, because objects decoded from a manifest may not
// carry their TypeMeta.
func kind(o client.Object) string {
	return reflect.TypeOf(o).Elem().Name()
}

// CompareGolden returns an error if got differs from the golden file at path.
func CompareGolden(path string, got []byte) error {
	if os.Getenv(UpdateEnv) == "true" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, got, 0o644)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: run with %s=true to create it", err, UpdateEnv)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("rendered output differs from %s: rerun with %s=true and review the diff", path, UpdateEnv)
	}
	return nil
}
