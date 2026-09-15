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

package operatorimages

import (
	"slices"
	"strings"
	"testing"
)

func TestCheckAcceptsEveryDeployedImage(t *testing.T) {
	if err := Check(deployed()); err != nil {
		t.Fatalf("Check(deployed()): %v", err)
	}
}

func TestCheckNamesTheUndeployedImages(t *testing.T) {
	err := Check([]string{"node", "new-thing", "another-thing"})
	if err == nil {
		t.Fatal("Check: want an error for images the operator does not deploy")
	}
	for _, img := range []string{"new-thing", "another-thing"} {
		if !strings.Contains(err.Error(), img) {
			t.Errorf("Check error %q does not name %s", err, img)
		}
	}
}

func TestCheckSkipsExceptions(t *testing.T) {
	notDeployed = map[string]string{"new-thing": "not deployed by the operator"}
	t.Cleanup(func() {
		notDeployed = map[string]string{}
	})
	if err := Check([]string{"node", "new-thing"}); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestMissingReportsEachImageOnce(t *testing.T) {
	got := missing([]string{"new-thing", "node", "new-thing"}, []string{"node"})
	if !slices.Equal(got, []string{"new-thing"}) {
		t.Errorf("missing = %v, want [new-thing]", got)
	}
}

func TestDeployedIncludesTheOperatorItself(t *testing.T) {
	got := deployed()
	for _, img := range []string{"calico", "node", "operator"} {
		if !slices.Contains(got, img) {
			t.Errorf("deployed() does not name %s", img)
		}
	}
}
