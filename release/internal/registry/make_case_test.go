// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package registry

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeImageReferencesPreserveTags(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"retag-build-image-arch-with-registry-amd64", "push-image-arch-to-registry-amd64"} {
		cmd := exec.Command("make", "--no-print-directory", "-f", "lib.Makefile", "-n", target, "REGISTRY=Quay.IO/Team", "BUILD_IMAGE=Mixed/Image", "IMAGETAG=v1.RC1", "ARCH=amd64")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make %s: %v\n%s", target, err, out)
		}
		if !strings.Contains(string(out), "quay.io/team/mixed/image:v1.RC1") {
			t.Fatalf("missing normalized reference: %s", out)
		}
		if strings.Contains(string(out), "docker tag Mixed/") || strings.Contains(string(out), "docker push Quay.") {
			t.Fatalf("unnormalized image reference: %s", out)
		}
	}
}
