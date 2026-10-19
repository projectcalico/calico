// Copyright 2023 Google LLC
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

package imager

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestWriteK8sManifests(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "k8s-manifests-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	tmpfile.Close()

	req := Request{
		ImageName:            "test-image",
		ProjectName:          "test-project",
		K8sManifestsFilepath: tmpfile.Name(),
		K8sNamespace:         "test-namespace",
	}

	err = WriteK8sManifests(req)
	if err != nil {
		t.Fatalf("WriteK8sManifests failed: %v", err)
	}

	// Read the file content
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expected := `apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotContent
metadata:
  name: test-image-vsc
spec:
  deletionPolicy: Retain
  driver: pd.csi.storage.gke.io
  source:
    snapshotHandle: projects/test-project/global/images/test-image
  volumeSnapshotRef:
    name: test-image-vs
    namespace: test-namespace
---
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: test-image-vs
  namespace: test-namespace
spec:
  source:
    volumeSnapshotContentName: test-image-vsc
`

	if string(content) != expected {
		t.Errorf("Unexpected content:\nGot:\n%s\nWant:\n%s", string(content), expected)
	}
}

func TestWriteK8sManifests_ParentDirDoesNotExist(t *testing.T) {
	req := Request{
		ImageName:            "test-image",
		ProjectName:          "test-project",
		K8sManifestsFilepath: "/nonexistent-dir-12345/manifests.yaml",
	}

	err := WriteK8sManifests(req)
	if err == nil {
		t.Fatal("WriteK8sManifests expected error but got nil")
	}

	expectedErrMsg := "parent directory \"/nonexistent-dir-12345\" does not exist"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error message containing %q, got %q", expectedErrMsg, err.Error())
	}
}

func TestBuildDiskStartupScriptValidImage(t *testing.T) {
	req := Request{
		ContainerImages:       []string{"ubuntu:latest", "gcr.io/test-project/test-image:v1"},
		StoreSnapshotCheckSum: true,
		ImagePullAuth:         None,
	}
	f, err := buildDiskStartupScript(req)
	if err != nil {
		t.Fatalf("buildDiskStartupScript failed: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	contentBytes, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read generated script: %v", err)
	}
	content := string(contentBytes)
	expectedSuffix := "\n\nunpack true None 'ubuntu:latest' 'gcr.io/test-project/test-image:v1'"
	if !strings.HasSuffix(content, expectedSuffix) {
		t.Errorf("expected script to end with %q, but got %q", expectedSuffix, content)
	}
}

// TestBuildDiskStartupScriptShellInjectionNeutralized tests that shell command
// injection payloads in container image references are neutralized by being
// safely single-quoted.
func TestBuildDiskStartupScriptShellInjectionNeutralized(t *testing.T) {
	req := Request{
		JobName:               "test-job",
		ContainerImages:       []string{"ubuntu:latest;id>/tmp/PWNED;#"},
		StoreSnapshotCheckSum: true,
		ImagePullAuth:         None,
	}
	f, err := buildDiskStartupScript(req)
	if err != nil {
		t.Fatalf("buildDiskStartupScript failed: %v", err)
	}
	scriptPath := f.Name()
	f.Close()
	defer os.Remove(scriptPath)

	contentBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read generated script: %v", err)
	}
	content := string(contentBytes)

	expectedSuffix := "\n\nunpack true None 'ubuntu:latest;id>/tmp/PWNED;#'"
	if !strings.HasSuffix(content, expectedSuffix) {
		t.Errorf("expected script to end with %q, but got %q", expectedSuffix, content)
	}

	lines := strings.Split(content, "\n")
	last := lines[len(lines)-1]

	// Part B: Execution check. Run the generated line under bash with unpack stubbed
	// and verify that `/tmp/PWNED` is NOT created.
	pwnedFile := "/tmp/PWNED"
	_ = os.Remove(pwnedFile) // ensure it doesn't exist beforehand
	defer os.Remove(pwnedFile)

	cmdStr := fmt.Sprintf("unpack() { :; }\n%s", last)
	cmd := exec.Command("bash", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to run shell execution check: %v", err)
	}

	if _, err := os.Stat(pwnedFile); !os.IsNotExist(err) {
		t.Fatalf("injection execution check failed: %s was created, meaning command injection succeeded!", pwnedFile)
	}
}
