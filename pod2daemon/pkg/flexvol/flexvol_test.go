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

package flexvol

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallDriverCopiesRunningBinary(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "uds")

	if err := installDriver(dst); err != nil {
		t.Fatalf("installDriver: %v", err)
	}

	// Destination must be byte-identical to the source so argv[0]
	// dispatch routes kubelet's "uds <args>" into the same binary.
	src, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	srcBytes, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}
	dstBytes, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(srcBytes, dstBytes) {
		t.Fatalf("dst (%d bytes) does not match src (%d bytes)", len(dstBytes), len(srcBytes))
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o550 {
		t.Errorf("dst permissions = %#o, want 0550", mode)
	}
}

func TestInstallDriverRequiresTarget(t *testing.T) {
	if err := installDriver(""); err == nil {
		t.Fatal("expected error when target is empty")
	}
}

func TestInstallDriverRejectsNonUdsBasename(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "policysync")
	if err := installDriver(dst); err == nil {
		t.Fatal("expected error when target basename is not \"uds\"")
	}
}

func TestInstallDriverOverwritesExistingFile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "uds")
	if err := os.WriteFile(dst, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed dst: %v", err)
	}

	if err := installDriver(dst); err != nil {
		t.Fatalf("installDriver: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if bytes.Equal(got, []byte("stale")) {
		t.Fatal("install did not overwrite existing file")
	}
}

func TestInstallDriverIfPresentSkipsMissingDriver(t *testing.T) {
	root := t.TempDir()
	if err := installDriverIfPresent(filepath.Join(root, "nodeagent~uds", "uds")); err != nil {
		t.Fatalf("installDriverIfPresent: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected nothing created, got %v", entries)
	}
}

func TestInstallDriverIfPresentReplacesInstalledDriver(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "uds")
	if err := os.WriteFile(dst, []byte("old"), 0o550); err != nil {
		t.Fatal(err)
	}
	if err := installDriverIfPresent(dst); err != nil {
		t.Fatalf("installDriverIfPresent: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, []byte("old")) {
		t.Fatal("installed driver was not replaced")
	}
}

const (
	testUID      = "20154c76-bf4e-11e7-8a7e-080027631ab3"
	testOtherUID = "2dc75e9a-cbec-11e7-b158-0800270da466"
)

func volumeDir(root, uid string) string {
	return root + "/pods/" + uid + "/volumes/nodeagent~uds/test-volume"
}

func TestCheckValidMountOptsAcceptsKubeletOptions(t *testing.T) {
	for _, uid := range []string{testUID, "0c6d6e1d9b3c4c2e8f0a1b2c3d4e5f60"} {
		opts := `{"kubernetes.io/pod.uid":"` + uid + `","kubernetes.io/pod.name":"p","kubernetes.io/pod.namespace":"ns","kubernetes.io/serviceAccount.name":"sa"}`
		c, path, ok := checkValidMountOpts(volumeDir("/var/lib/kubelet", uid), opts)
		if !ok {
			t.Fatalf("uid %q: expected valid opts", uid)
		}
		if path != uid || c.UID != uid || c.Workload != "p" || c.Namespace != "ns" || c.ServiceAccount != "sa" {
			t.Errorf("uid %q: unexpected result path=%q creds=%+v", uid, path, c)
		}
	}
}

func TestCheckValidMountOptsRejectsUIDNotMatchingDir(t *testing.T) {
	for _, uid := range []string{"", "x", testOtherUID} {
		opts := `{"kubernetes.io/pod.uid":"` + uid + `"}`
		if _, _, ok := checkValidMountOpts(volumeDir("/var/lib/kubelet", testUID), opts); ok {
			t.Errorf("uid %q: expected rejection", uid)
		}
	}
}

func TestCheckValidMountOptsUsesExactKeys(t *testing.T) {
	opts := `{"kubernetes.io/pod.uid":"` + testUID + `",` +
		`"kubernetes.io/pod.name":"p","kubernetes.io/pod.namespace":"ns","kubernetes.io/serviceAccount.name":"sa",` +
		`"Kubernetes.io/pod.uid":"` + testOtherUID + `",` +
		`"Kubernetes.io/pod.name":"other","Kubernetes.io/pod.namespace":"other","Kubernetes.io/serviceAccount.name":"other"}`
	c, path, ok := checkValidMountOpts(volumeDir("/var/lib/kubelet", testUID), opts)
	if !ok {
		t.Fatal("expected valid opts")
	}
	if path != testUID || c.Workload != "p" || c.Namespace != "ns" || c.ServiceAccount != "sa" {
		t.Errorf("non-exact keys used: path=%q creds=%+v", path, c)
	}
}

func TestPodUIDFromDir(t *testing.T) {
	for _, root := range []string{
		"/var/lib/kubelet",
		"/var/snap/microk8s/common/var/lib/kubelet",
		"/var/lib/k0s/kubelet",
		"/data/custom-kubelet",
	} {
		for _, dir := range []string{volumeDir(root, testUID), volumeDir(root, testUID) + "/"} {
			if uid, err := podUIDFromDir(dir); err != nil || uid != testUID {
				t.Errorf("podUIDFromDir(%q) = %q, %v", dir, uid, err)
			}
		}
	}

	for _, dir := range []string{
		"",
		"/",
		"/var/lib/kubelet/pods/" + testUID,
		"/var/lib/kubelet/pods/" + testUID + "/volumes/other~driver/test-volume",
		"/var/lib/kubelet/notpods/" + testUID + "/volumes/nodeagent~uds/test-volume",
		volumeDir("/var/lib/kubelet", ".."),
		volumeDir("/var/lib/kubelet", "------------------------------------"),
		volumeDir("/var/lib/kubelet", "0c6d6e1d9b3c4c2e8f0a1b2c3d4e5f6"),
	} {
		if uid, err := podUIDFromDir(dir); err == nil {
			t.Errorf("podUIDFromDir(%q) = %q, expected error", dir, uid)
		}
	}
}

func TestUnmountCleansUpUnderAnyKubeletRoot(t *testing.T) {
	useTempConfiguration(t)
	for _, root := range []string{"/var/lib/kubelet", "/var/snap/microk8s/common/var/lib/kubelet", "/var/lib/k0s/kubelet"} {
		workloadDir := filepath.Join(configuration.NodeAgentWorkloadHomeDir, testUID)
		credsFile := filepath.Join(configuration.NodeAgentCredentialsHomeDir, testUID+".json")
		if err := os.MkdirAll(workloadDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(credsFile, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := unmount(volumeDir(root, testUID)); err != nil {
			t.Fatalf("root %q: unmount: %v", root, err)
		}
		for _, p := range []string{workloadDir, credsFile} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("root %q: %s not removed", root, p)
			}
		}
	}
}

func useTempConfiguration(t *testing.T) {
	home := t.TempDir()
	prev := configuration
	configuration = &ConfigurationOptions{
		NodeAgentManagementHomeDir:  home,
		NodeAgentWorkloadHomeDir:    filepath.Join(home, "mount"),
		NodeAgentCredentialsHomeDir: filepath.Join(home, "creds"),
		LogLevel:                    LOG_LEVEL_WARN,
	}
	if err := os.MkdirAll(configuration.NodeAgentCredentialsHomeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration = prev })
}

func TestPathUnder(t *testing.T) {
	if p, err := pathUnder("/var/run/nodeagent/mount", "abc"); err != nil || p != "/var/run/nodeagent/mount/abc" {
		t.Errorf("pathUnder valid: got %q, %v", p, err)
	}
	for _, elem := range []string{"", ".", "..", "../x", "a/b", "/etc"} {
		if _, err := pathUnder("/var/run/nodeagent/mount", elem); err == nil {
			t.Errorf("pathUnder(%q): expected error", elem)
		}
	}
}
