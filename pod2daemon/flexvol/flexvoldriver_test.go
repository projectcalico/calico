// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
