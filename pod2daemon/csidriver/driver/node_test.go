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

package driver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/moby/sys/mountinfo"
	. "github.com/onsi/gomega"
)

const (
	testVolumeID = "csi-test-volume"

	// Set in the child process that inMountNamespace starts.
	mountNamespaceEnv = "CSIDRIVER_TEST_IN_MOUNT_NAMESPACE"
)

func TestPublishTwiceMountsOnce(t *testing.T) {
	if !inMountNamespace(t) {
		return
	}
	g := NewWithT(t)
	ns, target := setUpMountTest(t)
	workloadDir := filepath.Join(ns.config.NodeAgentWorkloadHomeDir, testVolumeID)

	_, err := ns.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	// Stands in for the socket the node agent creates for the workload.
	g.Expect(os.WriteFile(filepath.Join(workloadDir, "socket"), nil, 0o600)).To(Succeed())

	// A kubelet restart publishes the volume of a running pod again.
	_, err = ns.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(countMounts(t, target)).To(Equal(1))
	g.Expect(countMounts(t, filepath.Join(target, "nodeagent"))).To(Equal(1))
	g.Expect(filepath.Join(target, "nodeagent", "socket")).To(BeAnExistingFile())
	g.Expect(credsFile(ns)).To(BeAnExistingFile())

	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(countMounts(t, target)).To(Equal(0))
	g.Expect(workloadDir).NotTo(BeADirectory())
	g.Expect(credsFile(ns)).NotTo(BeAnExistingFile())
}

func TestUnpublishRemovesStackedLayers(t *testing.T) {
	if !inMountNamespace(t) {
		return
	}
	g := NewWithT(t)
	ns, target := setUpMountTest(t)

	_, err := ns.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	// Stack two more layers the way a driver that mounted on every publish did.
	workloadDir := filepath.Join(ns.config.NodeAgentWorkloadHomeDir, testVolumeID)
	for range 2 {
		g.Expect(syscall.Mount("tmpfs", target, "tmpfs", 0, "size=8K")).To(Succeed())
		g.Expect(os.Mkdir(filepath.Join(target, "nodeagent"), 0o777)).To(Succeed())
		g.Expect(syscall.Mount(workloadDir, filepath.Join(target, "nodeagent"), "", syscall.MS_BIND, "")).To(Succeed())
	}
	g.Expect(countMounts(t, target)).To(Equal(3))

	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(countMounts(t, target)).To(Equal(0))
	g.Expect(countMounts(t, filepath.Join(target, "nodeagent"))).To(Equal(0))
	g.Expect(workloadDir).NotTo(BeADirectory())
	g.Expect(credsFile(ns)).NotTo(BeAnExistingFile())
}

func TestUnpublishFailsWhileTargetIsBusy(t *testing.T) {
	if !inMountNamespace(t) {
		return
	}
	g := NewWithT(t)
	ns, target := setUpMountTest(t)
	workloadDir := filepath.Join(ns.config.NodeAgentWorkloadHomeDir, testVolumeID)

	_, err := ns.NodePublishVolume(context.Background(), publishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	// An open file keeps the tmpfs busy, so it cannot be unmounted.
	busy, err := os.Create(filepath.Join(target, "busy"))
	g.Expect(err).NotTo(HaveOccurred())
	defer func() { _ = busy.Close() }()

	// The kubelet takes success to mean the target is gone, so this must fail.
	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).To(HaveOccurred())
	g.Expect(countMounts(t, target)).To(Equal(1))
	g.Expect(workloadDir).To(BeADirectory())
	g.Expect(credsFile(ns)).To(BeAnExistingFile())

	// The kubelet retries. The first attempt already removed the inner bind mount.
	g.Expect(busy.Close()).To(Succeed())
	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(countMounts(t, target)).To(Equal(0))
	g.Expect(workloadDir).NotTo(BeADirectory())
	g.Expect(credsFile(ns)).NotTo(BeAnExistingFile())
}

func TestUnpublishAfterNodeReboot(t *testing.T) {
	if !inMountNamespace(t) {
		return
	}
	g := NewWithT(t)
	ns, target := setUpMountTest(t)

	// A reboot drops the mounts and the pod info file, but the target directory stays.
	g.Expect(os.MkdirAll(target, 0o777)).To(Succeed())
	_, err := ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())

	// The kubelet may also ask again after it removed the target.
	g.Expect(os.Remove(target)).To(Succeed())
	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
}

// inMountNamespace reports whether the test is running where it may mount. If
// not, it re-runs the test in a child process with its own mount namespace and
// returns false, so that the caller returns and the child's result stands.
//
// The child is root in a new user namespace unless the test already runs as
// root, so the tests need no privileges and never touch the host's mounts.
func inMountNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv(mountNamespaceEnv) != "" {
		return true
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), mountNamespaceEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	if os.Geteuid() != 0 {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}

	out, err := cmd.CombinedOutput()
	t.Logf("output of the test in its own mount namespace:\n%s", out)
	if err != nil {
		// Fail rather than skip: a skipped mount test looks like a pass.
		t.Fatalf("test failed, or could not start in a new mount namespace (needs root or unprivileged user namespaces): %v", err)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("%s did not run in the child process", t.Name())
	}
	return false
}

// setUpMountTest returns a node service rooted in a temporary directory and the
// target path to publish to.
func setUpMountTest(t *testing.T) (*nodeService, string) {
	t.Helper()

	// Mounts made here must not propagate out of the test's namespace.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatalf("failed to make mounts private: %v", err)
	}

	root := t.TempDir()
	cfg := &ConfigurationOptions{
		NodeAgentManagementHomeDir:  filepath.Join(root, "nodeagent"),
		NodeAgentWorkloadHomeDir:    filepath.Join(root, "nodeagent", "mount"),
		NodeAgentCredentialsHomeDir: filepath.Join(root, "nodeagent", "creds"),
	}
	if err := os.MkdirAll(cfg.NodeAgentManagementHomeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "pod", "volumes", "kubernetes.io~csi", "felix-sync", "mount")

	// Detach anything a failed test leaves behind, so TempDir cleanup can remove it.
	t.Cleanup(func() {
		for range 5 {
			_ = syscall.Unmount(filepath.Join(target, "nodeagent"), syscall.MNT_DETACH)
			_ = syscall.Unmount(target, syscall.MNT_DETACH)
		}
	})
	return &nodeService{config: cfg}, target
}

func publishRequest(target string) *csi.NodePublishVolumeRequest {
	return &csi.NodePublishVolumeRequest{
		VolumeId:   testVolumeID,
		TargetPath: target,
		VolumeContext: map[string]string{
			"csi.storage.k8s.io/pod.name":            "test-pod",
			"csi.storage.k8s.io/pod.namespace":       "test-ns",
			"csi.storage.k8s.io/pod.uid":             "abc-def-123-456",
			"csi.storage.k8s.io/serviceAccount.name": "test-sa",
		},
	}
}

func unpublishRequest(target string) *csi.NodeUnpublishVolumeRequest {
	return &csi.NodeUnpublishVolumeRequest{VolumeId: testVolumeID, TargetPath: target}
}

func credsFile(ns *nodeService) string {
	return filepath.Join(ns.config.NodeAgentCredentialsHomeDir, testVolumeID+".json")
}

// countMounts returns the number of mounts stacked at path.
func countMounts(t *testing.T, path string) int {
	t.Helper()
	mounts, err := mountinfo.GetMounts(func(i *mountinfo.Info) (skip, stop bool) {
		return i.Mountpoint != path, false
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(mounts)
}
