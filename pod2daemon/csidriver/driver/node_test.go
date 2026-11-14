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
	"path/filepath"
	"syscall"
	"testing"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/moby/sys/mountinfo"
	. "github.com/onsi/gomega"
)

const testVolumeID = "csi-test-volume"

func TestPublishTwiceMountsOnce(t *testing.T) {
	g := NewWithT(t)
	ns, target := setUpMountTest(t)

	// A kubelet restart publishes the volume of a running pod again.
	for range 2 {
		_, err := ns.NodePublishVolume(context.Background(), publishRequest(target))
		g.Expect(err).NotTo(HaveOccurred())
	}

	g.Expect(countMounts(t, target)).To(Equal(1))
	g.Expect(countMounts(t, filepath.Join(target, "nodeagent"))).To(Equal(1))

	_, err := ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(countMounts(t, target)).To(Equal(0))
}

func TestUnpublishRemovesStackedLayers(t *testing.T) {
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
}

func TestUnpublishUnmountedTarget(t *testing.T) {
	g := NewWithT(t)
	ns, target := setUpMountTest(t)

	// After a node reboot the target exists but nothing is mounted on it.
	g.Expect(os.MkdirAll(target, 0o777)).To(Succeed())
	_, err := ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())

	// The kubelet may also ask again after the target is gone.
	g.Expect(os.Remove(target)).To(Succeed())
	_, err = ns.NodeUnpublishVolume(context.Background(), unpublishRequest(target))
	g.Expect(err).NotTo(HaveOccurred())
}

// setUpMountTest returns a node service rooted in a temporary directory and the
// target path to publish to. It skips the test unless it can mount.
func setUpMountTest(t *testing.T) (*nodeService, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root; run with make -C pod2daemon ut")
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
