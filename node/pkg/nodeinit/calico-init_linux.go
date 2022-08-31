// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

// Package nodeinit contains the calico-node -init command, which is intended to be run from
// an init container to do privileged pre-flight initialisation.  At present, it mounts
// the BPF filesystem so it is only useful for BPF mode.
package nodeinit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
)

func Run(bestEffort bool) {
	// Check $CALICO_STARTUP_LOGLEVEL to capture early log statements
	startup.ConfigureLogging()

	err := ensureBPFFilesystem()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount BPF filesystem.")
		if !bestEffort {
			os.Exit(2) // Using 2 just to distinguish from the usage error case.
		}
	}

	err = ensureCgroupV2Filesystem()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount cgroup2 filesystem.")
		if !bestEffort {
			os.Exit(3)
		}
	}
}

func ensureBPFFilesystem() error {
	// Check if the BPF filesystem is mounted at the expected location.
	logrus.Info("Checking if BPF filesystem is mounted.")
	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		mountPoint := parts[1]
		fs := parts[2]

		if mountPoint == bpf.DefaultBPFfsPath && fs == "bpf" {
			logrus.Info("BPF filesystem is mounted.")
			return nil
		}
	}
	if scanner.Err() != nil {
		return fmt.Errorf("failed to read /proc/mounts: %w", scanner.Err())
	}

	// If we get here, the BPF filesystem is not mounted.  Try to mount it.
	logrus.Info("BPF filesystem is not mounted. Trying to mount it...")
	err = syscall.Mount(bpf.DefaultBPFfsPath, bpf.DefaultBPFfsPath, "bpf", 0, "")
	if err != nil {
		return fmt.Errorf("failed to mount BPF filesystem: %w", err)
	}
	logrus.Info("Mounted BPF filesystem.")
	return nil
}

// ensureCgroupV2Filesystem() enters the cgroup and mount namespace of the process
// with PID 1 running on a host to allow felix running in calico-node to access the root of cgroup namespace.
// This is needed by felix to attach CTLB programs and implement k8s services correctly.
func ensureCgroupV2Filesystem() error {
	// Check if the Cgroup2 filesystem is mounted at the expected location.
	logrus.Info("Checking if cgroup2 filesystem is mounted.")
	mountInfoFile := "/nodeproc/1/mountinfo"
	mounts, err := os.Open(mountInfoFile)
	if err != nil {
		return fmt.Errorf("failed to open %s. err: %w", mountInfoFile, err)
	}
	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		// An example line in mountinfo file:
		// 35 24 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
		line := scanner.Text()
		mountPoint := strings.Split(line, " ")[4] // 4 is the index to mount points in mountinfo files

		extraInfo := strings.Split(line, " - ")
		if len(extraInfo) > 1 {
			fsType := strings.Split(extraInfo[1], " ")[0] // fsType is the first string after -

			if mountPoint == bpf.CgroupV2Path && fsType == "cgroup2" {
				logrus.Info("Cgroup2 filesystem is mounted.")
				return nil
			}
		}
	}
	if scanner.Err() != nil {
		return fmt.Errorf("failed to read %s: %w", mountInfoFile, scanner.Err())
	}

	// If we get here, the Cgroup2 filesystem is not mounted.  Try to mount it.
	logrus.Info("Cgroup2 filesystem is not mounted. Trying to mount it...")

	err = os.MkdirAll(bpf.CgroupV2Path, 0700)
	if err != nil {
		return fmt.Errorf("failed to prepare mount point: %v. err: %w.", bpf.CgroupV2Path, err)
	}
	logrus.Infof("Mount point %s is ready for mounting root cgroup2 fs.", bpf.CgroupV2Path)

	mountCmd := exec.Command("mountns", bpf.CgroupV2Path)
	out, err := mountCmd.Output()
	logrus.Debugf("Executed %v. err:%v out:\n%s", mountCmd, err, out)
	if err != nil {
		return fmt.Errorf("failed to mount cgroup2 filesystem: %w", err)
	}

	logrus.Infof("Mounted root cgroup2 filesystem.")
	return nil
}
