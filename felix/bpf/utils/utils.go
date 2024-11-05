// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

// Package bpf provides primitives to manage Calico-specific XDP programs
// attached to network interfaces, along with the blocklist LPM map and the
// failsafe map.
//
// It does not call the bpf() syscall itself but executes external programs
// like bpftool and ip.

package utils

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
)

func MaybeMountBPFfs() (string, error) {
	var err error
	bpffsPath := bpfdefs.DefaultBPFfsPath

	mnt, err := isMount(bpfdefs.DefaultBPFfsPath)
	if err != nil {
		return "", err
	}

	fsBPF, err := isBPF(bpfdefs.DefaultBPFfsPath)
	if err != nil {
		return "", err
	}

	if !mnt {
		err = mountBPFfs(bpfdefs.DefaultBPFfsPath)
	} else if !fsBPF {
		var runfsBPF bool

		bpffsPath = "/var/run/calico/bpffs"

		if err := os.MkdirAll(bpffsPath, 0700); err != nil {
			return "", err
		}

		runfsBPF, err = isBPF(bpffsPath)
		if err != nil {
			return "", err
		}

		if !runfsBPF {
			err = mountBPFfs(bpffsPath)
		}
	}

	return bpffsPath, err
}

func MaybeMountCgroupV2() (string, error) {
	var err error
	cgroupV2Path := bpfdefs.GetCgroupV2Path()
	if err := os.MkdirAll(cgroupV2Path, 0700); err != nil {
		return "", err
	}

	mnt, err := isMount(cgroupV2Path)
	if err != nil {
		return "", fmt.Errorf("error checking if %s is a mount: %v", cgroupV2Path, err)
	}

	fsCgroup, err := isCgroupV2(cgroupV2Path)
	if err != nil {
		return "", fmt.Errorf("error checking if %s is CgroupV2: %v", cgroupV2Path, err)
	}

	if !mnt {
		err = mountCgroupV2(cgroupV2Path)
	} else if !fsCgroup {
		err = fmt.Errorf("something that's not cgroup v2 is already mounted in %s", cgroupV2Path)
	}

	return cgroupV2Path, err
}

func mountCgroupV2(path string) error {
	return syscall.Mount(path, path, "cgroup2", 0, "")
}

func isBPF(path string) (bool, error) {
	var fsdata unix.Statfs_t
	if err := unix.Statfs(path, &fsdata); err != nil {
		return false, fmt.Errorf("%s is not mounted", path)
	}

	return uint32(fsdata.Type) == uint32(unix.BPF_FS_MAGIC), nil
}

func isCgroupV2(path string) (bool, error) {
	var fsdata unix.Statfs_t
	if err := unix.Statfs(path, &fsdata); err != nil {
		return false, fmt.Errorf("%s is not mounted", path)
	}

	return uint32(fsdata.Type) == uint32(unix.CGROUP2_SUPER_MAGIC), nil
}

func mountBPFfs(path string) error {
	return syscall.Mount(path, path, "bpf", 0, "")
}

func isMount(path string) (bool, error) {
	procPath := "/proc/self/mountinfo"

	mi, err := os.Open(procPath)
	if err != nil {
		return false, err
	}
	defer mi.Close()

	sc := bufio.NewScanner(mi)

	for sc.Scan() {
		line := sc.Text()
		columns := strings.Split(line, " ")
		if len(columns) < 7 {
			return false, fmt.Errorf("not enough fields from line %q: %+v", line, columns)
		}

		mountPoint := columns[4]
		if filepath.Clean(mountPoint) == filepath.Clean(path) {
			return true, nil
		}
	}

	return false, nil
}

func RemoveBPFSpecialDevices() {
	bpfin, err := netlink.LinkByName(dataplanedefs.BPFInDev)
	if err != nil {
		var lnf netlink.LinkNotFoundError
		if errors.As(err, &lnf) {
			return
		}
		log.WithError(err).Warnf("Failed to make sure that %s/%s device is (not) present.", dataplanedefs.BPFInDev, dataplanedefs.BPFOutDev)
		return
	}

	err = netlink.LinkDel(bpfin)
	if err != nil {
		log.WithError(err).Warnf("Failed to remove %s/%s device.", dataplanedefs.BPFInDev, dataplanedefs.BPFOutDev)
	}
}
