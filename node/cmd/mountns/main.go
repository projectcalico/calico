//go:build cgo

// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package main

import (
	"fmt"
	"os"
	"syscall"
)

// As more systems adopt cgroup2, k8s started to containerize each pod in a separate cgroup.
// This change prevents felix from attaching CTLB programs to cgroup ns correctly. To fix the issue,
// we need to mount root cgroup at /run/calico/cgroup (where felix expects it), not the one
// allocated by k8s to calico-node. This binary takes the following steps to solve it:
// - Enter the namespace root before mounting cgroup2 fs. (Usually, /proc/1/ns points to
//   the root of all namespaces, however, we mount /proc/1 on host at /initproc on calico-node pod,
//   so /initproc/ns is the root of namespaces.)
// - Mount root cgroups fs at /run/calico/cgroup.

// The following C code is executed as a cgo constructor which runs before the main function.
// The reason for this behavior is to set cgroup and mount namespace correctly, before mounting
// cgroup2 fs in the main function. Mount ns can only be changed in a single-thread process,
// so we need to change it by exploiting cgo constructor before Go runtime starts new threads.

// In addition, normal frameworks, like logrus, are not used in the go code to prevent:
// - any unexpected initialisation logic. This is important for setting mount ns
//   correctly, as mentioned above.
// - unnecessary increase of the binary size, which currently is less than 2MB.

/*
#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>

__attribute__((constructor)) void set_namespaces(void) {
	// open /initproc/ns/cgroup, which is equivalent to /proc/1/ns/cgroup on host.
	// Then run setns syscall to change the cgroup namespace to this value.
	setns(open("/initproc/ns/cgroup", O_RDONLY, 0), CLONE_NEWCGROUP);

	// open /initproc/ns/mnt, which is equivalent to /proc/1/ns/mnt on host.
	// Then run setns syscall to change the mount namespace to this value.
	setns(open("/initproc/ns/mnt", O_RDONLY, 0), CLONE_NEWNS);
} */
import "C"

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <mountpoint>\n", os.Args[0])
		os.Exit(1)
	}
	mountPoint := os.Args[1]
	fmt.Println("Trying to mount root cgroup fs.")
	err := syscall.Mount("none", mountPoint, "cgroup2", 0, "")
	if err != nil {
		fmt.Printf("Failed to mount Cgroup filesystem. err: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Successfully mounted root cgroup fs.")
}
