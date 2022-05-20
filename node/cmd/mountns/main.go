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
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
)

/*
#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>

__attribute__((constructor)) void set_namespaces(void) {
	setns(open("/initproc/ns/cgroup", O_RDONLY, 0), CLONE_NEWCGROUP);
	setns(open("/initproc/ns/mnt", O_RDONLY, 0), CLONE_NEWNS);
} */
import "C"

func main() {
	logrus.Info("Trying to mount root cgroup fs.")
	err := syscall.Mount("none", bpf.CgroupV2Path, "cgroup2", 0, "")
	if err != nil {
		logrus.WithError(err).Errorf("Failed to mount Cgroup filesystem.")
		os.Exit(1)
	}
	logrus.Info("Successfully mounted root cgroup fs.")
}
