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

package bpfutils

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"sync"

	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var memLockOnce sync.Once
var BTFEnabled bool

func init() {
	BTFEnabled = SupportsBTF()
}

func SupportsBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil {
		log.WithError(err).Debug("BTF not supported")
		return false
	}
	return true
}

func IncreaseLockedMemoryQuota() {
	memLockOnce.Do(func() {
		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
		if err != nil {
			log.WithError(err).Error("Failed to increase RLIMIT_MEMLOCK, loading BPF programs may fail")
		}
	})
}

var numbersRegex = regexp.MustCompile(`\d+`)

func PidOfLongestLivedProcess(procPath string) (int, error) {
	proc, err := ioutil.ReadDir(procPath)
	if err != nil {
		return -1, fmt.Errorf("error reading path %s %w", procPath, err)
	}
	for _, f := range proc {
		if f.IsDir() && numbersRegex.MatchString(f.Name()) {
			mountInfoPath := fmt.Sprintf("/proc/%s/mountinfo", f.Name())
			_, err := os.Stat(mountInfoPath)
			if err != nil {
				continue
			}
			pid, _ := strconv.Atoi(f.Name())
			return pid, nil
		}
	}
	return -1, fmt.Errorf("longest lived process not found")
}
