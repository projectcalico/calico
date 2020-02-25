// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package cgroup

import (
	"fmt"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

func MaybeMoveToFelixCgroupv2() {
	cgroup := os.Getenv("FELIX_DEBUGBPFCGROUPV2")
	if cgroup != "" {
		log.WithField("cgroup", cgroup).Info("Moving to cgroup")
		cgroupPath := path.Join("/run/calico/cgroup/", cgroup)
		startTime := time.Now()
		for {
			if _, err := os.Stat(cgroupPath); err == nil {
				myPid := os.Getpid()
				file, err := os.OpenFile(path.Join(cgroupPath, "cgroup.procs"), os.O_WRONLY, 0700)
				if err != nil {
					log.WithError(err).Panic("Failed to open cgroup.procs")
				}
				_, err = file.WriteString(fmt.Sprint(myPid, "\n"))
				if err != nil {
					log.WithError(err).Panic("Failed to write cgroup")
				}
				err = file.Close()
				if err != nil {
					log.WithError(err).Panic("Failed to close cgroup")
				}
				break
			}
			if time.Since(startTime) > 10*time.Second {
				log.Panic("cgroup never appeared")
			}
			time.Sleep(time.Second)
		}
		log.WithField("cgroup", cgroup).Info("Moved to cgroup")
	}
}
