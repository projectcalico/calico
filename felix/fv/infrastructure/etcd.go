// Copyright (c) 2017-2018,2020 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"fmt"
	"os"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

func RunEtcd() *containers.Container {
	args := []string{
			"--privileged", // So that we can add routes inside the etcd container,
			// when using the etcd container to model an external client connecting
			// into the cluster.
			utils.Config.EtcdImage,
			"etcd",
			"--advertise-client-urls", "http://127.0.0.1:2379",
			"--listen-client-urls", "http://0.0.0.0:2379"}
        arch := os.Getenv("ARCH")
        if len(arch) == 0 {
                log.Info("ARCH env is not defined, set it to amd64")
                arch = "amd64"
        }
	if arch != "amd64" {
		args = append([]string{"-e", fmt.Sprintf("ETCD_UNSUPPORTED_ARCH=%s",arch)},
					args...)
	}

	log.Info("Starting etcd")
	return containers.Run("etcd",
		containers.RunOpts{
			AutoRemove: true,
			StopSignal: "SIGKILL",
		},
		args...)
}
