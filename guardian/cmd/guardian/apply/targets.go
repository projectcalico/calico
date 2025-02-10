// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package apply

import (
	"github.com/projectcalico/calico/guardian/pkg/config"
	"github.com/projectcalico/calico/guardian/pkg/server"
)

func Targets(cfg *config.Config) []server.TargetParam {
	return []server.TargetParam{
		{
			Path:         "/api/",
			Dest:         cfg.K8sEndpoint + ":6443",
			TokenPath:    "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token",
			CABundlePath: "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt",
		},
		{
			Path:         "/apis/",
			Dest:         cfg.K8sEndpoint + ":6443",
			TokenPath:    "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token",
			CABundlePath: "/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt",
		},
	}
}
