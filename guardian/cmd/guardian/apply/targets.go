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

const (
	defaultTokenPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCABundlePath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func targets(cfg *config.Config) []server.Target {
	//return []server.Target{
	//	server.MustCreateTarget("/api/", cfg.K8sEndpoint+":6443",
	//		server.WithToken("/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token"),
	//		server.WithCAPem("/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt")),
	//	server.MustCreateTarget("/apis/", cfg.K8sEndpoint+":6443",
	//		server.WithToken("/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/token"),
	//		server.WithCAPem("/home/brian-mcmahon/go-private/src/github.com/projectcalico/calico/guardian/ca.crt")),
	//}
	return []server.Target{
		server.MustCreateTarget("/api/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
		server.MustCreateTarget("/apis/", cfg.K8sEndpoint+":6443",
			server.WithToken(defaultTokenPath),
			server.WithCAPem(defaultCABundlePath)),
	}
}
