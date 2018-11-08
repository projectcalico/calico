// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
package calico

import (
	"os"
	"strings"
)

type routeGenerator struct {
	client *client
}

func NewRouteGenerator(c *client) (rg *routeGenerator, err error) {
	rg = &routeGenerator{client: c}
	return
}

func (rg *routeGenerator) Start() (err error) {
	// MVP implementation: read CIDRs to advertise,
	// comma-separated, from an environment variable
	// CALICO_STATIC_ROUTES.
	routeString := os.Getenv("CALICO_STATIC_ROUTES")
	cidrs := []string{}
	for _, route := range strings.Split(routeString, ",") {
		cidr := strings.TrimSpace(route)
		if cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	rg.client.updateRoutes(cidrs)
	return
}
