// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

//go:build !linux

package nftables

import "sigs.k8s.io/knftables"

// readTablesViaNetlink reports no tables off Linux, where there is no nftables to clean up. The
// netlink client we use for the real read doesn't build anywhere else.
func readTablesViaNetlink(family knftables.Family, tables []string, onStillAlive func()) (map[string]*iptablesTableState, error) {
	return nil, nil
}
