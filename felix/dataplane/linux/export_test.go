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

package intdataplane

// LiveMigrationListenerCount reports how many listeners - in production, endpoint
// managers - are registered with the live migration monitor.  There must be one per
// enabled IP version: with the IPv6 endpoint manager missing, IPv6 workload routes
// are neither suppressed on a migration target nor elevated after cutover.
func (d *InternalDataplane) LiveMigrationListenerCount() int {
	return len(d.liveMigrationMonitor.listeners)
}
