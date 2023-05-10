//go:build windows

// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ipv4

import (
	"errors"
	"net"

	log "github.com/sirupsen/logrus"
)

// GetDefaultIPv4Pool detects host interfaces and selects default IP pool without overlapping
func GetDefaultIPv4Pool(preferedPool *net.IPNet) (*net.IPNet, error) {
	log.Debug("getting default pool based on host interface unsupported on this OS")
	return nil, errors.New("getting default pool based on host interface unsupported on this OS")
}
