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

package logutils

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/typha/pkg/config"
)

// getFileDestination is unsupported on non-Linux platforms: rotation-aware
// file writing relies on POSIX-specific primitives. Typha only runs on
// Linux; this stub exists so that the combined calico binary can be built
// for Windows (which imports this package transitively via node).
func getFileDestination(_ *config.Config, _ log.Level) (*logutils.Destination, error, error) {
	return nil, nil, errors.New("file logging is not supported on this platform")
}

// getSyslogDestination is unsupported on non-Linux platforms: Go's
// log/syslog package does not compile on Windows.
func getSyslogDestination(_ *config.Config, _ log.Level) (*logutils.Destination, error) {
	return nil, errors.New("syslog logging is not supported on this platform")
}
