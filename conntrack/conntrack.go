// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"net"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
)

var conntrackDirections = []string{
	"--orig-src",
	"--orig-dst",
	"--reply-src",
	"--reply-dst",
}

const numRetries = 3

type Conntrack struct {
	newCmd newCmd
}

func New() *Conntrack {
	return NewWithCmdShim(func(name string, arg ...string) CmdIface {
		return exec.Command(name, arg...)
	})
}

// NewWithCmdShim is a test constructor that allows for shimming exec.Command.
func NewWithCmdShim(newCmd newCmd) *Conntrack {
	return &Conntrack{
		newCmd: newCmd,
	}
}

type newCmd func(name string, arg ...string) CmdIface

type CmdIface interface {
	CombinedOutput() ([]byte, error)
}

func (c Conntrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	var family string
	switch ipVersion {
	case 4:
		family = "ipv4"
	case 6:
		family = "ipv6"
	default:
		log.WithField("version", ipVersion).Panic("Unknown IP version")
	}
	log.WithField("ip", ipAddr).Info("Removing conntrack flows")
	for _, direction := range conntrackDirections {
		logCxt := log.WithFields(log.Fields{"ip": ipAddr, "direction": direction})
		// Retry a few times because the conntrack command seems to fail at random.
		for retry := 0; retry <= numRetries; retry += 1 {
			cmd := c.newCmd("conntrack",
				"--family", family,
				"--delete", direction,
				ipAddr.String())
			output, err := cmd.CombinedOutput()
			if err == nil {
				logCxt.Debug("Successfully removed conntrack flows.")
				break
			}
			if strings.Contains(string(output), "0 flow entries") {
				// Success, there were no flows.
				logCxt.Debug("IP wasn't in conntrack")
				break
			}
			if retry == numRetries {
				logCxt.WithError(err).Error("Failed to remove conntrack flows after retries.")
			} else {
				logCxt.WithError(err).Warn("Failed to remove conntrack flows, will retry...")
			}
		}
	}
}
