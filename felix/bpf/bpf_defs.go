// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package bpf

import (
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/asm"
)

type ProgFD uint32

func (f ProgFD) Close() error {
	log.WithField("fd", int(f)).Debug("Closing ProgFD")
	return unix.Close(int(f))
}

type ProgResult struct {
	RC       int32
	Duration time.Duration
	DataOut  []byte
}

// PolicyDebugInfo describes policy debug info
type PolicyDebugInfo struct {
	IfaceName  string    `json:"ifacename"`
	Hook       string    `json:"hook"`
	PolicyInfo asm.Insns `json:"policyInfo"`
	Error      string    `json:"error"`
}

const (
	RuntimeProgDir = "/var/run/calico/bpf/prog"
	RuntimePolDir  = "/var/run/calico/bpf/policy"
)
