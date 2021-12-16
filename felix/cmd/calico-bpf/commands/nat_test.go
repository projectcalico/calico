// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package commands

import (
	"fmt"
	"net"
	"testing"

	nat2 "github.com/projectcalico/calico/felix/bpf/nat"
)

func TestNATDump(t *testing.T) {
	nat := nat2.MapMem{
		nat2.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6):   nat2.NewNATValue(35, 2, 0, 0),
		nat2.NewNATKey(net.IPv4(2, 1, 1, 1), 553, 17): nat2.NewNATValue(107, 1, 0, 0),
		nat2.NewNATKey(net.IPv4(3, 1, 1, 1), 553, 17): nat2.NewNATValue(108, 1, 0, 0),
	}

	back := nat2.BackendMapMem{
		nat2.NewNATBackendKey(35, 0):  nat2.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		nat2.NewNATBackendKey(35, 1):  nat2.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		nat2.NewNATBackendKey(108, 0): nat2.NewNATBackendValue(net.IPv4(3, 3, 3, 3), 553),
	}

	dumpNice(func(format string, i ...interface{}) { fmt.Printf(format, i...) }, nat, back)
}
