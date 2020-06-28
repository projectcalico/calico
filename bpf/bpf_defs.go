// +build !windows

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

// Copyright (c) 2020  All rights reserved.

package bpf

import (
	"time"

	"golang.org/x/sys/unix"
)

type MapFD uint32

func (f MapFD) Close() error {
	return unix.Close(int(f))
}

type ProgFD uint32

func (f ProgFD) Close() error {
	return unix.Close(int(f))
}

func IsNotExists(err error) bool {
	return err == unix.ENOENT
}

type ProgResult struct {
	RC       int32
	Duration time.Duration
	DataOut  []byte
}

type MapInfo struct {
	Type      int
	KeySize   int
	ValueSize int
}

const ObjectDir = "/usr/lib/calico/bpf"
