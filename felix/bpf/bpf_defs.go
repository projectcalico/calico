// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type MapFD uint32

func (f MapFD) Close() error {
	log.WithField("fd", int(f)).Debug("Closing MapFD")
	return unix.Close(int(f))
}

type ProgFD uint32

func (f ProgFD) Close() error {
	log.WithField("fd", int(f)).Debug("Closing ProgFD")
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
	Type       int
	KeySize    int
	ValueSize  int
	MaxEntries int
}

const (
	ObjectDir      = "/usr/lib/calico/bpf"
	RuntimeProgDir = "/var/run/calico/bpf/prog"
	RuntimePolDir  = "/var/run/calico/bpf/pol"
)

// ErrIterationFinished is returned by the MapIterator's Next() method when there are no more keys.
var ErrIterationFinished = errors.New("iteration finished")

// ErrVisitedTooManyKeys is returned by the MapIterator's Next() method if it sees many more keys than there should
// be in the map.
var ErrVisitedTooManyKeys = errors.New("visited 10x the max size of the map keys")
