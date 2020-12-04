// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package idalloc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	log "github.com/sirupsen/logrus"
)

// IPSetIDAllocator allocates unique 64-bit IDs for the given string IDs.  It ensures uniqueness by tracking
// allocations in a map.  To minimise churn over restart, IDs are chosen by iterated hashing with collision detection.
// No-longer needed IDs must be released via the Release method or they will be leaked.
type IDAllocator struct {
	strToUint64 map[string]uint64
	uint64ToStr map[uint64]string

	buf []byte
}

func New() *IDAllocator {
	return &IDAllocator{
		strToUint64: map[string]uint64{},
		uint64ToStr: map[uint64]string{},
	}
}

func (a *IDAllocator) ReserveWellKnownID(id string, n uint64) {
	if _, exists := a.uint64ToStr[n]; exists {
		log.Panicf("ID %v already in use for well-known reservation '%v'", n, id)
	}
	if _, exists := a.strToUint64[id]; exists {
		log.Panicf("Already have well-known reservation '%v'", id)
	}
	a.uint64ToStr[n] = id
	a.strToUint64[id] = n
}

func (a *IDAllocator) TrialHash(id string, n uint64) uint64 {
	if len(a.buf) < 8+len(id) {
		a.buf = make([]byte, 8+len(id))
	}
	binary.LittleEndian.PutUint64(a.buf[:8], n)
	copy(a.buf[8:], id)
	hash := sha256.Sum256(a.buf)
	return binary.LittleEndian.Uint64(hash[:8])
}

func (a *IDAllocator) GetNoAlloc(id string) uint64 {
	if uid, ok := a.strToUint64[id]; ok {
		log.WithFields(log.Fields{"id": id, "uint64": uid}).Debug("Found existing IP set ID mapping")
		return uid
	}
	return 0
}

// GetOrAlloc returns the existing allocation for the given ID (if there is one), or allocates one if not.
func (a *IDAllocator) GetOrAlloc(id string) uint64 {
	debug := log.GetLevel() >= log.DebugLevel
	if uid, ok := a.strToUint64[id]; ok {
		if debug {
			log.WithFields(log.Fields{"id": id, "uint64": uid}).Debug("Found existing IP set ID mapping")
		}
		return uid
	}
	if debug {
		log.WithFields(log.Fields{"id": id}).Debug("No existing IP set ID mapping, allocating one...")
	}
	for n := uint64(0); n < math.MaxUint64; n++ {
		candidate := a.TrialHash(id, n)
		if candidate == 0 {
			if debug {
				log.WithField("id", id).Debug("Disallowing 0 as uint64 version of ID.")
			}
			continue
		}
		if _, idInUse := a.uint64ToStr[candidate]; idInUse {
			if debug {
				log.WithFields(log.Fields{"id": id, "n": n}).Debug("ID collision, will try next candidate.")
			}
			continue
		}
		a.uint64ToStr[candidate] = id
		a.strToUint64[id] = candidate
		if debug {
			log.WithFields(log.Fields{"id": id, "n": n, "uint64": candidate}).Debug("Found unused ID.")
		}
		return candidate
	}
	// Exhausting uint64 is quite unlikely.
	log.Panic("Ran out of candidates.")
	panic("Ran out of candidates.")
}

var ErrNotFound = errors.New("release of unknown ID")

func (a *IDAllocator) ReleaseUintID(id uint64) error {
	strID, ok := a.uint64ToStr[id]
	if !ok {
		return ErrNotFound
	}
	delete(a.uint64ToStr, id)
	delete(a.strToUint64, strID)
	return nil
}

// GetAndRelease releases the given IP set ID allocation and returns the old value, or 0 if the ID was not known.
func (a *IDAllocator) GetAndRelease(id string) uint64 {
	oldID, ok := a.strToUint64[id]
	if !ok {
		log.WithField("id", id).Warn("Asked to release unknown ID")
		return 0
	}
	delete(a.uint64ToStr, oldID)
	delete(a.strToUint64, id)
	return oldID
}
