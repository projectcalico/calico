// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package markbits

import (
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"
)

// MarkBitsManager provides set of functions to manage an uint32 mark bits based on a given mark mask.
type MarkBitsManager struct {
	name             string
	mask             uint32
	numBitsAllocated int
	numFreeBits      int

	mutex sync.Mutex
}

func NewMarkBitsManager(markMask uint32, markName string) *MarkBitsManager {
	numBitsFound := 0
	for shift := uint(0); shift < 32; shift++ {
		bit := uint32(1) << shift
		if markMask&bit > 0 {
			numBitsFound += 1
		}
	}

	return &MarkBitsManager{
		name:             markName,
		mask:             markMask,
		numBitsAllocated: 0,
		numFreeBits:      numBitsFound,
	}
}

func (mc *MarkBitsManager) GetMask() uint32 {
	return mc.mask
}

// Allocate next mark bit.
func (mc *MarkBitsManager) NextSingleBitMark() (uint32, error) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mark, err := mc.nthMark(mc.numBitsAllocated)
	if err != nil {
		return 0, err
	}
	mc.numFreeBits--
	mc.numBitsAllocated++
	return mark, nil
}

func (mc *MarkBitsManager) AvailableMarkBitCount() int {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()
	return mc.numFreeBits
}

// Allocate a block of bits given a requested size.
// Performance is not a priority here since it is just a start of day operation.
// Return allocated mark and how many bits allocated.
// It is up to the caller to check the result.
func (mc *MarkBitsManager) NextBlockBitsMark(size int) (uint32, int) {
	mark := uint32(0)
	for allocated := 0; allocated < size; allocated++ {
		if bit, err := mc.NextSingleBitMark(); err != nil {
			log.WithFields(log.Fields{
				"Name":                   mc.name,
				"MarkMask":               mc.mask,
				"requestedMarkBlockSize": size,
			}).Warning("Not enough mark bits available.")

			// Return as many bits as possible.
			return mark, allocated
		} else {
			mark |= bit
		}
	}

	return mark, size
}

// Return Nth mark bit without allocation.
func (mc *MarkBitsManager) nthMark(n int) (uint32, error) {
	numBitsFound := 0
	for shift := uint(0); shift < 32; shift++ {
		candidate := uint32(1) << shift
		if mc.mask&candidate > 0 {
			if numBitsFound == n {
				return candidate, nil
			}
			numBitsFound++
		}
	}

	return 0, errors.New("No mark bit found")
}

// Return how many free position number left.
func (mc *MarkBitsManager) CurrentFreeNumberOfMark() int {
	if mc.numFreeBits > 0 {
		return int(uint64(1) << uint64(mc.numFreeBits))
	}
	return 0
}

// Return a mark given a position number.
func (mc *MarkBitsManager) MapNumberToMark(n int) (uint32, error) {
	number := uint32(n)
	mark := uint32(0)
	numBitsFound := uint32(0)
	for shift := uint(0); shift < 32 && number > 0; shift++ {
		candidate := uint32(1) << shift
		if mc.mask&candidate > 0 {
			value := number & (uint32(1) << numBitsFound)
			if value > 0 {
				mark |= candidate
				number -= value
			}
			numBitsFound++
		}
	}

	if number > 0 {
		log.WithFields(log.Fields{
			"Name":               mc.name,
			"MarkMask":           mc.mask,
			"requestedMapNumber": n,
		}).Warn("Not enough mark bits available.")
		return 0, errors.New("Not enough mark bits available")
	}

	return mark, nil
}

// Return a position number given a mark.
func (mc *MarkBitsManager) MapMarkToNumber(mark uint32) (int, error) {
	if mark&mc.mask != mark {
		// mark bit not compatible.
		return 0, errors.New("Mark bit not compatible")
	}

	number := 0
	numBitsFound := uint32(0)
	for shift := uint(0); shift < 32; shift++ {
		bit := uint32(1) << shift
		if mc.mask&bit > 0 {
			if bit&mark > 0 {
				number += int(uint32(1) << numBitsFound)
			}
			numBitsFound++
		}
	}

	return number, nil
}
