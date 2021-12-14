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

package rules

import (
	"errors"
	"hash/fnv"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/markbits"
)

const (
	// Use an invalid interface name for non-cali endpoint.
	pseudoNonCaliEndpointName = "/cali/Pseudo/NonCali/Endpoint/"
)

// Endpoint Mark Mapper (EPM) provides set of functions to manage allocation/free endpoint mark bit
// given a mark bit mask. Note: This is not thread safe.
type EndpointMarkMapper interface {
	GetMask() uint32
	GetEndpointMark(ep string) (uint32, error)
	ReleaseEndpointMark(ep string)
	SetEndpointMark(ep string, mark uint32) error
}

type DefaultEPMarkManager struct {
	markBitsManager *markbits.MarkBitsManager
	maxPosition     int

	hash32 HashCalculator32

	activeEndpointToPosition map[string]int
	activeEndpointToMark     map[string]uint32
	activePositionToEndpoint map[int]string
	activeMarkToEndpoint     map[uint32]string
}

func NewEndpointMarkMapper(markMask, nonCaliMark uint32) EndpointMarkMapper {
	return NewEndpointMarkMapperWithShim(markMask, nonCaliMark, fnv.New32())
}

func NewEndpointMarkMapperWithShim(markMask, nonCaliMark uint32, hash32 HashCalculator32) EndpointMarkMapper {
	markBitsManager := markbits.NewMarkBitsManager(markMask, "endpoint-iptable-mark")

	epmm := &DefaultEPMarkManager{
		markBitsManager:          markBitsManager,
		maxPosition:              markBitsManager.CurrentFreeNumberOfMark(), // This includes zero
		hash32:                   hash32,
		activeEndpointToPosition: map[string]int{},
		activeEndpointToMark:     map[string]uint32{},
		activePositionToEndpoint: map[int]string{},
		activeMarkToEndpoint:     map[uint32]string{},
	}

	// Reserve nonCaliMark to pseudoNonCaliEndpoint. This mark is reserved for any traffic whose
	// incoming interface is neither a workload nor a host endpoint.
	err := epmm.SetEndpointMark(pseudoNonCaliEndpointName, nonCaliMark)
	if err != nil {
		log.WithFields(log.Fields{
			"MarkMask":    markMask,
			"NonCaliMark": nonCaliMark,
		}).Panic("Reserve non-cali endpoint mark failed.")
	}

	return epmm
}

func (epmm *DefaultEPMarkManager) GetMask() uint32 {
	return epmm.markBitsManager.GetMask()
}

func (epmm *DefaultEPMarkManager) GetEndpointMark(ep string) (uint32, error) {
	length := len(ep)
	if length == 0 {
		return 0, errors.New("Invalid endpoint name")
	}

	// Return current mark for Endpoint if it already has one.
	if mark, ok := epmm.activeEndpointToMark[ep]; ok {
		return mark, nil
	}

	// Try to allocate a position based on hash from endpoint name.
	_, err := epmm.hash32.Write([]byte(ep))
	if err != nil {
		return 0, errors.New("Failed to allocate a hash position")
	}

	total := int(epmm.hash32.Sum32())
	epmm.hash32.Reset()

	var prospect int
	gotOne := false
	for i := 0; i < epmm.maxPosition; i++ {
		prospect = (total + i) % epmm.maxPosition
		if prospect == 0 {
			// Make sure we get non zero position number.
			continue
		}
		_, alreadyAlloced := epmm.activePositionToEndpoint[prospect]
		if !alreadyAlloced {
			gotOne = true
			break
		}
	}

	if !gotOne {
		return 0, errors.New("No mark left for endpoint")
	}

	return epmm.allocateOnePosition(ep, prospect)
}

func (epmm *DefaultEPMarkManager) allocateOnePosition(ep string, pos int) (uint32, error) {
	mark, err := epmm.markBitsManager.MapNumberToMark(pos)
	if err != nil {
		return 0, err
	}
	epmm.setMark(ep, pos, mark)
	return mark, nil
}

func (epmm *DefaultEPMarkManager) ReleaseEndpointMark(ep string) {
	if mark, ok := epmm.activeEndpointToMark[ep]; ok {
		epmm.deleteMark(ep, epmm.activeEndpointToPosition[ep], mark)
	}
}

// This is used to set a mark for an endpoint from previous allocated mark.
// The endpoint should not have a mark already.
func (epmm *DefaultEPMarkManager) SetEndpointMark(ep string, mark uint32) error {
	if currentMark, ok := epmm.activeEndpointToMark[ep]; ok {
		// We got a endpoint with mark already.
		if currentMark != mark {
			return errors.New("Different mark already exists")
		}
		return nil
	}
	if currentEP, ok := epmm.activeMarkToEndpoint[mark]; ok {
		// We got a mark with endpoint already.
		if currentEP != ep {
			return errors.New("Endpoint with this mark already exists")
		}
		return nil
	}

	pos, err := epmm.markBitsManager.MapMarkToNumber(mark)
	if err != nil {
		return err
	}
	epmm.setMark(ep, pos, mark)
	return nil
}

func (epmm *DefaultEPMarkManager) deleteMark(ep string, pos int, mark uint32) {
	delete(epmm.activePositionToEndpoint, pos)
	delete(epmm.activeMarkToEndpoint, mark)
	delete(epmm.activeEndpointToPosition, ep)
	delete(epmm.activeEndpointToMark, ep)
}

func (epmm *DefaultEPMarkManager) setMark(ep string, pos int, mark uint32) {
	epmm.activePositionToEndpoint[pos] = ep
	epmm.activeEndpointToPosition[ep] = pos
	epmm.activeEndpointToMark[ep] = mark
	epmm.activeMarkToEndpoint[mark] = ep
}

// This interface has subset of functions of built in hash32 interface.
type HashCalculator32 interface {
	// Write (via the embedded io.Writer interface) adds more data to the running hash.
	// It never returns an error.
	io.Writer

	// Sum32 returns a hash result of uint32.
	// It does not change the underlying hash state.
	Sum32() uint32

	// Reset resets the Hash to its initial state.
	Reset()
}
