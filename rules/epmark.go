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
	"hash"
	"hash/fnv"

	"github.com/projectcalico/felix/markbits"
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

	hash32 hash.Hash32

	activeEndpointToPosition map[string]int
	activeEndpointToMark     map[string]uint32
	activePositionToEndpoint map[int]string
}

func NewEndpointMarkMapper(markMask uint32) EndpointMarkMapper {
	markBitsManager := markbits.NewMarkBitsManager(markMask, "endpoint-iptable-mark")

	return &DefaultEPMarkManager{
		markBitsManager: markBitsManager,
		maxPosition:     markBitsManager.CurrentFreeNumberOfMark(), // This includes zero
		hash32:          fnv.New32(),
		activeEndpointToPosition: map[string]int{},
		activeEndpointToMark:     map[string]uint32{},
		activePositionToEndpoint: map[int]string{},
	}
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
	epmm.hash32.Write([]byte(ep))
	total := int(epmm.hash32.Sum32())

	var prospect int
	for i := 0; i < epmm.maxPosition; i++ {
		prospect = (total + i) % epmm.maxPosition
		if prospect == 0 {
			// Make sure we get non zero position number.
			continue
		}
		_, alreadyAlloced := epmm.activePositionToEndpoint[prospect]
		if !alreadyAlloced {
			break
		}
	}

	mark, err := epmm.markBitsManager.MapNumberToMark(prospect)
	if err != nil {
		return 0, err
	}
	epmm.setMark(ep, prospect, mark)
	return mark, nil
}

func (epmm *DefaultEPMarkManager) ReleaseEndpointMark(ep string) {
	if pos, ok := epmm.activeEndpointToPosition[ep]; ok {
		delete(epmm.activeEndpointToPosition, ep)
		delete(epmm.activeEndpointToMark, ep)
		delete(epmm.activePositionToEndpoint, pos)
	}
}

// This is used to set a mark for an endpoint from previous allocated mark.
// The endpoint should not have a mark already.
func (epmm *DefaultEPMarkManager) SetEndpointMark(ep string, mark uint32) error {
	if current, ok := epmm.activeEndpointToMark[ep]; ok {
		// We got a mark already.
		if current != mark {
			return errors.New("Different mark already exists")
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

func (epmm *DefaultEPMarkManager) setMark(ep string, pos int, mark uint32) {
	epmm.activePositionToEndpoint[pos] = ep
	epmm.activeEndpointToPosition[ep] = pos
	epmm.activeEndpointToMark[ep] = mark
}
