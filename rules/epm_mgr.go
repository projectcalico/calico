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
	"sync"

	"github.com/projectcalico/felix/markbits"
)

// Endpoint Mark Manager (EPM) provides set of functions to manage allocation/free endpoint mark bit
// given a mark bit mask.
type EndPointMarkManager struct {
	markBitsManager *markbits.MarkBitsManager
	maxPosition     int

	activeEndpointToPosition map[string]int
	activePositionToEndpoint map[int]string

	mutex sync.Mutex
}

func NewEndPointMarkManager(markMask uint32) *EndPointMarkManager {
	markBitsManager := markbits.NewMarkBitsManager(markMask, "endpoint-iptable-mark")

	return &EndPointMarkManager{
		markBitsManager:          markBitsManager,
		maxPosition:              markBitsManager.CurrentFreeNumberOfMark(), // This includes zero
		activeEndpointToPosition: map[string]int{},
		activePositionToEndpoint: map[int]string{},
	}
}

func (epmm *EndPointMarkManager) GetEndPointMark(ep string) (uint32, error) {
	length := len(ep)
	if length == 0 {
		return 0, errors.New("Invalid endpoint name")
	}

	epmm.mutex.Lock()
	defer epmm.mutex.Unlock()

	// Return current mark for EndPoint if it already has one.
	if pos, ok := epmm.activeEndpointToPosition[ep]; ok {
		mark := epmm.markBitsManager.MapNumberToMark(pos)
		if mark == 0 {
			return 0, errors.New("Not enough mark bits available")
		}
		return mark, nil
	}

	// Try to allocate a position based on a simple hash from endpoint name.
	// Make sure we are likely to get a good performance based on average 10 to 50 pods per node.

	// Take last two bytes or one byte from name and take the modulus of max position.
	var total int
	bytes := []byte(ep)
	if length >= 2 {
		total = int(uint32(bytes[length-2])<<8 + uint32(bytes[length-1]))
	} else {
		total = int(bytes[length-1])
	}
	prospect := total % epmm.maxPosition //Get hash position prospect
	if prospect == 0 {
		// Make sure it is not zero
		prospect++
	}

	if _, alloced := epmm.activePositionToEndpoint[prospect]; alloced {
		// We got a collision, prospect position has been allocated. Walk through and find an empty position.
		for i := 0; i < epmm.maxPosition && alloced; i++ {
			prospect++
			if prospect >= epmm.maxPosition {
				prospect = 1 // Make sure it is not zero
			}

			_, alloced = epmm.activePositionToEndpoint[prospect]
		}

		if alloced {
			return 0, errors.New("No mark position left")
		}
	}

	epmm.activePositionToEndpoint[prospect] = ep
	epmm.activeEndpointToPosition[ep] = prospect
	mark := epmm.markBitsManager.MapNumberToMark(prospect)
	if mark == 0 {
		return 0, errors.New("Not enough mark bits available")
	}
	return mark, nil
}

func (epmm *EndPointMarkManager) RemoveEndPointMark(ep string) {
	epmm.mutex.Lock()
	defer epmm.mutex.Unlock()

	if _, ok := epmm.activeEndpointToPosition[ep]; ok {
		pos := epmm.activeEndpointToPosition[ep]
		delete(epmm.activeEndpointToPosition, ep)
		delete(epmm.activePositionToEndpoint, pos)
	}
}

func (epmm *EndPointMarkManager) SetEndPointMark(ep string, mark uint32) {
	epmm.mutex.Lock()
	defer epmm.mutex.Unlock()

	pos := epmm.markBitsManager.MapMarkToNumber(mark)
	epmm.activePositionToEndpoint[pos] = ep
	epmm.activeEndpointToPosition[ep] = pos
}
