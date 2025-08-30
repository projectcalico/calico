// Copyright (c) 2025 NeuReality Ltd.
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

package dataplane

import "fmt"

type dataplaneDriverMultiplexer struct {
	primaryDriver   DataplaneDriver
	secondaryDriver DataplaneDriver
}

func (multiplexer dataplaneDriverMultiplexer) SendMessage(msg interface{}) error {
	secondaryErr := multiplexer.secondaryDriver.SendMessage(msg)
	primaryErr := multiplexer.primaryDriver.SendMessage(msg)

	if primaryErr != nil || secondaryErr != nil {
		fmt.Errorf("errors in sending message to drivers: primary driver error %w, secondary driver error %w",
			primaryErr, secondaryErr)
	}

	return nil
}

func (multiplexer dataplaneDriverMultiplexer) RecvMessage() (msg interface{}, err error) {
	return multiplexer.primaryDriver.RecvMessage() // receive message from the primary driver only
}
