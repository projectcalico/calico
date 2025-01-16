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

type dataplaneDriverDecorator struct {
     primaryDriver DataplaneDriver
     secondaryDriver DataplaneDriver 
}

func (decorator dataplaneDriverDecorator) SendMessage(msg interface{}) error {
     decorator.secondaryDriver.SendMessage(msg)
     return decorator.primaryDriver.SendMessage(msg) // return message from the primary driver only
}

func (decorator dataplaneDriverDecorator) RecvMessage() (msg interface{}, err error) {
     return decorator.primaryDriver.RecvMessage() // receive message from the primary driver only
}
