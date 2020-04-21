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

package routetable

import (
	"errors"

	"github.com/golang-collections/collections/stack"
	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

type RouteTableManager struct {
	tableIndexStack *stack.Stack
}

func NewRouteTableManager(routeTableRange v3.RouteTableRange) *RouteTableManager {
	r := &RouteTableManager{
		tableIndexStack: stack.New(),
	}
	// Push in reverse order so that the lowest index will come out first.
	for i := routeTableRange.Max; i >= routeTableRange.Min; i-- {
		r.tableIndexStack.Push(i)
	}
	return r
}

func (r *RouteTableManager) GrabIndex() (int, error) {
	if r.tableIndexStack.Len() == 0 {
		return 0, errors.New("No more routing tables available")
	}
	return r.tableIndexStack.Pop().(int), nil
}

func (r *RouteTableManager) ReleaseIndex(index int) {
	r.tableIndexStack.Push(index)
}
