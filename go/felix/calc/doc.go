// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

// The calc package implements a calculation graph for Felix's dynamic state.
// The graph filters and transforms updates from the backend Syncer into a
// stream of host-specific updates to policies, profiles, endpoints and IP
// sets.
//
// The graph is available either with a synchronous callback API or as a
// channel-based async API.  The async version of the API  is recommended
// because it includes and EventBuffer to efficiently batch IP set updates.
// In addition, it converts the callbacks into structs from the felix/proto
// package, which are ready to be marshaled directly to the felix front-end.
//
// 	// Using the async API.
// 	asyncCalcGraph := calc.NewAsyncCalcGraph("hostname", outputChannel)
// 	syncer := fc.datastore.Syncer(asyncCalcGraph)
// 	syncer.Start()
// 	asyncCalcGraph.Start()
//	for event := range outputChannel {
//		switch event := event.(type) {
//		case *proto.XYZ:
//			...
//		...
//	}
package calc
