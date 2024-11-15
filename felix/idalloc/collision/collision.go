// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/idalloc"
)

type checkpoint struct {
	prevCheckpoint uint64
	inverse        string
}

func main() {
	fmt.Println("Finding collision in the ID allocator hash function (this will take a while)...")

	logrus.SetLevel(logrus.InfoLevel)

	alloc := idalloc.New()
	hash := func(id string) uint64 {
		return alloc.TrialHash(id, 0)
	}

	for {
		idToInverse := map[uint64]checkpoint{}

		initialInput := fmt.Sprint(rand.Int63())
		initialID := hash(initialInput)
		id := initialID
		fmt.Println("Initial ID: ", initialID)

		prevCheckpoint := id
		i := 0
		for {
			input := strconv.FormatUint(id, 16)
			id = hash(input)
			if id == initialID {
				if input == initialInput {
					fmt.Println("Looped around to original input without a collision")
					break
				} else {
					fmt.Printf("Collision: f(%s) == f(%s) == %#x\n", input, initialInput, id)
				}
			}
			if (id % (2 << 24)) == 0 {
				c, ok := idToInverse[id]
				if ok {
					// Found a loop
					fmt.Printf("Found a loop ID=%#x checkpoint inverse=%s prevCheckpoint=%#x myLastCheckpoint=%#x myLastInverse=%s\n",
						id, c.inverse, c.prevCheckpoint, prevCheckpoint, idToInverse[prevCheckpoint].inverse)

					inverses := map[uint64]string{}
					id1 := prevCheckpoint
					for id1 != id {
						input := strconv.FormatUint(id1, 16)
						id1 = hash(input)
						inverses[id1] = input
					}
					id2 := c.prevCheckpoint
					for {
						input := strconv.FormatUint(id2, 16)
						id2 = hash(input)
						inverse, ok := inverses[id2]
						if ok {
							fmt.Printf("Found collision: f(%s) == f(%s) == %#x", inverse, input, id2)
							os.Exit(0)
						}
						inverses[id2] = input
					}
				}
				idToInverse[id] = checkpoint{
					prevCheckpoint: prevCheckpoint,
					inverse:        input,
				}
				fmt.Printf("Making checkpoint after %d iterations: f(%s) = %#x \n", i, input, id)
				prevCheckpoint = id
			}
			i++
		}
	}
}
