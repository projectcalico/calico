// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package maps

import (
	"context"
	"errors"
	"sync"
	"unsafe"
)

// ErrIterationFinished is returned by the Iterator's Next() method when there are no more keys.
var ErrIterationFinished = errors.New("iteration finished")

// ErrVisitedTooManyKeys is returned by the Iterator's Next() method if it sees
// many more keys than there should be in the map.
var ErrVisitedTooManyKeys = errors.New("visited 10x the max size of the map keys")

type keysValues struct {
	keys   []byte
	values []byte
	err    error
	count  int
}

// Iterator handles one pass of iteration over the map.
type Iterator struct {
	// Metadata about the map.
	mapFD      FD
	maxEntries int
	valueSize  int
	keySize    int

	// The values below point to the C heap.  We must allocate the key and value buffers
	// on the C heap because we pass them to the kernel as pointers contained in the
	// bpf_attr union.  That extra level of indirection defeats Go's special handling of
	// pointers when passing them to the syscall.  If we allocated the keys and values as
	// slices and the garbage collector decided to move the backing memory of the slices
	// then the pointers we write to the bpf_attr union could end up being stale (since
	// the union is opaque to the garbage collector).

	// keys points to a buffer containing up to IteratorNumKeys keys
	keysBuff    unsafe.Pointer
	keysBufSize int
	// values points to a buffer containing up to IteratorNumKeys values
	valuesBuff    unsafe.Pointer
	valuesBufSize int

	keys   []byte
	values []byte

	// valueStride is the step through the values buffer.  I.e. the size of the value
	// rounded up for alignment.
	valueStride int
	// keyStride is the step through the keys buffer.  I.e. the size of the key rounded up
	// for alignment.
	keyStride int
	// numEntriesLoaded is the number of valid entries in the key and values buffers.
	numEntriesLoaded int
	// entryIdx is the index of the next key/value to return.
	entryIdx int
	// numEntriesVisited is incremented for each entry that we visit.  Used as a sanity
	// check in case we go into an infinite loop.
	numEntriesVisited int

	// wg is to sync with the syscall executing thread on close
	wg                   sync.WaitGroup
	keysValues           chan keysValues
	cancelCtx            context.Context
	cancelCB             context.CancelFunc
	batchLookupSupported bool
}

type MapInfo struct {
	Type       int
	KeySize    int
	ValueSize  int
	MaxEntries int
	Id         int
}
