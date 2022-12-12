// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multireadbuf

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
)

var interestingSizes = []int{
	0, 1, 10, 100, 1000,
	defaultFlushThreshold - 1,
	defaultFlushThreshold,
	defaultFlushThreshold + 1,
	defaultFlushThreshold * 2,
}

func TestSimpleWriteThenRead(t *testing.T) {
	for _, size := range interestingSizes {
		t.Run(fmt.Sprintf("writeSize: %d", size), func(t *testing.T) {
			mrb := New(0)
			data := generateData(size)
			n, err := mrb.Write(data)
			if err != nil {
				t.Errorf("Write returned unexpected error: %v", err)
			}
			if n != len(data) {
				t.Errorf("Incorrect write length: got %d, expected %d", n, len(data))
			}
			if err := mrb.Close(); err != nil {
				t.Fatalf("Close returned unexpected error: %v", err)
			}
			if out, err := io.ReadAll(mrb.Reader()); err != nil {
				t.Fatalf("Reader returned unexpected error: %v", err)
			} else if !reflect.DeepEqual(out, data) {
				t.Fatalf("Reader returned incorrect data: got %x, expected %x", out, data)
			}
			t.Log("Second reader should return same values...")
			if out, err := io.ReadAll(mrb.Reader()); err != nil {
				t.Fatalf("Second Reader returned unexpected error: %v", err)
			} else if !reflect.DeepEqual(out, data) {
				t.Fatalf("Second Reader returned incorrect data: got %x, expected %x", out, data)
			}
		})
	}
}

func BenchmarkNReaders(b *testing.B) {
	for _, writeTo := range []bool{false, true} {
		for _, n := range []int{1, 10, 100, 1000} {
			name := fmt.Sprintf("%dReaders", n)
			if writeTo {
				name += "WriteTo"
			}
			b.Run(name, func(b *testing.B) {
				benchmarkNReaders(b, n, writeTo)
			})
		}
	}
}

func benchmarkNReaders(b *testing.B, numReaders int, writeTo bool) {
	for j := 0; j < b.N; j++ {
		b.StopTimer()
		mrb := New(0)
		data := generateData(1024*1024 + 27)
		b.SetBytes(int64(numReaders * len(data)))

		var wg sync.WaitGroup
		results := make([]struct {
			out []byte
			err error
		}, numReaders)
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			if writeTo {
				// Use the WriteTo() method, which avoids copies.
				go func(i int) {
					defer wg.Done()
					var buf bytes.Buffer
					r := mrb.Reader()
					n, err := r.WriteTo(&buf)
					if n != int64(buf.Len()) {
						results[i].err = fmt.Errorf("incorrect n: %d", n)
					} else {
						results[i].out = buf.Bytes()
						results[i].err = err
					}
				}(i)
			} else {
				// Use io.ReadAll()
				go func(i int) {
					defer wg.Done()
					r := mrb.Reader()
					results[i].out, results[i].err = io.ReadAll(r)
				}(i)
			}
		}

		b.StartTimer()

		remainingData := data
		for len(remainingData) > 0 {
			wrSize := 1000
			if wrSize > len(remainingData) {
				wrSize = len(remainingData)
			}
			n, err := mrb.Write(remainingData[:wrSize])
			if err != nil {
				b.Fatalf("Write returned unexpected error: %v", err)
			}
			if n != wrSize {
				b.Fatalf("Incorrect write length: got %d, expected %d", n, wrSize)
			}
			remainingData = remainingData[wrSize:]
		}

		if err := mrb.Close(); err != nil {
			b.Fatalf("Close returned unexpected error: %v", err)
		}
		wg.Wait()
		b.StopTimer()

		for _, result := range results {
			if result.err != nil {
				b.Fatalf("Reader returned unexpected error: %v", result.err)
			} else if !reflect.DeepEqual(result.out, data) {
				b.Fatalf("Reader returned incorrect data: got %x, expected %x", result.out, data)
			}
		}
		b.StartTimer()
	}
}

func generateData(size int) []byte {
	x := make([]byte, size)
	for i := range x {
		x[i] = byte(i % 237)
	}
	return x
}
