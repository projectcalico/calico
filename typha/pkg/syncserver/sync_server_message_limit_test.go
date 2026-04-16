// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package syncserver

import (
	"bytes"
	"encoding/gob"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

func TestLimitedReaderAllowsNormalMessages(t *testing.T) {
	var stream bytes.Buffer
	enc := gob.NewEncoder(&stream)

	wantHello := syncproto.Envelope{
		Message: syncproto.MsgClientHello{
			Hostname:   "node-a",
			Info:       "test",
			Version:    "v3.31.5",
			SyncerType: syncproto.SyncerTypeFelix,
		},
	}
	wantPong := syncproto.Envelope{
		Message: syncproto.MsgPong{
			PingTimestamp: time.Unix(123, 456),
		},
	}

	if err := enc.Encode(&wantHello); err != nil {
		t.Fatalf("encoding hello: %v", err)
	}
	if err := enc.Encode(&wantPong); err != nil {
		t.Fatalf("encoding pong: %v", err)
	}

	lr := &limitedReader{r: bytes.NewReader(stream.Bytes()), limit: 1024}
	dec := gob.NewDecoder(lr)

	var gotHello syncproto.Envelope
	lr.reset()
	if err := dec.Decode(&gotHello); err != nil {
		t.Fatalf("decoding hello: %v", err)
	}
	if !reflect.DeepEqual(gotHello, wantHello) {
		t.Fatalf("decoded hello mismatch: got %#v want %#v", gotHello, wantHello)
	}

	var gotPong syncproto.Envelope
	lr.reset()
	if err := dec.Decode(&gotPong); err != nil {
		t.Fatalf("decoding pong: %v", err)
	}
	if !reflect.DeepEqual(gotPong, wantPong) {
		t.Fatalf("decoded pong mismatch: got %#v want %#v", gotPong, wantPong)
	}
}

func TestLimitedReaderRejectsOversizedRead(t *testing.T) {
	// Create a payload larger than the limit.
	const limit int64 = 64
	payload := bytes.Repeat([]byte{0xab}, int(limit*2))

	lr := &limitedReader{r: bytes.NewReader(payload), limit: limit}

	buf := make([]byte, len(payload))
	var total int64
	for {
		n, err := lr.Read(buf[total:])
		total += int64(n)
		if err != nil {
			if !errors.Is(err, errInboundMessageTooLarge) {
				t.Fatalf("expected errInboundMessageTooLarge, got %v", err)
			}
			break
		} else if n <= 0 {
			t.Fatalf("read returned 0 bytes without error, possible infinite loop")
		}
		if total > limit {
			t.Fatalf("read past limit without error: total %d, limit %d", total, limit)
		}
	}
	if total != limit {
		t.Fatalf("expected total bytes read to equal limit, got %d (limit %d)", total, limit)
	}
}

func TestLimitedReaderResetAllowsNextMessage(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 100)
	lr := &limitedReader{r: bytes.NewReader(data), limit: 60}

	buf := make([]byte, 50)
	n, err := lr.Read(buf)
	if err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}
	if n != 50 {
		t.Fatalf("first read: expected 50 bytes, got %d", n)
	}

	lr.reset()

	n, err = lr.Read(buf)
	if err != nil {
		t.Fatalf("read after reset should succeed: %v", err)
	}
	if n != 50 {
		t.Fatalf("read after reset: expected 50 bytes, got %d", n)
	}
}
