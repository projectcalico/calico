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
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

func TestGobFrameLimitedReaderPreservesGobStreamState(t *testing.T) {
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

	dec := gob.NewDecoder(newGobFrameLimitedReader(bytes.NewReader(stream.Bytes()), 1024))

	var gotHello syncproto.Envelope
	if err := dec.Decode(&gotHello); err != nil {
		t.Fatalf("decoding hello: %v", err)
	}
	if !reflect.DeepEqual(gotHello, wantHello) {
		t.Fatalf("decoded hello mismatch: got %#v want %#v", gotHello, wantHello)
	}

	var gotPong syncproto.Envelope
	if err := dec.Decode(&gotPong); err != nil {
		t.Fatalf("decoding pong: %v", err)
	}
	if !reflect.DeepEqual(gotPong, wantPong) {
		t.Fatalf("decoded pong mismatch: got %#v want %#v", gotPong, wantPong)
	}
}

func TestGobFrameLimitedReaderPreservesGobStreamStateWithBufioPath(t *testing.T) {
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

	// Wrap in struct{io.Reader} to hide the ReadByte method, forcing the
	// bufio.NewReader path in newGobFrameLimitedReader — the same path
	// used in production with net.Conn.
	dec := gob.NewDecoder(newGobFrameLimitedReader(struct{ io.Reader }{bytes.NewReader(stream.Bytes())}, 1024))

	var gotHello syncproto.Envelope
	if err := dec.Decode(&gotHello); err != nil {
		t.Fatalf("decoding hello: %v", err)
	}
	if !reflect.DeepEqual(gotHello, wantHello) {
		t.Fatalf("decoded hello mismatch: got %#v want %#v", gotHello, wantHello)
	}

	var gotPong syncproto.Envelope
	if err := dec.Decode(&gotPong); err != nil {
		t.Fatalf("decoding pong: %v", err)
	}
	if !reflect.DeepEqual(gotPong, wantPong) {
		t.Fatalf("decoded pong mismatch: got %#v want %#v", gotPong, wantPong)
	}
}

func TestGobFrameLimitedReaderRejectsOversizedFrameBeforeReadingPayload(t *testing.T) {
	const limit = 16
	payload := bytes.Repeat([]byte{0xab}, 32)
	prefix := encodeGobUint(limit + 1)
	source := bytes.NewReader(append(prefix, payload...))

	reader := newGobFrameLimitedReader(source, limit)

	var oneByte [1]byte
	_, err := reader.Read(oneByte[:])
	if !errors.Is(err, errInboundMessageTooLarge) {
		t.Fatalf("expected oversized-frame error, got %v", err)
	}

	if remaining := source.Len(); remaining != len(payload) {
		t.Fatalf("expected payload to remain unread, %d bytes remain", remaining)
	}
}

func encodeGobUint(value uint64) []byte {
	if value <= 0x7f {
		return []byte{byte(value)}
	}

	n := 0
	for tmp := value; tmp > 0; tmp >>= 8 {
		n++
	}

	buf := make([]byte, n+1)
	buf[0] = byte(-int8(n))
	for i := n; i > 0; i-- {
		buf[i] = byte(value)
		value >>= 8
	}
	return buf
}
