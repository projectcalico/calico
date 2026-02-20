// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package extdataplane

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func TestWrapPayloadWithEnvelopeMainline(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	msg := &proto.ConfigUpdate{
		Config: map[string]string{
			"key1": "value1",
		},
	}
	enveloped, err := WrapPayloadWithEnvelope(msg, 10)
	if err != nil {
		t.Fatalf("Unexpected error wrapping payload: %v", err)
	}
	if enveloped.SequenceNumber != 10 {
		t.Errorf("Expected SeqNum 10 but got %v", enveloped.SequenceNumber)
	}

	out := enveloped.GetConfigUpdate()
	if !reflect.DeepEqual(out, msg) {
		t.Errorf("Expected %v but got %v", msg, out)
	}
}

func TestAllPayloadTypes(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	env := &proto.ToDataplane{}
	payload := env.ProtoReflect().Descriptor().Oneofs().ByName("payload")
	t.Log("Number of payload types:", payload.Fields().Len())
	for i := 0; i < payload.Fields().Len(); i++ {
		field := payload.Fields().Get(i)
		msgDesc := field.Message()
		msgType, err := protoregistry.GlobalTypes.FindMessageByName(msgDesc.FullName())
		if err != nil {
			t.Fatalf("Failed to find message type for %v: %v", msgDesc.FullName(), err)
		}
		msg := msgType.New().Interface()
		enveloped, err := WrapPayloadWithEnvelope(msg, 42)
		if err != nil {
			t.Errorf("Unexpected error wrapping payload of type %v: %v", msgDesc.FullName(), err)
			continue
		}
		if enveloped.SequenceNumber != 42 {
			t.Errorf("Expected SeqNum 42 but got %v for payload type %v", enveloped.SequenceNumber, msgDesc.FullName())
		}
		// Use reflection to get the payload back out.
		gotField := enveloped.ProtoReflect().WhichOneof(payload)
		if gotField == nil {
			t.Errorf("Expected payload field to be set for type %v but was nil", msgDesc.FullName())
			continue
		}
		if gotField.FullName() != field.FullName() {
			t.Errorf("Expected payload field %v but got %v", field.FullName(), gotField.FullName())
			continue
		}
	}
}

func BenchmarkWrapPayloadWithEnvelope(b *testing.B) {
	logutils.ConfigureLoggingForTestingTB(b)
	msg := &proto.ConfigUpdate{
		Config: map[string]string{
			"key1": "value1",
		},
	}

	b.ReportAllocs()
	for b.Loop() {
		_, err := WrapPayloadWithEnvelope(msg, 123)
		if err != nil {
			b.Fatalf("Unexpected error wrapping payload: %v", err)
		}
	}
}
