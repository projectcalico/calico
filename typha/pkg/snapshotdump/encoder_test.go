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

package snapshotdump

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// emitSample writes a small two-section snapshot through the emitter and
// returns whatever was written to the underlying buffer.
func emitSample(t *testing.T, format Format) []byte {
	t.Helper()
	var buf bytes.Buffer
	em, err := newEmitter(&buf, format)
	if err != nil {
		t.Fatalf("newEmitter: %v", err)
	}

	mustEmit := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("emit: %v", err)
		}
	}

	mustEmit(em.begin("felix"))
	mustEmit(em.kv("felix", api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "LogSeverityScreen"},
			Value:    "Info",
			Revision: "1234",
		},
		UpdateType: api.UpdateTypeKVNew,
	}))
	mustEmit(em.kv("felix", api.Update{
		KVPair: model.KVPair{
			Key:   model.GlobalConfigKey{Name: "a-long-one"},
			Value: strings.Repeat("x", 1000), // force long lines for the wrap test
		},
		UpdateType: api.UpdateTypeKVNew,
	}))
	mustEmit(em.end("felix", 2, "in-sync"))

	mustEmit(em.begin("bgp"))
	mustEmit(em.end("bgp", 0, "in-sync"))

	if err := em.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// parseLines splits NDJSON into one decoded object per non-empty line.
func parseLines(t *testing.T, ndjson []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(ndjson, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		out = append(out, obj)
	}
	return out
}

func TestEmitterNDJSONFraming(t *testing.T) {
	objs := parseLines(t, emitSample(t, FormatNDJSON))

	// begin felix, 2 kvs, end felix, begin bgp, end bgp = 6 lines.
	if len(objs) != 6 {
		t.Fatalf("expected 6 lines, got %d: %v", len(objs), objs)
	}
	if objs[0]["section"] != "felix" || objs[0]["event"] != "begin" {
		t.Errorf("unexpected first line: %v", objs[0])
	}
	if objs[1]["key"] == nil || objs[1]["updateType"] != "new" {
		t.Errorf("unexpected kv line: %v", objs[1])
	}
	end := objs[3]
	if end["event"] != "end" || end["status"] != "in-sync" {
		t.Errorf("unexpected end line: %v", end)
	}
	// numKVs is a JSON number -> float64.
	if n, ok := end["numKVs"].(float64); !ok || n != 2 {
		t.Errorf("expected numKVs=2, got %v", end["numKVs"])
	}
}

func TestEmitterGzipBase64RoundTrip(t *testing.T) {
	encoded := emitSample(t, FormatGzipBase64)

	// Every line of the encoded output must be short enough to survive kubectl
	// exec, and contain only base64 characters.
	for _, line := range bytes.Split(encoded, []byte("\n")) {
		if len(line) > base64WrapColumn {
			t.Fatalf("base64 line longer than wrap column (%d): %d bytes", base64WrapColumn, len(line))
		}
	}

	// Decode the same way calicoctl does: base64 decode (skipping newlines) then
	// gunzip, and confirm we recover the original NDJSON framing.
	gz, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	decoded, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read decoded: %v", err)
	}

	objs := parseLines(t, decoded)
	if len(objs) != 6 {
		t.Fatalf("expected 6 lines after round-trip, got %d", len(objs))
	}
	if objs[0]["section"] != "felix" || objs[0]["event"] != "begin" {
		t.Errorf("unexpected first line after round-trip: %v", objs[0])
	}
	// The 1000-char value must survive intact.
	if objs[2]["value"] != strings.Repeat("x", 1000) {
		t.Errorf("long value did not round-trip intact")
	}
}

func TestParseFormat(t *testing.T) {
	for _, in := range []string{"ndjson", "gzip-base64"} {
		if _, err := ParseFormat(in); err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", in, err)
		}
	}
	if _, err := ParseFormat("bogus"); err == nil {
		t.Errorf("ParseFormat(bogus) expected error, got nil")
	}
}
