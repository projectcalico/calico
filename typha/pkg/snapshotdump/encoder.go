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
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Format controls how the snapshot stream is encoded on the wire.
type Format string

const (
	// FormatNDJSON writes newline-delimited JSON straight to the output.  Best
	// for humans reading the dump directly.
	FormatNDJSON Format = "ndjson"
	// FormatGzipBase64 gzip-compresses the newline-delimited JSON stream and
	// base64-encodes it, hard-wrapping the base64 at a fixed column.  This
	// survives "kubectl exec" round-tripping (which can drop connections on
	// very long lines) and is compact for large snapshots.  Decode with
	// base64 -> gunzip to recover the NDJSON.
	FormatGzipBase64 Format = "gzip-base64"
)

// base64WrapColumn is the column at which base64 output is wrapped.  It is well
// under any plausible kubectl-exec line-length limit.  The streaming base64
// decoder (base64.NewDecoder) strips newlines, so wrapping is transparent to
// the reader.
const base64WrapColumn = 100

// ParseFormat validates and returns a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatNDJSON:
		return FormatNDJSON, nil
	case FormatGzipBase64:
		return FormatGzipBase64, nil
	default:
		return "", fmt.Errorf("unknown format %q (expected %q or %q)", s, FormatNDJSON, FormatGzipBase64)
	}
}

// sectionEvent marks the start or end of one syncer type's snapshot.
type sectionEvent struct {
	Section string `json:"section"`
	Event   string `json:"event"` // "begin" or "end"
	NumKVs  *int   `json:"numKVs,omitempty"`
	Status  string `json:"status,omitempty"`
}

// kvLine is one key/value pair within a section.
type kvLine struct {
	Section    string          `json:"section"`
	Key        string          `json:"key"`
	Value      json.RawMessage `json:"value"`
	Revision   any             `json:"revision,omitempty"`
	UpdateType string          `json:"updateType"`
}

// emitter writes the structured snapshot stream.  It owns the writer chain
// (which, for gzip-base64, wraps gzip and base64 encoders) and must be closed
// to flush.  It is not safe for concurrent use; the caller dumps each syncer
// type sequentially.
type emitter struct {
	enc     *json.Encoder
	closers []io.Closer // closed in order (gzip before base64)
	tail    func() error
}

func newEmitter(out io.Writer, format Format) (*emitter, error) {
	switch format {
	case FormatNDJSON:
		return &emitter{enc: json.NewEncoder(out)}, nil
	case FormatGzipBase64:
		lw := &lineWrapper{w: out, max: base64WrapColumn}
		b64 := base64.NewEncoder(base64.StdEncoding, lw)
		gz := gzip.NewWriter(b64)
		return &emitter{
			enc:     json.NewEncoder(gz),
			closers: []io.Closer{gz, b64},
			tail:    lw.finish,
		}, nil
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func (e *emitter) begin(section string) error {
	return e.enc.Encode(sectionEvent{Section: section, Event: "begin"})
}

func (e *emitter) kv(section string, u api.Update) error {
	keyStr, err := model.KeyToDefaultPath(u.Key)
	if err != nil {
		keyStr = fmt.Sprintf("%#v", u.Key)
	}
	// Pre-marshal the value so that an un-marshalable value can't corrupt the
	// line; substitute a placeholder string instead.
	valBytes, err := json.Marshal(u.Value)
	if err != nil {
		valBytes, _ = json.Marshal(fmt.Sprintf("<unmarshalable value: %v>", err))
	}
	return e.enc.Encode(kvLine{
		Section:    section,
		Key:        keyStr,
		Value:      json.RawMessage(valBytes),
		Revision:   u.Revision,
		UpdateType: u.UpdateType.String(),
	})
}

func (e *emitter) end(section string, numKVs int, status string) error {
	return e.enc.Encode(sectionEvent{Section: section, Event: "end", NumKVs: &numKVs, Status: status})
}

// Close flushes and closes the writer chain.
func (e *emitter) Close() error {
	var firstErr error
	for _, c := range e.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.tail != nil {
		if err := e.tail(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// lineWrapper inserts a newline into the byte stream every max bytes.  It is
// used to wrap base64 output so that no single line is long enough to trip the
// kubectl-exec long-line bug.
type lineWrapper struct {
	w   io.Writer
	max int
	col int
}

func (l *lineWrapper) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if l.col >= l.max {
			if _, err := l.w.Write([]byte{'\n'}); err != nil {
				return written, err
			}
			l.col = 0
		}
		n := l.max - l.col
		if n > len(p) {
			n = len(p)
		}
		m, err := l.w.Write(p[:n])
		written += m
		l.col += m
		p = p[m:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// finish writes a trailing newline if the last line was non-empty, so the
// output always ends cleanly.
func (l *lineWrapper) finish() error {
	if l.col > 0 {
		_, err := l.w.Write([]byte{'\n'})
		l.col = 0
		return err
	}
	return nil
}
