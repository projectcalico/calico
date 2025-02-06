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

package apiutil

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// EventStream represents a http stream. Users can write objects to the response one at a time and the objects
// will be flushed based on the configuration of the stream in the format configured in the stream.
type EventStream[E any] interface {
	WriteData(E) error
	Error(msg string) error
}

type Event struct {
	Type string `json:"type,omitempty"`
	Data any    `json:"data"`
}

// jsonStreamWriter implements a ResponseStream. The format written to the http stream is json.
type jsonEventStreamWriter[E any] struct {
	*flusherWriter
}

func (w *jsonEventStreamWriter[E]) Error(msg string) error {
	_, err := fmt.Fprintf(w, "error: %s\n\n", msg)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}

	w.Flush()
	return nil
}

// WriteData encodes the given object as json and flushes it down the http stream.
func (w *jsonEventStreamWriter[E]) WriteData(e E) error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	_, err = fmt.Fprintf(w, "data: %s\n\n", data)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}

	w.Flush()
	return nil
}

type flusherWriter struct {
	http.ResponseWriter
	asFlusher http.Flusher
}

func newFlusherWriter(w http.ResponseWriter) *flusherWriter {
	return &flusherWriter{
		ResponseWriter: w,
		asFlusher:      w.(http.Flusher),
	}
}

func (f *flusherWriter) Flush() {
	f.asFlusher.Flush()
}

func newJSONStreamWriter[E any](w http.ResponseWriter) EventStream[E] {
	return &jsonEventStreamWriter[E]{flusherWriter: newFlusherWriter(w)}
}
