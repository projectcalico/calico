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

// eventStream represents a server side event stream. Users can write objects to the response one at a time and the objects
// will be flushed based on the configuration of the stream in the format configured in the stream.
type eventStream[E any] interface {
	writeData(E) error
	error(msg string) error
}

type Event struct {
	Type string `json:"type,omitempty"`
	Data any    `json:"data"`
}

// jsonEventStream implements a eventStream. It writes it's data back as json objects.
type jsonEventStream[E any] struct {
	*flusherWriter
}

func (w *jsonEventStream[E]) error(msg string) error {
	_, err := fmt.Fprintf(w, "error: %s\n\n", msg)
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}

	w.Flush()
	return nil
}

// WriteData encodes the given object as json and flushes it down the http stream.
func (w *jsonEventStream[E]) writeData(e E) error {
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

func newJSONEventStreamWriter[E any](w http.ResponseWriter) eventStream[E] {
	return &jsonEventStream[E]{flusherWriter: newFlusherWriter(w)}
}
