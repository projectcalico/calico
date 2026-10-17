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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var errNotExist = errors.New("object does not exist")

type objectAttrs struct {
	Name     string
	Size     int64
	Created  time.Time
	Metadata map[string]string
}

// bucket is the slice of Cloud Storage that artifact needs, so the CLI can be
// tested against an in-memory fake.
type bucket interface {
	// Stat returns errNotExist when there is no object called name.
	Stat(ctx context.Context, name string) (*objectAttrs, error)
	// List returns the objects whose names start with prefix. With a
	// delimiter it stops at the next delimiter, returning the deeper names as
	// prefixes instead. Both slices are sorted.
	List(ctx context.Context, prefix, delimiter string) ([]objectAttrs, []string, error)
	// Read returns errNotExist when there is no object called name.
	Read(ctx context.Context, name string) (io.ReadCloser, error)
	// Write stores everything read from r as name. If r fails, nothing is
	// stored and any existing object is left as it was.
	Write(ctx context.Context, name string, r io.Reader, contentType string, metadata map[string]string) error
	// Delete returns errNotExist when there is no object called name.
	Delete(ctx context.Context, name string) error
}

type bucketOpener func(ctx context.Context, name string) (bucket, error)

// location is a gs:// URL split into the bucket and the object-name prefix
// that every name at a storage level starts with.
type location struct {
	bucket string
	prefix string
}

func parseLocation(s string) (location, error) {
	rest, ok := strings.CutPrefix(s, "gs://")
	b, prefix, _ := strings.Cut(rest, "/")
	if !ok || b == "" {
		return location{}, fmt.Errorf("'%s' is not a gs:// location", s)
	}
	return location{bucket: b, prefix: prefix}, nil
}

// object joins rel to the prefix the way "${base}/${rel}" does, so an empty
// rel names the prefix as a directory.
func (l location) object(rel string) string {
	if l.prefix == "" {
		return rel
	}
	return l.prefix + "/" + rel
}

func (l location) url(name string) string {
	return "gs://" + l.bucket + "/" + name
}
