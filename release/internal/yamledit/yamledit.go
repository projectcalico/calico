// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package yamledit replaces values in a YAML file without reformatting it.
package yamledit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Edit struct {
	Key string

	To string
}

func (e Edit) validate() error {
	if e.To == "" {
		return fmt.Errorf("no replacement value")
	}
	if e.Key == "" {
		return fmt.Errorf("no key to replace")
	}
	return nil
}

type span struct{ start, end int }

// Matching nothing is an error: a renamed key would otherwise leave the file
// unstamped.
func (e Edit) apply(src []byte) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	spans, err := e.spans(src)
	if err != nil {
		return nil, err
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("key %q matched nothing", e.Key)
	}
	var out bytes.Buffer
	out.Grow(len(src))
	prev := 0
	for _, s := range spans {
		out.Write(src[prev:s.start])
		out.WriteString(e.To)
		prev = s.end
	}
	out.Write(src[prev:])
	return out.Bytes(), nil
}

func ApplyToFile(path string, edits ...Edit) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	out := src
	for _, e := range edits {
		if out, err = e.apply(out); err != nil {
			return fmt.Errorf("editing %s: %w", path, err)
		}
	}
	if bytes.Equal(out, src) {
		return nil
	}
	if err := os.WriteFile(path, out, info.Mode().Perm()); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func (e Edit) spans(src []byte) ([]span, error) {
	var docs []*yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing yaml: %w", err)
		}
		docs = append(docs, &doc)
	}
	want := strings.Split(e.Key, ".")
	var spans []span
	var walk func(n *yaml.Node, path []string) error
	walk = func(n *yaml.Node, path []string) error {
		for i, child := range n.Content {
			at := path
			if n.Kind == yaml.MappingNode {
				if i%2 == 0 {
					continue
				}
				at = append(path, n.Content[i-1].Value)
				if matches(at, want) && child.Kind == yaml.ScalarNode {
					s, err := valueSpan(src, child)
					if err != nil {
						return err
					}
					spans = append(spans, s)
				}
			}
			if err := walk(child, at); err != nil {
				return err
			}
		}
		return nil
	}
	for _, doc := range docs {
		if err := walk(doc, nil); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	return spans, nil
}

func matches(at, want []string) bool {
	if len(want) == 1 {
		return at[len(at)-1] == want[0]
	}
	return slices.Equal(at, want)
}

// Reports a quoted scalar's interior, so replacing keeps the quotes.
func valueSpan(src []byte, n *yaml.Node) (span, error) {
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return span{}, fmt.Errorf("line %d: cannot replace a block scalar", n.Line)
	}
	line, ok := lineSpan(src, n.Line)
	if !ok {
		return span{}, fmt.Errorf("line %d is outside the file", n.Line)
	}
	start := line.start + n.Column - 1
	if start > line.end {
		return span{}, fmt.Errorf("line %d: value starts past the end of its line", n.Line)
	}
	rest := src[start:line.end]
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
		end := bytes.IndexByte(rest[1:], rest[0])
		if end < 0 {
			return span{}, fmt.Errorf("line %d: unterminated quoted value", n.Line)
		}
		return span{start + 1, start + 1 + end}, nil
	}
	if i := bytes.Index(rest, []byte(" #")); i >= 0 {
		rest = rest[:i]
	}
	// Inside a flow mapping or sequence the value ends at its separator, not
	// at the end of the line.
	if i := bytes.IndexAny(rest, ",}]"); i >= 0 {
		rest = rest[:i]
	}
	rest = bytes.TrimRight(rest, " \t")
	if len(rest) == 0 {
		return span{}, fmt.Errorf("line %d: no value to replace", n.Line)
	}
	return span{start, start + len(rest)}, nil
}

func lineSpan(src []byte, line int) (span, bool) {
	if line < 1 {
		return span{}, false
	}
	start := 0
	for ; line > 1; line-- {
		i := bytes.IndexByte(src[start:], '\n')
		if i < 0 {
			return span{}, false
		}
		start += i + 1
	}
	end := len(src)
	if i := bytes.IndexByte(src[start:], '\n'); i >= 0 {
		end = start + i
	}
	return span{start, end}, true
}
