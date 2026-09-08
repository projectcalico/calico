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

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// yamlIndent matches what the rest of the bundle manifests are written with.
const yamlIndent = 2

// document is a YAML file held as a node tree, so that an update can rewrite a
// handful of fields and leave everything else - key order, styles, comments -
// as it was.
type document struct {
	path string
	root yaml.Node
}

func loadDocument(path string) (*document, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	d := &document{path: path}
	if err := yaml.Unmarshal(content, &d.root); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return d, nil
}

func (d *document) save() error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(yamlIndent)
	if err := enc.Encode(&d.root); err != nil {
		return fmt.Errorf("encoding %s: %w", d.path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("encoding %s: %w", d.path, err)
	}
	if err := os.WriteFile(d.path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", d.path, err)
	}
	return nil
}

// set writes a string at the given path, where each path element is either a
// mapping key or a sequence index. Missing mappings along the path are created;
// a missing sequence index is an error, since we have no way to know what else
// the element should hold.
func (d *document) set(value string, path ...any) error {
	if len(path) == 0 {
		return fmt.Errorf("no path given")
	}
	key, ok := path[len(path)-1].(string)
	if !ok {
		return fmt.Errorf("%s: last path element must be a mapping key", pathString(path))
	}
	parent, err := d.lookup(path[:len(path)-1], true)
	if err != nil {
		return err
	}
	if parent.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a mapping", pathString(path[:len(path)-1]))
	}
	if node := mapValue(parent, key); node != nil {
		node.Tag = "!!str"
		node.Value = value
		return nil
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
	return nil
}

// delete removes a mapping key. Deleting a key that is not there is not an error.
func (d *document) delete(path ...any) error {
	if len(path) == 0 {
		return fmt.Errorf("no path given")
	}
	key, ok := path[len(path)-1].(string)
	if !ok {
		return fmt.Errorf("%s: last path element must be a mapping key", pathString(path))
	}
	parent, err := d.lookup(path[:len(path)-1], false)
	if err != nil || parent == nil || parent.Kind != yaml.MappingNode {
		return err
	}
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
			return nil
		}
	}
	return nil
}

// lookup walks the path from the root of the document. With create set, a
// missing mapping key or a sequence index one past the end is filled in with an
// empty collection of whatever kind the rest of the path needs; without it, a
// missing key returns a nil node and no error.
func (d *document) lookup(path []any, create bool) (*yaml.Node, error) {
	node := &d.root
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil, fmt.Errorf("%s is empty", d.path)
		}
		node = node.Content[0]
	}

	for i, element := range path {
		// The path continues, so whatever sits at this element has to be the
		// collection that the next element indexes into. A key that is there but
		// empty is treated the same as one that is missing.
		if create {
			makeCollection(node, path, i)
		}

		switch element := element.(type) {
		case string:
			if node.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s: not a mapping", pathString(path[:i]))
			}
			child := mapValue(node, element)
			if child == nil {
				if !create {
					return nil, nil
				}
				child = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: element},
					child,
				)
			}
			node = child
		case int:
			if node.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("%s: not a sequence", pathString(path[:i]))
			}
			if element == len(node.Content) && create {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"})
			}
			if element >= len(node.Content) {
				return nil, fmt.Errorf("%s: index out of range", pathString(path[:i+1]))
			}
			node = node.Content[element]
		default:
			return nil, fmt.Errorf("%s: path elements must be mapping keys or sequence indices", pathString(path[:i+1]))
		}
	}
	if create {
		makeCollection(node, path, len(path))
	}
	return node, nil
}

// makeCollection turns an empty node into the mapping or sequence that path
// element i indexes into. Everything past the end of the path is a mapping,
// since that is what a set or a delete needs its parent to be.
func makeCollection(node *yaml.Node, path []any, i int) {
	if node.Kind != 0 && node.Tag != "!!null" {
		return
	}
	if i < len(path) {
		if _, isIndex := path[i].(int); isIndex {
			node.Kind, node.Tag, node.Value = yaml.SequenceNode, "!!seq", ""
			return
		}
	}
	node.Kind, node.Tag, node.Value = yaml.MappingNode, "!!map", ""
}

// mapValue returns the value node for a key of a mapping node, or nil.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func pathString(path []any) string {
	var b strings.Builder
	for _, element := range path {
		switch element := element.(type) {
		case string:
			fmt.Fprintf(&b, ".%s", element)
		default:
			fmt.Fprintf(&b, "[%v]", element)
		}
	}
	if b.Len() == 0 {
		return "."
	}
	return b.String()
}
