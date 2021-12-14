// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package yaml

import (
	"bufio"
	"bytes"
	"io"
)

const (
	yamlSeparator     = "\n---"
	maxDocumentLength = 10 * 1024 * 1024 // 10MB.
)

type Separator interface {
	Next() ([]byte, error)
}

type YAMLSeparator struct {
	scanner *bufio.Scanner
}

func NewYAMLDocumentSeparator(reader io.Reader) Separator {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), maxDocumentLength)
	scanner.Split(splitYAMLDocument)
	return &YAMLSeparator{
		scanner: scanner,
	}
}

// Copyright 2014 The Kubernetes Authors.
// Function originally from:
// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apimachinery/pkg/util/yaml/decoder.go .
func splitYAMLDocument(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	sep := len([]byte(yamlSeparator))
	if i := bytes.Index(data, []byte(yamlSeparator)); i >= 0 {
		// We have a potential document terminator
		i += sep
		after := data[i:]
		if len(after) == 0 {
			// we can't read any more characters
			if atEOF {
				return len(data), data[:len(data)-sep], nil
			}
			return 0, nil, nil
		}
		if j := bytes.IndexByte(after, '\n'); j >= 0 {
			return i + j + 1, data[0 : i-sep], nil
		}
		return 0, nil, nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func (t *YAMLSeparator) Next() ([]byte, error) {
	if !t.scanner.Scan() {
		err := t.scanner.Err()
		if err == nil {
			err = io.EOF
		}
		return []byte{}, err
	}

	return t.scanner.Bytes(), nil
}
