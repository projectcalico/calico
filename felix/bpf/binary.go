// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package bpf

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"

	"github.com/sirupsen/logrus"
)

// Binary is an in memory representation of a BPF binary
type Binary struct {
	raw []byte
}

// BinaryFromFile reads a binary from a file
func BinaryFromFile(ifile string) (*Binary, error) {
	raw, err := os.ReadFile(ifile)
	if err != nil {
		return nil, err
	}

	return &Binary{
		raw: raw,
	}, nil
}

// WriteToFile writes the binary to a file
func (b *Binary) WriteToFile(ofile string) error {
	err := os.WriteFile(ofile, b.raw, 0600)
	if err != nil {
		return err
	}

	// Append a UUID to the file.  We want each attachment point to get its own jump map
	// but tc names jump maps by hash of the binary, which means they can clash if we load
	// the same binary onto multiple interfaces.
	f, err := os.OpenFile(ofile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}()
	uuid := make([]byte, 16)
	_, err = rand.Read(uuid)
	if err != nil {
		return err
	}
	_, err = f.Write(uuid)
	if err != nil {
		return err
	}
	return nil
}

// ReplaceAll replaces all non-overlapping instance of orig with replacements.
func (b *Binary) ReplaceAll(orig, replacement []byte) {
	b.raw = bytes.ReplaceAll(b.raw, orig, replacement)
}

func (b *Binary) replaceAllLoadImm32(orig, replacement []byte) {
	// immediate load has 2 byte 00 op code as a prefix
	ldimm := make([]byte, 6)
	copy(ldimm[2:], orig[:4])
	rep := make([]byte, 6)
	copy(rep[2:], replacement[:4])

	b.ReplaceAll(ldimm[:], rep[:])
}

// PatchSkbMark replaces SKBM with the expected mark - for tests.
func (b *Binary) PatchSkbMark(mark uint32) {
	logrus.WithField("mark", mark).Debug("Patching skb mark")
	b.patchU32Placeholder("SKBM", uint32(mark))
}

// patchU32Placeholder replaces a placeholder with the given value.
func (b *Binary) patchU32Placeholder(from string, to uint32) {
	toBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(toBytes, to)
	b.replaceAllLoadImm32([]byte(from), toBytes)
}
