// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/sirupsen/logrus"
)

type Map interface {
	EnsureExists() error
	Iter(func(k, v []byte)) error
	Update(k, v []byte) error
	Delete(k []byte) error
}

func NewPinnedMap(name, filename string, mapType string, keySize, valueSize int, maxEntries int, flags int) Map {
	m := &PinnedMap{
		Filename:   filename,
		Type:       mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Name:       name,
		Flags:      flags,
	}
	return m
}

type PinnedMap struct {
	Filename   string
	Type       string
	KeySize    int
	ValueSize  int
	MaxEntries int
	Name       string
	Flags      int

	fdLoaded bool
	fd       MapFD
}

func (b *PinnedMap) Close() error {
	err := b.fd.Close()
	b.fdLoaded = false
	b.fd = 0
	return err
}

func (b *PinnedMap) Iter(f func(k, v []byte)) error {
	cmd := exec.Command("bpftool", "map", "dump", "pinned", b.Filename)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()

	err = cmd.Start()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(out)
	scanner.Split(bufio.ScanWords)

	var k, v []byte
	seenKey := false
	for scanner.Scan() {
		text := scanner.Text()
		if text == "key:" {
			if seenKey {
				f(k, v)
				seenKey = false
				k = k[:0]
				v = v[:0]
			}
			continue
		}
		if text == "value:" {
			seenKey = true
			continue
		}
		if text == "Found" {
			break
		}
		i, err := strconv.ParseUint(text, 16, 8)
		if err != nil {
			return err
		}
		b := byte(i)
		if seenKey {
			v = append(k, b)
		} else {
			k = append(k, b)
		}
	}
	if seenKey && scanner.Err() == nil {
		f(k, v)
	}
	return scanner.Err()
}

func (b *PinnedMap) Update(k, v []byte) error {
	return UpdateMapEntry(b.fd, k, v)
}

func appendBytes(strings []string, bytes []byte) []string {
	for _, b := range bytes {
		strings = append(strings, strconv.FormatInt(int64(b), 10))
	}
	return strings
}

func (b *PinnedMap) Delete(k []byte) error {
	args := make([]string, 0, 10+len(k))
	args = append(args, "map", "delete",
		"pinned", b.Filename,
		"key")
	args = appendBytes(args, k)

	cmd := exec.Command("bpftool", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.WithField("out", string(out)).Error("Failed to run bpftool")
	}
	return err
}

func (b *PinnedMap) EnsureExists() error {
	if b.fdLoaded {
		return nil
	}

	_, err := maybeMountBPFfs()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount bpffs")
		return err
	}
	// FIXME hard-coded dir
	err = os.MkdirAll("/sys/fs/bpf/tc/globals", 0700)
	if err != nil {
		logrus.WithError(err).Error("Failed create dir")
		return err
	}
	_, err = os.Stat(b.Filename)
	if err == nil {
		b.fd, err = GetPinnedMapFD(b.Filename)
		if err == nil {
			b.fdLoaded = true
			logrus.WithField("fd", b.fd).WithField("name", b.Filename).Info("Loaded map file descriptor.")
		}
		return err
	}
	if !os.IsNotExist(err) {
		return err
	}
	cmd := exec.Command("bpftool", "map", "create", b.Filename,
		"type", b.Type,
		"key", fmt.Sprint(b.KeySize),
		"value", fmt.Sprint(b.ValueSize),
		"entries", fmt.Sprint(b.MaxEntries),
		"name", b.Name,
		"flags", fmt.Sprint(b.Flags),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.WithField("out", string(out)).Error("Failed to run bpftool")
		return err
	}
	b.fd, err = GetPinnedMapFD(b.Filename)
	if err == nil {
		b.fdLoaded = true
		logrus.WithField("fd", b.fd).WithField("name", b.Filename).Info("Loaded map file descriptor.")
	}
	return err
}
