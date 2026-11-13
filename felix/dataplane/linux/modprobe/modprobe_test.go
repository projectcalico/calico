// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

package modprobe

import (
	"errors"
	"slices"
	"testing"
)

func TestExecReturnsCommandOutputAndError(t *testing.T) {
	cmd := &fakeCmd{output: []byte("test output"), err: errors.New("test mp error")}
	var gotName string
	var gotArgs []string
	uut := New("test_module", func(name string, args ...string) Cmd {
		gotName, gotArgs = name, args
		return cmd
	})

	out, err := uut.Exec()

	if out != "test output" {
		t.Errorf("Exec() output = %q, want %q", out, "test output")
	}
	if err == nil || err.Error() != "test mp error" {
		t.Errorf("Exec() error = %v, want %q", err, "test mp error")
	}
	if gotName != "modprobe" || !slices.Equal(gotArgs, []string{"test_module"}) {
		t.Errorf("ran %q %q, want \"modprobe\" [\"test_module\"]", gotName, gotArgs)
	}
	if cmd.outputCallCount != 1 {
		t.Errorf("Output() called %d times, want 1", cmd.outputCallCount)
	}
}

type fakeCmd struct {
	output          []byte
	err             error
	outputCallCount int
}

func (c *fakeCmd) Output() ([]byte, error) {
	c.outputCallCount++
	return c.output, c.err
}
