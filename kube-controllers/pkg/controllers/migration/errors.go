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

package migration

import "errors"

// terminalError wraps an error that should not be retried. The migration
// controller transitions to Failed immediately when it encounters one.
type terminalError struct {
	err error
}

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// asTerminal marks an error as terminal (non-retryable).
func asTerminal(err error) error {
	return &terminalError{err: err}
}

// isTerminal returns true if the error (or any error in its chain) is terminal.
func isTerminal(err error) bool {
	var t *terminalError
	return errors.As(err, &t)
}
