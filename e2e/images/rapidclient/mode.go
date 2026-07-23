/*
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import "sort"

// Mode is one behaviour of the multi-mode rapidclient binary, selected at
// runtime by the MODE env var. Each mode parses its own flags from the args it
// is handed, so modes have independent flag surfaces. Add a mode by calling
// registerMode from an init().
type Mode interface {
	// Name is the MODE value that selects this mode.
	Name() string
	// Run parses flags from args and executes the mode. A non-nil error is
	// surfaced by main as a non-zero exit.
	Run(args []string) error
}

// modes is the registry of available modes, keyed by Name.
var modes = map[string]Mode{}

// registerMode adds m to the registry. Intended to be called from init().
func registerMode(m Mode) {
	modes[m.Name()] = m
}

// lookupMode returns the registered mode for name, if any.
func lookupMode(name string) (Mode, bool) {
	m, ok := modes[name]
	return m, ok
}

// modeNames returns the registered mode names, sorted, for error messages.
func modeNames() []string {
	names := make([]string, 0, len(modes))
	for n := range modes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
