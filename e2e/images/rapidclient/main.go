/*
Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

// Command rapidclient is a multi-mode e2e test utility. The mode is selected by
// the MODE environment variable; an unset MODE defaults to "client", preserving
// the original client behaviour (and its flag interface) for existing callers.
// See DESIGN.md for the mode contracts.
package main

import (
	"log"
	"os"
)

// defaultMode is used when MODE is unset, preserving the original rapidclient
// (client) behaviour for existing callers such as the maglev e2e test.
const defaultMode = "client"

// resolveMode maps a MODE env value to a registered mode. An empty value selects
// defaultMode, preserving the original client behaviour for callers that set no
// MODE. ok is false for a non-empty but unregistered mode.
func resolveMode(env string) (mode Mode, name string, ok bool) {
	name = env
	if name == "" {
		name = defaultMode
	}
	m, ok := lookupMode(name)
	return m, name, ok
}

func main() {
	mode, modeName, ok := resolveMode(os.Getenv("MODE"))
	if !ok {
		log.Fatalf("unknown MODE %q; known modes: %v", modeName, modeNames())
	}

	if err := mode.Run(os.Args[1:]); err != nil {
		log.Fatalf("%s: %v", modeName, err)
	}
}
