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

// Command artifact stores and fetches CI artifacts and caches in Google Cloud
// Storage. It replaces the gsutil-based script from calico/ci-scripts, and
// keeps its commands, flags, environment, output and exit codes.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	a := &app{
		getenv: os.Getenv,
		stdout: os.Stdout,
		stderr: &lockedWriter{w: os.Stderr},
		open:   openGCS,
	}
	code := a.run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
