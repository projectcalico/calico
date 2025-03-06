// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package fv

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"testing"

	. "github.com/onsi/gomega"
)

func setup(t *testing.T) (context.Context, func()) {
	RegisterTestingT(t)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	// Use a channel to detect when the test is done
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		select {
		case <-sigs:
			fmt.Println("Interrupt received, ensuring cleanup...")
			// If interrupted, call t.Fail() to stop the test gracefully
		case <-ctx.Done():
			// If the test finishes naturally, return
		}
	}()
	return ctx, cancel
}
