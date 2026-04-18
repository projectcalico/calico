// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package main

import (
	"github.com/projectcalico/calico/pkg/cmdwrapper"
	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/logutils"
)

// This is a wrapper program to restart the passed-in program any time it
// exits with RestartReturnCode, used by felix and kube-controllers to
// signal restart-on-configuration-change.
func main() {
	logutils.ConfigureEarlyLogging()
	logutils.ConfigureLogging(&config.Config{
		LogSeverityScreen:       "info",
		DebugDisableLogDropping: true,
	})
	cmdwrapper.Run()
}
