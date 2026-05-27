// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
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

package flowlog

import "github.com/projectcalico/calico/lib/std/log"

// logutil keeps a compatibility shim local to this package so the existing
// `logutil.Tracef(cond, fmt, args...)` call sites continue to work. The shim
// emits at Debug level only when `display` is true; this preserves the
// behaviour previously provided by felix/logutils.Tracef.
type logutilShim struct{}

func (logutilShim) Tracef(display bool, format string, args ...any) {
	if display {
		log.Debugf(format, args...)
	}
}

var logutil = logutilShim{}
