//go:build !cgo

// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"github.com/sirupsen/logrus"

	"runtime"
)

// BPF dataplane is not supported in some architectures like Armv7, and at the same time
// this binary cannot be compiled for these architectures becuase of the dependency to
// libbpf and cgo. This file is compiled for these architectures.
func main() {
	logrus.Infof("mountns binary is not supported on %s architecture.", runtime.GOARCH)
}
