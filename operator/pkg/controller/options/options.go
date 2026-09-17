// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

// Package options is where controllers read the options the daemon detected at
// startup. The types are aliases because the startup extension contributes
// controllers, and a variant's Add takes ControllerOptions.
package options

import (
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

type (
	ControllerOptions = extensions.ControllerOptions
	Controller        = extensions.Controller
)
