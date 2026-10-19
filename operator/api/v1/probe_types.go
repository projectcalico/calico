// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package v1

// ProbeOverride allows customization of probe timing parameters without
// changing the probe handler itself (which the operator controls).
type ProbeOverride struct {
	// PeriodSeconds is how often (in seconds) to perform the probe.
	// +optional
	PeriodSeconds *int32 `json:"periodSeconds,omitempty"`

	// TimeoutSeconds is the number of seconds after which the probe times out.
	// +optional
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// FailureThreshold is the minimum consecutive failures for the probe
	// to be considered failed after having succeeded.
	// +optional
	FailureThreshold *int32 `json:"failureThreshold,omitempty"`

	// InitialDelaySeconds is the number of seconds after the container
	// starts before the probe is initiated.
	// +optional
	InitialDelaySeconds *int32 `json:"initialDelaySeconds,omitempty"`
}
