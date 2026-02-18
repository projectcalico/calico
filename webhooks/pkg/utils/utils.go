// Copyright 2026 Tigera, Inc.
//
// Copyright 2018 The Kubernetes Authors.
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

package utils

import (
	"net/http"

	v1 "k8s.io/api/admission/v1"
)

type HandlerProvider interface {
	Handler() AdmissionReviewHandler
}

type V1AdmissionFunc func(v1.AdmissionReview) *v1.AdmissionResponse

// AdmissionReviewHandler is a handler, for both validators and mutators, that supports multiple admission review versions
type AdmissionReviewHandler struct {
	ProcessV1Review V1AdmissionFunc
}

func NewDelegateToV1AdmitHandler(f V1AdmissionFunc) AdmissionReviewHandler {
	return AdmissionReviewHandler{ProcessV1Review: f}
}

// HandleFn is a function type that takes an AdmissionReviewHandler and returns an http.HandlerFunc to help with
// webhook registration.
type HandleFn func(handler AdmissionReviewHandler) func(http.ResponseWriter, *http.Request)
