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

package apiserver_test

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
)

// calicoExt is the same Enterprise build running as Calico.
var (
	ext       = enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{})
	calicoExt = enterprise.New(operatorv1.Calico, eoptions.Options{})
)

// ctx is the reconcile context the specs pass to the extension hooks.
var ctx = context.Background()

func TestAPIServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/enterprise/apiserver Suite")
}
