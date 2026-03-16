#!/bin/bash

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(realpath $(dirname "${BASH_SOURCE}")/..)
BINDIR=${REPO_ROOT}/bin

APPLY_CONFIG_PKG="github.com/projectcalico/api/pkg/client/applyconfiguration_generated"
APPLY_CONFIG_DIR="${REPO_ROOT}/pkg/client/applyconfiguration_generated"

# Install applyconfiguration-gen if not already present in the build image.
if ! command -v applyconfiguration-gen &> /dev/null; then
	echo "Installing applyconfiguration-gen..."
	go install k8s.io/code-generator/cmd/applyconfiguration-gen@v0.35.2
fi

# Generate OpenAPI schema JSON for applyconfiguration-gen.
# This populates the structured-merge-diff type information in internal/internal.go,
# which is required for fake.NewClientset() to work correctly.
OPENAPI_SCHEMA=$(mktemp)
trap "rm -f ${OPENAPI_SCHEMA}" EXIT
echo "Generating OpenAPI schema for applyconfiguration-gen..."
go run "${REPO_ROOT}/hack/openapi-schema/" > "${OPENAPI_SCHEMA}"

# Generate apply configurations (required for NewClientset in fake clientset)
applyconfiguration-gen "$@" \
		--go-header-file "${REPO_ROOT}/hack/boilerplate/boilerplate.go.txt" \
		--openapi-schema "${OPENAPI_SCHEMA}" \
		--output-dir "${APPLY_CONFIG_DIR}" \
		--output-pkg "${APPLY_CONFIG_PKG}" \
		"github.com/projectcalico/api/pkg/apis/projectcalico/v3"

# Patch applyconfiguration-gen bugs (see patches/0002-* and patches/0003-*).
patch -p2 -d "${REPO_ROOT}" < "${REPO_ROOT}/patches/0002-Fix-duplicate-ensureProtoPort-method-in-FelixConfigurationSpec.patch"
patch -p2 -d "${REPO_ROOT}" < "${REPO_ROOT}/patches/0003-Fix-pointer-slice-append-in-IPAMBlockSpec-Allocations.patch"

# Generate the versioned clientset (pkg/client/clientset_generated/clientset)
client-gen "$@" \
		--go-header-file "${REPO_ROOT}/hack/boilerplate/boilerplate.go.txt" \
		--input-base "github.com/projectcalico/api/pkg/apis/" \
		--input "projectcalico/v3" \
		--output-dir "${REPO_ROOT}/pkg/client/clientset_generated" \
		--clientset-path "github.com/projectcalico/api/pkg/client/clientset_generated/" \
		--clientset-name "clientset" \
		--apply-configuration-package "${APPLY_CONFIG_PKG}"
# generate lister
lister-gen "$@" \
		--go-header-file "${REPO_ROOT}/hack/boilerplate/boilerplate.go.txt" \
		--output-dir "${REPO_ROOT}/pkg/client/listers_generated" \
		--output-pkg "github.com/projectcalico/api/pkg/client/listers_generated" \
		"github.com/projectcalico/api/pkg/apis/projectcalico/v3"
# generate informer
informer-gen "$@" \
		--go-header-file "${REPO_ROOT}/hack/boilerplate/boilerplate.go.txt" \
		--versioned-clientset-package "github.com/projectcalico/api/pkg/client/clientset_generated/clientset" \
		--listers-package "github.com/projectcalico/api/pkg/client/listers_generated" \
		--output-dir "${REPO_ROOT}/pkg/client/informers_generated" \
		--output-pkg "github.com/projectcalico/api/pkg/client/informers_generated" \
		"github.com/projectcalico/api/pkg/apis/projectcalico/v3"
