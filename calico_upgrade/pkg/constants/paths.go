// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package constants

import (
	"os"
	"path/filepath"
)

const (
	DefaultConfigPathV1 = "/etc/calico/apiconfigv1.cfg"
	DefaultConfigPathV3 = "/etc/calico/apiconfigv3.cfg"

	FileConvertedNames   = "convertednames"
	FileNameClashes      = "nameclashes"
	FileConversionErrors = "conversionerrors"
	FilePolicyController = "policycontroller"
	FileValidationErrors = "validationerrors"

	defaultOutputDir = "calico-upgrade-report"
)

var AllReportFiles = []string{
	FileConvertedNames,
	FileNameClashes,
	FileConversionErrors,
	FilePolicyController,
	FileValidationErrors,
}

func GetDefaultOutputDir() string {
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Join(cwd, defaultOutputDir)
	}
	return filepath.Join(os.TempDir(), defaultOutputDir)
}
