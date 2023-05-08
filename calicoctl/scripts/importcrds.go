// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	crdPrefix  = "crd.projectcalico.org_"
	fileSuffix = ".yaml"
)

// Reads all CRD files that are downloaded from libcalico-go
// and encodes them as strings literals in calicoctl/commands/crds/crds.go
func main() {
	crdPath := "../../../../libcalico-go/config/crd/"

	fs, _ := os.ReadDir(crdPath)
	out, _ := os.Create("../../commands/crds/crds.go")
	_, _ = out.Write([]byte(fmt.Sprintf(`// Copyright (c) %s Tigera, Inc. All rights reserved.

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

`, time.Now().Format("2006"))))
	_, _ = out.Write([]byte("package crds\n\n//DO NOT CHANGE. This is a generated file. In order to update, run `make gen-crds`.\n\nconst (\n"))
	for _, f := range fs {
		if strings.HasSuffix(f.Name(), fileSuffix) && strings.HasPrefix(f.Name(), crdPrefix) {
			fname := strings.TrimPrefix(f.Name(), crdPrefix)
			name := strings.TrimSuffix(fname, fileSuffix)
			_, _ = out.Write([]byte("\t" + name + " = "))
			b, _ := os.ReadFile(crdPath + f.Name())
			fstr := strconv.Quote(string(b))
			_, _ = out.Write([]byte(fstr))
			_, _ = out.Write([]byte("\n"))
		}
	}
	_, _ = out.Write([]byte(")\n"))
}
