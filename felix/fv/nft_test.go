// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"os"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
)

func NFTMode() bool {
	return os.Getenv("FELIX_FV_NFTABLES") == "Enabled"
}

func logNFTDiags(f *infrastructure.Felix) {
	f.Exec("nft", "list", "ruleset")
}
