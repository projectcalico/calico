// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package tasks

import (
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
)

// AnnouceHashrelease sends a notification to announce a release
func AnnouceHashrelease(slackCfg slack.Config, hashrelease hashreleaseserver.Hashrelease, CIURL, tmpDir string) error {
	m := slack.SuccessMessage{
		Data: slack.SuccessMessageData{
			BaseMessageData: slack.BaseMessageData{
				ReleaseName: hashrelease.Name,
				Product:     utils.Calico,
				Stream:      hashrelease.Stream(),
				ReleaseType: utils.ReleaseTypeHashrelease,
				CIURL:       CIURL,
				Versions:    hashrelease.Versions,
			},
			DocsURL:            hashrelease.URL(),
			ImageScanResultURL: imagescanner.RetrieveResultURL(tmpDir),
		},
	}
	return m.Send(slackCfg)
}
