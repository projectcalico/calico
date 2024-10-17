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
	"errors"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	errrs "github.com/projectcalico/calico/release/pkg/errors"
)

// Notify sends a notification based on the error
func Notify(err error, cfg *config.Config) error {
	var m slack.Message
	var errInvalidImages errrs.ErrInvalidImages
	var errHashreleaseAlreadyExists errrs.ErrHashreleaseAlreadyExists
	if errors.As(err, &errInvalidImages) {
		m = slack.FailedImagesMessage{
			Data: slack.FailedImagesMessageData{
				BaseMessageData: slack.BaseMessageData{
					ReleaseName: errInvalidImages.ReleaseName,
					Product:     utils.ProductName,
					Stream:      errInvalidImages.Stream,
					ReleaseType: utils.ReleaseTypeHashrelease,
					CIURL:       cfg.CI.URL(),
					Versions:    errInvalidImages.Versions,
				},
				FailedImages: errInvalidImages.FailedImages,
			},
		}
	} else if errors.As(err, &errHashreleaseAlreadyExists) {
		m = slack.FailureMessage{
			Data: slack.FailureMessageData{
				BaseMessageData: slack.BaseMessageData{
					ReleaseName: errHashreleaseAlreadyExists.ReleaseName,
					Product:     utils.ProductName,
					Stream:      errHashreleaseAlreadyExists.Stream,
					ReleaseType: utils.ReleaseTypeHashrelease,
					CIURL:       cfg.CI.URL(),
					Versions:    errHashreleaseAlreadyExists.Versions,
				},
				Error: errHashreleaseAlreadyExists.Error(),
			},
		}
	} else {
		// attempt to get the branch and version to determine the stream
		branch, _ := utils.GitBranch(cfg.RepoRootDir)
		ver := version.GitVersion()
		m = slack.FailureMessage{
			Data: slack.FailureMessageData{
				BaseMessageData: slack.BaseMessageData{
					Product: utils.ProductName,
					Stream:  version.DeterminePublishStream(branch, ver.FormattedString()),
					CIURL:   cfg.CI.URL(),
				},
				Error: err.Error(),
			},
		}
	}
	return m.Send(cfg.SlackConfig)
}

// AnnouceHashrelease sends a notification to announce a release
func AnnouceHashrelease(hashrelease hashreleaseserver.Hashrelease, cfg *config.Config) error {
	m := slack.SuccessMessage{
		Data: slack.SuccessMessageData{
			BaseMessageData: slack.BaseMessageData{
				ReleaseName: hashrelease.Name,
				Product:     utils.ProductName,
				Stream:      hashrelease.Stream(),
				ReleaseType: utils.ReleaseTypeHashrelease,
				CIURL:       cfg.CI.URL(),
				Versions:    hashrelease.Versions,
			},
			DocsURL:            hashrelease.URL(),
			ImageScanResultURL: imagescanner.RetrieveResultURL(cfg.OutputDir),
		},
	}
	return m.Send(cfg.SlackConfig)
}
