// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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
	"fmt"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	errr "github.com/projectcalico/calico/release/pkg/errors"
)

var product = utils.ProductName

// SendErrorNotification sends a slack notification for a given error.
// The error type determines the message to send.
func SendErrorNotification(cfg *slack.Config, notificationErr error, ciURL, repoRoot string) error {
	switch {
	case errors.As(notificationErr, &errr.ErrHashreleaseMissingImages{}):
		_err := notificationErr.(*errr.ErrHashreleaseMissingImages)
		msgData := &slack.MissingImagesMessageData{
			BaseMessageData: slack.BaseMessageData{
				ReleaseName:     _err.Hashrelease.Name,
				Product:         product,
				Stream:          _err.Hashrelease.Stream,
				ProductVersion:  _err.Hashrelease.ProductVersion,
				OperatorVersion: _err.Hashrelease.OperatorVersion,
				ReleaseType:     "hashrelease",
				CIURL:           ciURL,
			},
			MissingImages: _err.MissingImages,
		}
		return slack.PostMissingImagesMessage(cfg, msgData)
	case errors.As(notificationErr, &errr.ErrHashreleaseExists{}):
		_err := notificationErr.(*errr.ErrHashreleaseExists)
		msgData := &slack.FailureMessageData{
			BaseMessageData: slack.BaseMessageData{
				ReleaseName:     _err.ReleaseName,
				Product:         product,
				Stream:          _err.Stream,
				ProductVersion:  _err.ProductVersion,
				OperatorVersion: _err.OperatorVersion,
				ReleaseType:     _err.ReleaseType,
				CIURL:           ciURL,
			},
			Error: _err.Error(),
		}
		return slack.PostFailureMessage(cfg, msgData)
	default:
		branch, err := utils.GitBranch(repoRoot)
		if err != nil {
			return fmt.Errorf("failed to get git branch to help determine stream: %w", err)
		}
		ver, err := command.GitVersion(repoRoot, true)
		if err != nil {
			return fmt.Errorf("failed to get git version to help determine stream: %w", err)
		}
		msgData := &slack.FailureMessageData{
			BaseMessageData: slack.BaseMessageData{
				Product:        product,
				Stream:         version.DeterminePublishStream(branch, ver),
				ProductVersion: ver,
				CIURL:          ciURL,
			},
			Error: notificationErr.Error(),
		}
		return slack.PostFailureMessage(cfg, msgData)
	}
}

// AnnounceHashrelease sends a slack notification for a new hashrelease.
func AnnounceHashrelease(cfg *slack.Config, hashrel *hashreleaseserver.Hashrelease, ciURL string) error {
	msgData := &slack.HashreleasePublishedMessageData{
		BaseMessageData: slack.BaseMessageData{
			ReleaseName:     hashrel.Name,
			Product:         product,
			Stream:          hashrel.Stream,
			ProductVersion:  hashrel.ProductVersion,
			OperatorVersion: hashrel.OperatorVersion,
			ReleaseType:     "hashrelease",
			CIURL:           ciURL,
		},
		DocsURL:            hashrel.URL(),
		ImageScanResultURL: hashrel.ImageScanResultURL,
	}
	return slack.PostHashreleaseAnnouncement(cfg, msgData)
}
