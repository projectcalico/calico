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

package slack

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

var (
	//go:embed templates/success.json.gotmpl
	successMessageTemplateData string

	//go:embed templates/failed-images.json.gotmpl
	failedImagesMessageTemplateData string

	//go:embed templates/failure.json.gotmpl
	failureMessageTemplateData string
)

// Config is the configuration for the Slack client
type Config struct {
	// Token is the token for the Slack API
	Token string `envconfig:"SLACK_API_TOKEN"`

	// Channel is the channel to post messages
	Channel string `envconfig:"SLACK_CHANNEL"`
}

// Message is a Slack message
type Message interface {
	Send(cfg Config) error
	TemplateText() string
}

type BaseMessageData struct {
	ReleaseName string
	Versions    version.Data
	Product     string
	Stream      string
	ReleaseType utils.ReleaseType
	CIURL       string
}

type BaseMessage struct {
	Data BaseMessageData
}

func (m BaseMessage) TemplateText() string {
	logrus.Fatal("TemplateText not implemented")
	return ""
}

func (m BaseMessage) Send(cfg Config) error {
	message, err := m.renderMessage()
	if err != nil {
		return err
	}
	client := slack.New(cfg.Token, slack.OptionDebug(logrus.IsLevelEnabled(logrus.DebugLevel)))
	_, _, err = client.PostMessage(cfg.Channel, slack.MsgOptionBlocks(message...))
	return err
}

func (m BaseMessage) renderMessage() ([]slack.Block, error) {
	tmpl, err := template.New("message").Parse(m.TemplateText())
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, m.Data); err != nil {
		return nil, err
	}
	blocks := slack.Blocks{}
	if err := blocks.UnmarshalJSON(buf.Bytes()); err != nil {
		return nil, err
	}
	return blocks.BlockSet, nil
}

type FailureMessageData struct {
	BaseMessageData
	Error string
}

type FailureMessage struct {
	BaseMessage
	Data FailureMessageData
}

func (m FailureMessage) TemplateText() string {
	return failureMessageTemplateData
}

type FailedImagesMessageData struct {
	BaseMessageData
	FailedImages []registry.Component
}

type FailedImagesMessage struct {
	BaseMessage
	Data FailedImagesMessageData
}

func (m FailedImagesMessage) TemplateText() string {
	return failedImagesMessageTemplateData
}

type SuccessMessageData struct {
	BaseMessageData
	DocsURL            string
	ImageScanResultURL string
}

type SuccessMessage struct {
	BaseMessage
	Data SuccessMessageData
}

func (m SuccessMessage) TemplateText() string {
	return successMessageTemplateData
}
