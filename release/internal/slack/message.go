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

package slack

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"

	"github.com/slack-go/slack"

	"github.com/projectcalico/calico/lib/std/log"
)

//go:embed templates/hashrelease-published.json.gotmpl
var publishedMessageTemplateData string

// HashreleasePublishedMessageData contains the fields for sending a message about a hashrelease being published.
type HashreleaseMessageData struct {
	ReleaseName        string
	Product            string
	Stream             string
	ProductVersion     string
	OperatorVersion    string
	ReleaseType        string
	CIURL              string
	DocsURL            string
	ImageScanResultURL string
}

// PostHashreleaseAnnouncement sends a message to slack about a hashrelease being published.
func PostHashreleaseAnnouncement(cfg *Config, msg *HashreleaseMessageData) error {
	message, err := renderMessage(publishedMessageTemplateData, msg)
	if err != nil {
		log.WithError(err).Error("Failed to render message")
		return err
	}
	return sendToSlack(cfg, message)
}

// renderMessage renders a message template with the provided data.
func renderMessage(text string, data any) ([]slack.Block, error) {
	tmpl, err := template.New("message").Parse(text)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	blocks := slack.Blocks{}
	if err := blocks.UnmarshalJSON(buf.Bytes()); err != nil {
		return nil, err
	}
	return blocks.BlockSet, nil
}

// sendToSlack sends a message to slack.
func sendToSlack(cfg *Config, message []slack.Block) error {
	if cfg == nil {
		return fmt.Errorf("no configuration provided")
	}
	if !cfg.Valid() {
		return fmt.Errorf("invalid or missing configuration")
	}

	client := slack.New(cfg.Token, slack.OptionDebug(log.IsLevelEnabled(log.DebugLevel)))
	_, _, err := client.PostMessage(cfg.Channel, slack.MsgOptionBlocks(message...))
	return err
}
