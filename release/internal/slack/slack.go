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
	_ "embed"
)

// Config is the configuration for the Slack client
type Config struct {
	// Token is the token for the Slack API
	Token string

	// Channel is the channel to post messages
	Channel string
}

func (c Config) Valid() bool {
	return c.Token != "" && c.Channel != ""
}
