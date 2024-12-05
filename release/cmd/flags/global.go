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

package flags

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	DebugFlagName = "debug"

	DebugFlag = &cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"d"},
		Usage:   "Enable verbose log output",
		Value:   false,
	}
)

// Slack flags
var (
	SlackTokenFlagName = "slack-token"
	SlackTokenFlag     = &cli.StringFlag{
		Name:    "slack-token",
		Usage:   "The Slack token to use for posting messages",
		EnvVars: []string{"SLACK_TOKEN"},
	}

	SlackChannelFlagName = "slack-channel"
	SlackChannelFlag     = &cli.StringFlag{
		Name:    "slack-channel",
		Usage:   "The Slack channel to post messages",
		EnvVars: []string{"SLACK_CHANNEL"},
	}

	SlackFlags = []cli.Flag{SlackTokenFlag, SlackChannelFlag}
)

// CI flags
var (
	semaphoreCI = "semaphore"

	CIFlagName = "ci"
	CIFlag     = &cli.BoolFlag{
		Name:    "ci",
		Usage:   "Enable CI mode",
		EnvVars: []string{"CI"},
		Value:   false,
	}

	CIURLFlagName = "ci-url"
	CIURLFlag     = &cli.StringFlag{
		Name:    "ci-url",
		Usage:   fmt.Sprintf("The URL for accesing %s CI", semaphoreCI),
		EnvVars: []string{"SEMAPHORE_ORGANIZATION_URL"},
	}

	CIJobIDFlagName = "ci-job-id"
	CIJobIDFlag     = &cli.StringFlag{
		Name:    "ci-job-id",
		Usage:   fmt.Sprintf("The job ID for the %s CI job", semaphoreCI),
		EnvVars: []string{"SEMAPHORE_JOB_ID"},
	}

	CIFlags = []cli.Flag{CIFlag, CIURLFlag, CIJobIDFlag}
)

// GlobalFlags are flags that are available to all commands
func GlobalFlags() []cli.Flag {
	f := []cli.Flag{DebugFlag}
	f = append(f, SlackFlags...)
	f = append(f, CIFlags...)
	return f
}
