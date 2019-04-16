// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package versionparse

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"

	version "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

var (
	kernelVersionRegexp = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)
)

func MustParseVersion(v string) *version.Version {
	ver, err := version.NewVersion(v)
	if err != nil {
		log.WithError(err).Panic("Failed to parse version.")
	}
	return ver
}

func GetKernelVersionReader() (io.Reader, error) {
	return os.Open("/proc/version")
}

func GetKernelVersion(reader io.Reader) (*version.Version, error) {
	kernVersion, err := ioutil.ReadAll(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to read kernel version from reader")
		return nil, err
	}
	s := string(kernVersion)
	log.WithField("rawVersion", s).Debug("Raw kernel version")
	matches := kernelVersionRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		msg := "Failed to parse kernel version string"
		log.WithField("rawVersion", s).Warn(msg)
		return nil, fmt.Errorf("%s", msg)
	}
	parsedVersion, err := version.NewVersion(matches[1])
	if err != nil {
		msg := "Failed to parse kernel version"
		log.WithField("rawVersion", s).WithError(err).Warn(msg)
		return nil, fmt.Errorf("%s", msg)
	}
	log.WithField("version", parsedVersion).Debug("Parsed kernel version")
	return parsedVersion, nil
}
