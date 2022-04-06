// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	kernelVersionRegexp = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+(?:-\d+)?)`)
	splitRe             = regexp.MustCompile(`[\.-]`)
)

type Version struct {
	versionSlice []int
	versionStr   string
}

func (v *Version) String() string {
	return v.versionStr
}

func NewVersion(ver string) (*Version, error) {
	var v Version
	var err error
	v.versionSlice, err = convertVersionToIntSlice(ver)
	v.versionStr = ver
	return &v, err
}

func MustParseVersion(v string) *Version {
	ver, err := NewVersion(v)
	if err != nil {
		log.WithError(err).Panic("Failed to parse version.")
	}
	return ver
}

func (v *Version) Compare(other *Version) int {
	vlen := len(v.versionSlice)
	olen := len(other.versionSlice)
	compLen := vlen
	if compLen > olen {
		compLen = olen
	}
	for index := 0; index < compLen; index++ {
		if v.versionSlice[index] == other.versionSlice[index] {
			continue
		}
		if v.versionSlice[index] > other.versionSlice[index] {
			return 1
		}
		if v.versionSlice[index] < other.versionSlice[index] {
			return -1
		}
	}
	if vlen < olen {
		return -1
	}
	if vlen > olen {
		return 1
	}
	return 0
}

func convertVersionToIntSlice(s string) ([]int, error) {
	parts := splitRe.Split(s, 4)
	intSlice := make([]int, len(parts))
	for index, element := range parts {
		val, err := strconv.Atoi(element)
		if err != nil {
			return nil, fmt.Errorf(
				"Error parsing version: %s", err)
		}
		intSlice[index] = val
	}
	return intSlice, nil
}

func GetKernelVersionReader() (io.Reader, error) {
	return os.Open("/proc/version")
}

func GetVersionFromString(s string) (*Version, error) {
	log.WithField("rawVersion", s).Debug("Raw kernel version")
	matches := kernelVersionRegexp.FindStringSubmatch(s)
	if len(matches) == 0 {
		msg := "Failed to parse kernel version string"
		log.WithField("rawVersion", s).Warn(msg)
		return nil, fmt.Errorf("%s", msg)
	}
	parsedVersion, err := NewVersion(matches[1])
	log.WithField("version", parsedVersion).Debug("Parsed kernel version")
	return parsedVersion, err
}

func GetDistFromString(s string) string {
	redhatRegexp := regexp.MustCompile(`el(\d+\_\d+)`)
	distName := "default"
	if strings.Contains(s, "Ubuntu") {
		distName = "ubuntu"
	} else if strings.Contains(s, "Red Hat") || redhatRegexp.MatchString(s) {
		distName = "rhel"
	}
	return distName
}

func GetKernelVersion(reader io.Reader) (*Version, error) {
	kernVersion, err := ioutil.ReadAll(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to read kernel version from reader")
		return nil, err
	}
	s := string(kernVersion)
	return GetVersionFromString(s)
}

func GetDistributionName() string {
	reader, err := GetKernelVersionReader()
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version reader")
		return "default"
	}
	kernVersion, err := ioutil.ReadAll(reader)
	if err != nil {
		log.WithError(err).Warn("Failed to read kernel version from reader")
		return "default"
	}
	s := string(kernVersion)

	return GetDistFromString(s)
}
