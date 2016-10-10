// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package config

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/kardianos/osext"
	"net"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const (
	MinIptablesMarkBits = 2
)

type Metadata struct {
	Name              string
	Default           interface{}
	ZeroValue         interface{}
	NonZero           bool
	DieOnParseFailure bool
	Local             bool
}

func (m *Metadata) GetMetadata() *Metadata {
	return m
}

func (m *Metadata) parseFailed(raw, msg string) error {
	return errors.New(
		fmt.Sprintf("Failed to parse config parameter %v; value %#v: %v",
			m.Name, raw, msg))
}

func (m *Metadata) setDefault(config *Config) {
	log.Debugf("Defaulting: %v to %v", m.Name, m.Default)
	field := reflect.ValueOf(config).Elem().FieldByName(m.Name)
	value := reflect.ValueOf(m.Default)
	field.Set(value)
}

type BoolParam struct {
	Metadata
}

func (p *BoolParam) Parse(raw string) (interface{}, error) {
	switch strings.ToLower(raw) {
	case "true", "1", "yes", "y", "t":
		return true, nil
	case "false", "0", "no", "n", "f":
		return false, nil
	}
	return nil, p.parseFailed(raw, "invalid boolean")
}

type IntParam struct {
	Metadata
	Min int
	Max int
}

func (p *IntParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid int")
		return nil, err
	}
	result := int(value)
	if result < p.Min {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at least %v", p.Min))
	} else if result > p.Max {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at most %v", p.Max))
	}
	return result, err
}

type Int32Param struct {
	Metadata
}

func (p *Int32Param) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 32)
	if err != nil {
		err = p.parseFailed(raw, "invalid 32-bit int")
		return nil, err
	}
	result := int32(value)
	return result, err
}

type FloatParam struct {
	Metadata
}

func (p *FloatParam) Parse(raw string) (result interface{}, err error) {
	result, err = strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	return
}

type RegexpParam struct {
	Metadata
	Regexp *regexp.Regexp
	Msg    string
}

func (p *RegexpParam) Parse(raw string) (result interface{}, err error) {
	if !p.Regexp.MatchString(raw) {
		err = p.parseFailed(raw, p.Msg)
	} else {
		result = raw
	}
	return
}

type FileParam struct {
	Metadata
	MustExist  bool
	Executable bool
}

func (p *FileParam) Parse(raw string) (interface{}, error) {
	if p.Executable {
		// Special case: for executable files, we search our directory
		// and the system path.
		logCxt := log.WithField("name", raw)
		var path string
		if myDir, err := osext.ExecutableFolder(); err == nil {
			logCxt.WithField("myDir", myDir).Info(
				"Looking for executable in my directory")
			path = myDir + string(os.PathSeparator) + raw
			stat, err := os.Stat(path)
			if err == nil {
				if m := stat.Mode(); !m.IsDir() && m&0111 > 0 {
					return path, nil
				}
			} else {
				logCxt.WithField("myDir", myDir).Info(
					"No executable in my directory")
				path = ""
			}
		} else {
			logCxt.WithError(err).Warn("Failed to get my dir")
		}
		if path == "" {
			logCxt.Info("Looking for executable on path")
			var err error
			path, err = exec.LookPath(raw)
			if err != nil {
				logCxt.WithError(err).Warn("Path lookup failed")
				path = ""
			}
		}
		if path == "" && p.MustExist {
			log.Error("Executable missing")
			return nil, p.parseFailed(raw, "missing file")
		}
		log.WithField("path", path).Info("Executable path")
		return path, nil
	} else if p.MustExist && raw != "" {
		log.WithField("path", raw).Info("Looking for required file")
		_, err := os.Stat(raw)
		if err != nil {
			log.Errorf("Failed to access %v: %v", raw, err)
			return nil, p.parseFailed(raw, "failed to access file")
		}
	}
	return raw, nil
}

type Ipv4Param struct {
	Metadata
}

func (p *Ipv4Param) Parse(raw string) (result interface{}, err error) {
	result = net.ParseIP(raw)
	if result == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	return
}

type PortListParam struct {
	Metadata
}

func (p *PortListParam) Parse(raw string) (interface{}, error) {
	result := []int{}
	for _, portStr := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			err = p.parseFailed(raw, "ports should be integers")
			return nil, err
		}
		if port < 0 || port > 65535 {
			err = p.parseFailed(raw, "ports must be in range 0-65535")
			return nil, err
		}
		result = append(result, int(port))
	}
	return result, nil
}

type EndpointListParam struct {
	Metadata
}

func (p *EndpointListParam) Parse(raw string) (result interface{}, err error) {
	value := strings.Split(raw, ",")
	scheme := ""
	resultSlice := []string{}
	for _, endpoint := range value {
		endpoint = strings.Trim(endpoint, " ")
		if len(endpoint) == 0 {
			continue
		}
		var u *url.URL
		u, err = url.Parse(endpoint)
		if err != nil {
			err = p.parseFailed(raw,
				fmt.Sprintf("%v is not a valid URL", endpoint))
			return
		}
		if scheme != "" && u.Scheme != scheme {
			err = p.parseFailed(raw,
				"all endpoints must have the same scheme")
			return
		}
		if u.Path == "" {
			u.Path = "/"
		}
		if u.Opaque != "" || u.User != nil || u.Path != "/" ||
			u.RawPath != "" || u.RawQuery != "" ||
			u.Fragment != "" {
			log.WithField("url", fmt.Sprintf("%#v", u)).Error(
				"Unsupported URL part")
			err = p.parseFailed(raw,
				"endpoint contained unsupported URL part; "+
					"expected http(s)://hostname:port only.")
			return
		}
		resultSlice = append(resultSlice, u.String())
	}
	result = resultSlice
	return
}

type MarkBitmaskParam struct {
	Metadata
}

func (p *MarkBitmaskParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		log.Warningf("Failed to parse %#v as an int: %v", raw, err)
		err = p.parseFailed(raw, "invalid mark: should be 32-bit int")
		return nil, err
	}
	result := uint32(value)
	bitCount := uint32(0)
	for i := uint(0); i < 32; i++ {
		bit := (result >> i) & 1
		bitCount += bit
	}
	if bitCount < MinIptablesMarkBits {
		err = p.parseFailed(raw,
			fmt.Sprintf("invalid mark: needs to have %v bits set",
				MinIptablesMarkBits))
	}
	return result, err
}

type OneofListParam struct {
	Metadata
	lowerCaseOptionsToCanonical map[string]string
}

func (p *OneofListParam) Parse(raw string) (result interface{}, err error) {
	result, ok := p.lowerCaseOptionsToCanonical[strings.ToLower(raw)]
	if !ok {
		err = p.parseFailed(raw, "unknown option")
	}
	return
}
