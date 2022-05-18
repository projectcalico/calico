// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	"net"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/kardianos/osext"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/stringutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
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
	return fmt.Errorf("Failed to parse config parameter %v; value %#v: %v", m.Name, raw, msg)
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

type BoolPtrParam struct {
	Metadata
}

func (p *BoolPtrParam) Parse(raw string) (interface{}, error) {
	t := true
	f := false
	switch strings.ToLower(raw) {
	case "true", "1", "yes", "y", "t":
		return &t, nil
	case "false", "0", "no", "n", "f":
		return &f, nil
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
	if result < p.Min {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at least %v", p.Min))
	} else if result > p.Max {
		err = p.parseFailed(raw,
			fmt.Sprintf("value must be at most %v", p.Max))
	} else {
		result := int(value)
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

type SecondsParam struct {
	Metadata
}

func (p *SecondsParam) Parse(raw string) (result interface{}, err error) {
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	result = time.Duration(seconds * float64(time.Second))
	return
}

type MillisParam struct {
	Metadata
}

func (p *MillisParam) Parse(raw string) (result interface{}, err error) {
	millis, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	result = time.Duration(millis * float64(time.Millisecond))
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

// RegexpPatternParam differs from RegexpParam (above) in that it validates
// string values that are (themselves) regular expressions.
type RegexpPatternParam struct {
	Metadata
	Flags []string
}

// Parse validates whether the given raw string contains a valid regexp pattern.
func (p *RegexpPatternParam) Parse(raw string) (interface{}, error) {
	var result *regexp.Regexp
	if raw == "" {
		for _, f := range p.Flags {
			if f == "nil-on-empty" {
				return nil, nil
			}
		}
	}
	result, compileErr := regexp.Compile(raw)
	if compileErr != nil {
		return nil, p.parseFailed(raw, "invalid regexp")
	}
	return result, nil
}

// RegexpPatternListParam differs from RegexpParam (above) in that it validates
// string values that are (themselves) regular expressions.
type RegexpPatternListParam struct {
	Metadata
	RegexpElemRegexp    *regexp.Regexp
	NonRegexpElemRegexp *regexp.Regexp
	Delimiter           string
	Msg                 string
}

// Parse validates whether the given raw string contains a list of valid values.
// Validation is dictated by two regexp patterns: one for valid regular expression
// values, another for non-regular expressions.
func (p *RegexpPatternListParam) Parse(raw string) (interface{}, error) {
	var result []*regexp.Regexp
	// Split into individual elements, then validate each one and compile to regexp
	tokens := strings.Split(raw, p.Delimiter)
	for _, t := range tokens {
		if p.RegexpElemRegexp.Match([]byte(t)) {
			// Need to remove the start and end symbols that wrap the actual regexp
			// Note: There's a coupling here with the assumed pattern in RegexpElemRegexp
			// i.e. that each value is wrapped by a single char symbol on either side
			regexpValue := t[1 : len(t)-1]
			compiledRegexp, compileErr := regexp.Compile(regexpValue)
			if compileErr != nil {
				return nil, p.parseFailed(raw, p.Msg)
			}
			result = append(result, compiledRegexp)
		} else if p.NonRegexpElemRegexp.Match([]byte(t)) {
			compiledRegexp, compileErr := regexp.Compile("^" + regexp.QuoteMeta(t) + "$")
			if compileErr != nil {
				return nil, p.parseFailed(raw, p.Msg)
			}
			result = append(result, compiledRegexp)
		} else {
			return nil, p.parseFailed(raw, p.Msg)
		}
	}
	return result, nil
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
	res := net.ParseIP(raw)
	if res == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	if !utils.IsIPv4(res) {
		err = p.parseFailed(raw, "not an IPv4 address")
	}
	result = res
	return
}

type Ipv6Param struct {
	Metadata
}

func (p *Ipv6Param) Parse(raw string) (result interface{}, err error) {
	res := net.ParseIP(raw)
	if res == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	if !utils.IsIPv6(res) {
		err = p.parseFailed(raw, "not an IPv6 address")
	}
	result = res
	return
}

type PortListParam struct {
	Metadata
}

func (p *PortListParam) Parse(raw string) (interface{}, error) {
	var result []ProtoPort
	for _, portStr := range strings.Split(raw, ",") {
		portStr = strings.Trim(portStr, " ")
		if portStr == "" {
			continue
		}

		protocolStr := "tcp"
		netStr := ""

		// Check if IPv6 network is set
		if strings.Contains(portStr, "[") && strings.Contains(portStr, "]") {
			// Grab the IPv6 network
			startIndex := strings.Index(portStr, "[")
			endIndex := strings.Index(portStr, "]:")
			netStr = portStr[startIndex+1 : endIndex]

			// Remove the IPv6 network value from portStr
			var withoutIPv6 strings.Builder
			withoutIPv6.WriteString(portStr[:startIndex])
			withoutIPv6.WriteString(portStr[endIndex+2:])
			portStr = withoutIPv6.String()
		}

		parts := strings.Split(portStr, ":")
		if len(parts) > 3 {
			return nil, p.parseFailed(raw,
				"ports should be <protocol>:<net>:<number> or <protocol>:<number> or <number>")
		}

		if len(parts) > 2 {
			netStr = parts[1]
			protocolStr = strings.ToLower(parts[0])
			portStr = parts[2]
		}

		if len(parts) == 2 {
			protocolStr = strings.ToLower(parts[0])
			portStr = parts[1]
		}

		if protocolStr != "tcp" && protocolStr != "udp" {
			return nil, p.parseFailed(raw, "unknown protocol: "+protocolStr)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			err = p.parseFailed(raw, "ports should be integers")
			return nil, err
		}
		if port < 0 || port > 65535 {
			err = p.parseFailed(raw, "ports must be in range 0-65535")
			return nil, err
		}

		protoPort := ProtoPort{
			Protocol: protocolStr,
			Port:     uint16(port),
		}

		if netStr != "" {
			_, netParsed, err := cnet.ParseCIDROrIP(netStr)
			if err != nil {
				err = p.parseFailed(raw, "invalid CIDR or IP "+netStr)
				return nil, err
			}
			protoPort.Net = netParsed.String()
		}

		result = append(result, protoPort)
	}
	return result, nil
}

type PortRangeParam struct {
	Metadata
}

func (p *PortRangeParam) Parse(raw string) (interface{}, error) {
	portRange, err := numorstring.PortFromString(raw)
	if err != nil {
		return nil, p.parseFailed(raw, fmt.Sprintf("%s is not a valid port range", raw))
	}
	if len(portRange.PortName) > 0 {
		return nil, p.parseFailed(raw, fmt.Sprintf("%s has port name set", raw))
	}
	return portRange, nil
}

type PortRangeListParam struct {
	Metadata
}

func (p *PortRangeListParam) Parse(raw string) (interface{}, error) {
	var result []numorstring.Port
	for _, rangeStr := range strings.Split(raw, ",") {
		portRange, err := numorstring.PortFromString(rangeStr)
		if err != nil {
			return nil, p.parseFailed(raw, fmt.Sprintf("%s is not a valid port range", rangeStr))
		}
		if len(portRange.PortName) > 0 {
			return nil, p.parseFailed(raw, fmt.Sprintf("%s has port name set", rangeStr))
		}
		result = append(result, portRange)
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

type CIDRListParam struct {
	Metadata
}

func (c *CIDRListParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("CIDRs raw", raw).Info("CIDRList")
	values := strings.Split(raw, ",")
	resultSlice := []string{}
	for _, in := range values {
		val := strings.Trim(in, " ")
		if len(val) == 0 {
			continue
		}
		ip, net, e := cnet.ParseCIDROrIP(val)
		if e != nil {
			err = c.parseFailed(in, "invalid CIDR or IP "+val)
			return
		}
		if ip.Version() != 4 {
			err = c.parseFailed(in, "invalid CIDR or IP (not v4)")
			return
		}
		resultSlice = append(resultSlice, net.String())
	}
	return resultSlice, nil
}

type RegionParam struct {
	Metadata
}

const regionNamespacePrefix = "openstack-region-"
const maxRegionLength int = validation.DNS1123LabelMaxLength - len(regionNamespacePrefix)

func (r *RegionParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("raw", raw).Info("Region")
	if len(raw) > maxRegionLength {
		err = fmt.Errorf("The value of OpenstackRegion must be %v chars or fewer", maxRegionLength)
		return
	}
	errs := validation.IsDNS1123Label(raw)
	if len(errs) != 0 {
		msg := "The value of OpenstackRegion must be a valid DNS label"
		for _, err := range errs {
			msg = msg + "; " + err
		}
		err = errors.New(msg)
		return
	}
	return raw, nil
}

// linux can support route-tables with indices up to 0xfffffff, however, using all of them would likely blow up, so cap the limit at 65535
const routeTableMaxLinux = 0xffffffff
const routeTableRangeMaxTables = 0xffff

type RouteTableRangeParam struct {
	Metadata
}

func (p *RouteTableRangeParam) Parse(raw string) (result interface{}, err error) {
	err = p.parseFailed(raw, "must be a range of route table indices within 1-250")
	m := regexp.MustCompile(`^(\d+)-(\d+)$`).FindStringSubmatch(raw)
	if m == nil {
		return
	}
	min, serr := strconv.Atoi(m[1])
	if serr != nil {
		return
	}
	max, serr := strconv.Atoi(m[2])
	if serr != nil {
		return
	}
	if min >= 1 && max >= min && max <= 250 {
		result = idalloc.IndexRange{Min: min, Max: max}
		err = nil
	}
	return
}

type RouteTableRangesParam struct {
	Metadata
}

// reserved linux kernel routing tables (will be ignored if targeted by routetablerange)
var routeTablesReservedLinux = []int{253, 254, 255}

func (p *RouteTableRangesParam) Parse(raw string) (result interface{}, err error) {
	match := regexp.MustCompile(`(\d+)-(\d+)`).FindAllStringSubmatch(raw, -1)
	if match == nil {
		err = p.parseFailed(raw, "must be a list of route-table ranges")
		return
	}

	tablesTargeted := 0
	ranges := make([]idalloc.IndexRange, 0)
	for _, r := range match {
		// first match is the whole matching string - we only care about submatches
		min, serr := strconv.Atoi(r[1])
		if serr != nil || min <= 0 {
			err = p.parseFailed(raw, "min value is not a valid number")
			return
		}
		max, serr := strconv.Atoi(r[2])
		if serr != nil {
			err = p.parseFailed(raw, "max value is not a valid number")
			return
		}
		// max val must be greater than min val
		if min > max {
			err = p.parseFailed(raw, "min value is greater than max value")
			return
		}

		if int64(max) > int64(routeTableMaxLinux) {
			err = p.parseFailed(raw, "max value is too high")
			return
		}

		tablesTargeted += max - min
		if tablesTargeted > routeTableRangeMaxTables {
			err = p.parseFailed(raw, "targets too many tables")
			return
		}

		// check if ranges collide with reserved linux tables
		includesReserved := false
		for _, rsrv := range routeTablesReservedLinux {
			if min <= rsrv && max >= rsrv {
				includesReserved = true
			}
		}
		if includesReserved {
			log.Infof("Felix route-table range includes reserved Linux tables, values 253-255 will be ignored.")
		}

		ranges = append(ranges, idalloc.IndexRange{Min: min, Max: max})
	}

	result = ranges
	return
}

type KeyValueListParam struct {
	Metadata
}

func (p *KeyValueListParam) Parse(raw string) (result interface{}, err error) {
	result, err = stringutils.ParseKeyValueList(raw)
	return
}
