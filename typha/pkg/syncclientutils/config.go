// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package syncclientutils

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// TyphaConfig specifies the sync-client connection parameters
type TyphaConfig struct {
	Addr           string
	K8sServiceName string
	K8sNamespace   string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// Client-side TLS config for communication with Typha.  If any of these are
	// specified, they _all_ must be - except that either CN or URISAN may be left unset.
	// confd will then initiate a secure (TLS) connection to Typha.  Typha must present a
	// certificate signed by a CA in CAFile, and with CN matching CN or URI SAN matching
	// URISAN.
	KeyFile  string
	CertFile string
	CAFile   string
	CN       string
	URISAN   string
}

// ReadTyphaConfig reads the TyphaConfig from environment variables.
//
// The supportedPrefixes is the set of allowed prefixes for each environment name. Name format is therefore:
// <prefix>TYPHA<fieldname uppercase>,  e.g.  CONFD_TYPHAADDR
func ReadTyphaConfig(supportedPrefixes []string) TyphaConfig {
	typhaConfig := &TyphaConfig{}
	kind := reflect.TypeOf(*typhaConfig)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		nameUpper := strings.ToUpper(field.Name)
		for _, prefix := range supportedPrefixes {
			varName := prefix + "TYPHA" + nameUpper
			if value := os.Getenv(varName); value != "" && value != "none" {
				log.Infof("Found %v=%v", varName, value)
				if field.Type.Name() == "Duration" {
					seconds, err := strconv.ParseFloat(value, 64)
					if err != nil {
						log.Error("Invalid float")
					}
					duration := time.Duration(seconds * float64(time.Second))
					reflect.ValueOf(typhaConfig).Elem().FieldByName(field.Name).Set(reflect.ValueOf(duration))
				} else {
					reflect.ValueOf(typhaConfig).Elem().FieldByName(field.Name).Set(reflect.ValueOf(value))
				}
				break
			}
		}
	}

	// Perform defaulting of the typha config for any required fields that were not set explicitly.
	if typhaConfig.K8sNamespace == "" {
		typhaConfig.K8sNamespace = "kube-system"
	}

	return *typhaConfig
}
