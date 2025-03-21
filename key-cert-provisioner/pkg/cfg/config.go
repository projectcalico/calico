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

package cfg

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Config holds parameters that are used during runtime.
type Config struct {
	CSRName             string
	CSRLabels           map[string]string
	Signer              string
	CommonName          string
	EmailAddress        string
	IPAddresses         []net.IP
	KeyPath             string
	CertPath            string
	CACertPath          string
	CACertPEM           []byte
	DNSNames            []string
	SignatureAlgorithm  string
	PrivateKeyAlgorithm string
	RegisterApiserver   bool
	AppName             string
	TimeoutDuration     time.Duration
}

// GetEnvOrDie convenience method for initializing env.
func GetEnvOrDie(env string) string {
	val := os.Getenv(env)
	if val == "" {
		log.Fatalf("environment variable %v cannot be empty", env)
	}
	return val
}

// GetConfigOrDie initializes the Config that this program relies on. It exists the program if expected variables are missing.
func GetConfigOrDie() *Config {
	dnsNames := strings.Split(os.Getenv("DNS_NAMES"), ",")
	if len(dnsNames) == 0 {
		log.Fatal("environment variable DNS_NAMES cannot be empty")
	}

	// If provided, decode the CA, so it can be written to file.
	b64CACert := os.Getenv("CA_CERT")
	var caCertName string
	var caCert []byte
	if len(b64CACert) > 0 {
		var err error
		caCert, err = base64.URLEncoding.DecodeString(b64CACert)
		if err != nil {
			log.Fatalf("Error while decoding CA Cert: %v", err)
		}
		caCertName = GetEnvOrDie("CA_CERT_NAME")
	}
	secretName := os.Getenv("SECRET_NAME")
	var csrName string
	if secretName == "" {
		csrName = fmt.Sprintf("%s:%s", GetEnvOrDie("POD_NAMESPACE"), GetEnvOrDie("POD_NAME"))
	} else {
		csrName = fmt.Sprintf("%s:%s", secretName, GetEnvOrDie("POD_NAME"))
	}
	timeoutDuration := 90 * time.Second
	timeoutEnv := os.Getenv("TIMEOUT_DURATION")
	if timeoutEnv != "" {
		var err error
		timeoutDuration, err = time.ParseDuration(timeoutEnv)
		if err != nil {
			log.Fatalf("unable to convert TIMEOUT env to an integer: %v", err)
		}

	}
	dir := GetEnvOrDie("CERTIFICATE_PATH")
	return &Config{
		CSRName:             csrName,
		SignatureAlgorithm:  os.Getenv("SIGNATURE_ALGORITHM"),
		Signer:              GetEnvOrDie("SIGNER"),
		CommonName:          GetEnvOrDie("COMMON_NAME"),
		EmailAddress:        os.Getenv("EMAIL_ADDRESS"),
		KeyPath:             filepath.Join(dir, GetEnvOrDie("KEY_NAME")),
		CertPath:            filepath.Join(dir, GetEnvOrDie("CERT_NAME")),
		CACertPath:          filepath.Join(dir, caCertName),
		CACertPEM:           caCert,
		IPAddresses:         []net.IP{net.ParseIP(GetEnvOrDie("POD_IP"))},
		AppName:             GetEnvOrDie("APP_NAME"),
		PrivateKeyAlgorithm: os.Getenv("KEY_ALGORITHM"),
		DNSNames:            dnsNames,
		TimeoutDuration:     timeoutDuration,
	}
}
