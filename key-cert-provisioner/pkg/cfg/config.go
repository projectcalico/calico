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

package cfg

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	certV1 "k8s.io/api/certificates/v1"
)

// Config holds parameters that are used during runtime.
type Config struct {
	CSRName             string
	EmptyDirLocation    string
	Signer              string
	CommonName          string
	EmailAddress        string
	PodIP               string
	KeyName             string
	CertName            string
	CACertName          string
	CACertPEM           []byte
	DNSNames            []string
	SignatureAlgorithm  string
	PrivateKeyAlgorithm string
	X509KeyUsage        x509.KeyUsage
	Certv1Usage         []certV1.KeyUsage
	RegisterApiserver   bool
	AppName             string
	TimeoutDuration     time.Duration
}

const (
	RSAWithSize2048   = "RSAWithSize2048"
	RSAWithSize4096   = "RSAWithSize4096"
	RSAWithSize8192   = "RSAWithSize8192"
	ECDSAWithCurve256 = "ECDSAWithCurve256"
	ECDSAWithCurve384 = "ECDSAWithCurve384"
	ECDSAWithCurve521 = "ECDSAWithCurve521"
)

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
	keyAlgorithm, x509Usage, certv1Usage := GetPrivateKeyInfo(os.Getenv("KEY_ALGORITHM"))
	return &Config{
		CSRName:             csrName,
		SignatureAlgorithm:  os.Getenv("SIGNATURE_ALGORITHM"),
		Signer:              GetEnvOrDie("SIGNER"),
		CommonName:          GetEnvOrDie("COMMON_NAME"),
		EmailAddress:        os.Getenv("EMAIL_ADDRESS"),
		EmptyDirLocation:    GetEnvOrDie("CERTIFICATE_PATH"),
		KeyName:             GetEnvOrDie("KEY_NAME"),
		CertName:            GetEnvOrDie("CERT_NAME"),
		CACertName:          caCertName,
		CACertPEM:           caCert,
		PodIP:               GetEnvOrDie("POD_IP"),
		AppName:             GetEnvOrDie("APP_NAME"),
		PrivateKeyAlgorithm: keyAlgorithm,
		Certv1Usage:         certv1Usage,
		X509KeyUsage:        x509Usage,
		DNSNames:            dnsNames,
		TimeoutDuration:     timeoutDuration,
	}
}

func GetPrivateKeyInfo(keyAlgorithm string) (string, x509.KeyUsage, []certV1.KeyUsage) {
	var x509Usage x509.KeyUsage
	var certv1Usage []certV1.KeyUsage
	switch keyAlgorithm {
	case RSAWithSize2048, RSAWithSize4096, RSAWithSize8192:
		x509Usage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		certv1Usage = []certV1.KeyUsage{certV1.UsageServerAuth, certV1.UsageClientAuth, certV1.UsageDigitalSignature, certV1.UsageKeyEncipherment}
		break
	case ECDSAWithCurve256, ECDSAWithCurve384, ECDSAWithCurve521:
		x509Usage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		certv1Usage = []certV1.KeyUsage{certV1.UsageServerAuth, certV1.UsageClientAuth, certV1.UsageDigitalSignature, certV1.UsageKeyAgreement}
		break
	default:
		log.Warnf("Unknown or missing private key algorithm, defaulting to RSAWithSize2048")
		keyAlgorithm = RSAWithSize2048
		x509Usage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		certv1Usage = []certV1.KeyUsage{certV1.UsageServerAuth, certV1.UsageClientAuth, certV1.UsageDigitalSignature, certV1.UsageKeyEncipherment}
	}
	return keyAlgorithm, x509Usage, certv1Usage
}
