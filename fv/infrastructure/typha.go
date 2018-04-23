// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/typha/pkg/tlsutils"
)

type Typha struct {
	*containers.Container
}

func (f *Typha) GetTyphaPID() int {
	return f.GetSinglePID("calico-typha")
}

func (f *Typha) GetTyphaPIDs() []int {
	return f.GetPIDs("calico-typha")
}

func RunTypha(infra DatastoreInfra, options TopologyOptions) *Typha {
	log.Info("Starting typha")

	args := infra.GetDockerArgs()
	args = append(args,
		"--privileged",
		"-e", "TYPHA_LOGSEVERITYSCREEN="+options.TyphaLogSeverity,
		"-e", "TYPHA_PROMETHEUSMETRICSENABLED=true",
	)

	if options.WithFelixTyphaTLS {
		EnsureTLSCredentials()
		args = append(args,
			"-e", "TYPHA_CAFILE="+filepath.Join(certDir, "ca.crt"),
			"-e", "TYPHA_SERVERKEYFILE="+filepath.Join(certDir, "server.key"),
			"-e", "TYPHA_SERVERCERTFILE="+filepath.Join(certDir, "server.crt"),
			"-e", "TYPHA_CLIENTCN=typha-client",
			"-v", certDir+":"+certDir,
		)
		options.ExtraEnvVars["FELIX_TYPHACAFILE"] = filepath.Join(certDir, "ca.crt")
		options.ExtraEnvVars["FELIX_TYPHAKEYFILE"] = filepath.Join(certDir, "client.key")
		options.ExtraEnvVars["FELIX_TYPHACERTFILE"] = filepath.Join(certDir, "client.crt")
		options.ExtraEnvVars["FELIX_TYPHACN"] = "typha-server"
		options.ExtraVolumes[certDir] = certDir
	}

	args = append(args,
		utils.Config.TyphaImage,
	)

	c := containers.Run("typha",
		containers.RunOpts{AutoRemove: true},
		args...,
	)

	return &Typha{
		Container: c,
	}
}

var certDir = ""

func EnsureTLSCredentials() {
	if certDir != "" {
		// Already in place.
		return
	}

	// Generate credentials needed for Felix-Typha TLS.
	var err error
	certDir, err = ioutil.TempDir("", "felixfv")
	tlsutils.PanicIfErr(err)

	// Trusted CA.
	caCert, caKey := tlsutils.MakeCACert("trustedCA")
	tlsutils.WriteCert(caCert.Raw, filepath.Join(certDir, "ca.crt"))

	// Typha server.
	serverCert, serverKey := tlsutils.MakePeerCert("typha-server", "", x509.ExtKeyUsageServerAuth, caCert, caKey)
	tlsutils.WriteKey(serverKey, filepath.Join(certDir, "server.key"))
	tlsutils.WriteCert(serverCert, filepath.Join(certDir, "server.crt"))

	// Typha client with good CN.
	clientCert, clientKey := tlsutils.MakePeerCert("typha-client", "", x509.ExtKeyUsageClientAuth, caCert, caKey)
	tlsutils.WriteKey(clientKey, filepath.Join(certDir, "client.key"))
	tlsutils.WriteCert(clientCert, filepath.Join(certDir, "client.crt"))
}

func RemoveTLSCredentials() {
	if certDir != "" {
		err := os.RemoveAll(certDir)
		tlsutils.PanicIfErr(err)
	}
}
