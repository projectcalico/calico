// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/tlsutils"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
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
		args = append(args, "-v", CertDir+":"+CertDir)
	}

	if options.WithFelixTyphaTLS {
		args = append(args,
			"-e", "TYPHA_CAFILE="+filepath.Join(CertDir, "ca.crt"),
			"-e", "TYPHA_SERVERKEYFILE="+filepath.Join(CertDir, "server.key"),
			"-e", "TYPHA_SERVERCERTFILE="+filepath.Join(CertDir, "server.crt"),
			"-e", "TYPHA_CLIENTCN=typha-client",
		)
		options.ExtraEnvVars["FELIX_TYPHACAFILE"] = filepath.Join(CertDir, "ca.crt")
		options.ExtraEnvVars["FELIX_TYPHAKEYFILE"] = filepath.Join(CertDir, "client.key")
		options.ExtraEnvVars["FELIX_TYPHACERTFILE"] = filepath.Join(CertDir, "client.crt")
		options.ExtraEnvVars["FELIX_TYPHACN"] = "typha-server"
		options.ExtraVolumes[CertDir] = CertDir
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

var CertDir = ""

func EnsureTLSCredentials() {
	if CertDir != "" {
		// Already in place.
		return
	}

	// Generate credentials needed for Felix-Typha TLS.
	var err error
	CertDir, err = os.MkdirTemp("", "felixfv")
	tlsutils.PanicIfErr(err)

	// Trusted CA.
	caCert, caKey := tlsutils.MakeCACert("trustedCA")
	tlsutils.WriteCert(caCert.Raw, filepath.Join(CertDir, "ca.crt"))

	// Untrusted CA.
	untrustedCert, untrustedKey := tlsutils.MakeCACert("untrustedCA")

	// Typha server.
	serverCert, serverKey := tlsutils.MakePeerCert("typha-server", "", x509.ExtKeyUsageServerAuth, caCert, caKey)
	tlsutils.WriteKey(serverKey, filepath.Join(CertDir, "server.key"))
	tlsutils.WriteCert(serverCert, filepath.Join(CertDir, "server.crt"))

	// Typha client with good CN.
	clientCert, clientKey := tlsutils.MakePeerCert("typha-client", "", x509.ExtKeyUsageClientAuth, caCert, caKey)
	tlsutils.WriteKey(clientKey, filepath.Join(CertDir, "client.key"))
	tlsutils.WriteCert(clientCert, filepath.Join(CertDir, "client.crt"))

	// Untrusted Typha client.
	clientUntrustedCert, clientUntrustedKey := tlsutils.MakePeerCert("typha-client", "", x509.ExtKeyUsageClientAuth, untrustedCert, untrustedKey)
	tlsutils.WriteKey(clientUntrustedKey, filepath.Join(CertDir, "client-untrusted.key"))
	tlsutils.WriteCert(clientUntrustedCert, filepath.Join(CertDir, "client-untrusted.crt"))

	// Ensure that all users can read these credentials.  (Needed because Typha now
	// runs as non-root.)
	err = exec.Command("chmod", "-R", "a+rx", CertDir).Run()
	tlsutils.PanicIfErr(err)
}

func RemoveTLSCredentials() {
	if CertDir != "" {
		err := os.RemoveAll(CertDir)
		tlsutils.PanicIfErr(err)
	}
}
