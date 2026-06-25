// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package typha

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/daemon"
	"github.com/projectcalico/calico/typha/pkg/snapshotdump"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// newClientCommand returns the "client" subcommand: a small set of tools that
// connect to a Typha instance as a sync client.  It replaces the old ad-hoc
// typha-client binary.
func newClientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Tools that connect to a Typha instance as a sync client",
	}
	cmd.AddCommand(newClientDumpCommand())
	return cmd
}

// dumpFlags holds the resolved flags for the "client dump" command.
type dumpFlags struct {
	server      string
	configFile  string
	syncerType  string
	format      string
	logLevel    string
	idleTimeout time.Duration

	keyFile      string
	certFile     string
	caFile       string
	serverCN     string
	serverURISAN string
}

func newClientDumpCommand() *cobra.Command {
	var f dumpFlags

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump the snapshot(s) a Typha instance is serving",
		Long: `Connects to a Typha instance and dumps the snapshot it serves, one syncer
type at a time, to stdout.

When run inside a Typha pod with no explicit --server or TLS flags, it reads
Typha's own configuration to find the listen port and certificate files and
connects to the local Typha over the loopback interface, presenting Typha's own
server certificate as its client identity.

The --format flag controls the output encoding:
  ndjson       newline-delimited JSON, one object per key (default; human-readable)
  gzip-base64  the NDJSON stream, gzipped and base64-encoded, wrapped into short
               lines so it survives "kubectl exec" (decode with: base64 -d | gunzip)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientDump(cmd.Context(), f)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&f.server, "server", "", "Typha address to connect to as host:port (default: derived from Typha config, e.g. localhost:5473)")
	flags.StringVarP(&f.configFile, "config-file", "c", daemon.DefaultConfigFile, "Typha config file to read connection defaults from")
	flags.StringVar(&f.syncerType, "type", "", "Syncer type to dump (felix, bgp, tunnel-ip-allocation, node-status); default: all types")
	flags.StringVar(&f.format, "format", string(snapshotdump.FormatNDJSON), "Output format: ndjson or gzip-base64")
	flags.StringVar(&f.logLevel, "log-level", "warn", "Log level for diagnostic logging (sent to stderr)")
	flags.DurationVar(&f.idleTimeout, "idle-timeout", 10*time.Second, "Per-syncer-type bound: if no updates arrive for this long and the snapshot is not yet in-sync, stop and emit a timed-out event. 0 disables the bound")

	flags.StringVar(&f.keyFile, "key-file", "", "TLS: private key file used to authenticate to the server")
	flags.StringVar(&f.certFile, "cert-file", "", "TLS: certificate file used to authenticate to the server")
	flags.StringVar(&f.caFile, "ca-file", "", "TLS: CA certificate file used to authenticate the server")
	flags.StringVar(&f.serverCN, "server-cn", "", "TLS: expected server common name")
	flags.StringVar(&f.serverURISAN, "server-uri", "", "TLS: expected server URI SAN")

	return cmd
}

func runClientDump(ctx context.Context, f dumpFlags) error {
	// Keep stdout clean for the dump: all logging goes to stderr.
	logrus.SetOutput(os.Stderr)
	if lvl, err := logrus.ParseLevel(f.logLevel); err == nil {
		logrus.SetLevel(lvl)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	format, err := snapshotdump.ParseFormat(f.format)
	if err != nil {
		return err
	}

	var syncerTypes []syncproto.SyncerType
	if f.syncerType != "" {
		syncerTypes = []syncproto.SyncerType{syncproto.SyncerType(f.syncerType)}
	}

	// Resolve the server address and TLS options, falling back to Typha's own
	// config when the user hasn't overridden them.
	server, clientOpts, err := resolveConnection(f)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	cfg := snapshotdump.Config{
		Server:      server,
		SyncerTypes: syncerTypes,
		Format:      format,
		Out:         os.Stdout,
		ClientOpts:  clientOpts,
		IdleTimeout: f.idleTimeout,
		MyVersion:   buildinfo.Version,
		MyHostname:  hostname,
	}
	return snapshotdump.Dump(ctx, cfg)
}

// resolveConnection works out the server address and client TLS options.  If
// the user supplied any TLS flags they are used verbatim; otherwise we load
// Typha's own config to discover the port and (for a loopback self-connection)
// the server certificate, key and CA.
func resolveConnection(f dumpFlags) (string, syncclient.Options, error) {
	opts := syncclient.Options{
		KeyFile:      f.keyFile,
		CertFile:     f.certFile,
		CAFile:       f.caFile,
		ServerCN:     f.serverCN,
		ServerURISAN: f.serverURISAN,
	}
	userSuppliedTLS := f.keyFile != "" || f.certFile != "" || f.caFile != "" || f.serverCN != "" || f.serverURISAN != ""

	// Always try to load Typha's config; we need it for the port default and,
	// unless the user overrode TLS, for the certificate files.
	typhaCfg := loadTyphaConfig(f.configFile)

	server := f.server
	if server == "" {
		host := typhaCfg.ServerHost
		if host == "" {
			host = "localhost"
		}
		port := typhaCfg.ServerPort
		if port == 0 {
			port = syncproto.DefaultPort
		}
		server = net.JoinHostPort(host, strconv.Itoa(port))
	}

	if !userSuppliedTLS && typhaCfg.ServerCertFile != "" {
		// Typha is serving TLS and the user didn't override: present Typha's own
		// server certificate as our client identity (the server is configured to
		// accept its own cert for loopback self-connections).
		opts.CertFile = typhaCfg.ServerCertFile
		opts.KeyFile = typhaCfg.ServerKeyFile
		opts.CAFile = typhaCfg.CAFile
		cn, uriSAN, err := certIdentity(typhaCfg.ServerCertFile)
		if err != nil {
			return "", opts, fmt.Errorf("failed to read Typha server certificate %q: %w", typhaCfg.ServerCertFile, err)
		}
		opts.ServerCN = cn
		opts.ServerURISAN = uriSAN
	}

	return server, opts, nil
}

// loadTyphaConfig loads Typha's config from the environment and the given config
// file, mirroring the daemon's loading order.  Errors are logged and ignored so
// that the dump command still works in a bare environment with explicit flags.
func loadTyphaConfig(configFile string) *config.Config {
	cfg := config.New()
	if envConfig := config.LoadConfigFromEnvironment(os.Environ()); len(envConfig) > 0 {
		if _, err := cfg.UpdateFrom(envConfig, config.EnvironmentVariable); err != nil {
			logrus.WithError(err).Debug("Failed to parse Typha config from environment")
		}
	}
	if fileConfig, err := config.LoadConfigFile(configFile); err != nil {
		logrus.WithError(err).WithField("configFile", configFile).Debug("Failed to load Typha config file")
	} else if _, err := cfg.UpdateFrom(fileConfig, config.ConfigFile); err != nil {
		logrus.WithError(err).WithField("configFile", configFile).Debug("Failed to parse Typha config file")
	}
	return cfg
}

// certIdentity parses a PEM certificate file and returns its common name and
// first URI SAN, for use as the expected server identity.  At least one of the
// two is needed to satisfy the sync client's TLS validation.
func certIdentity(certFile string) (cn, uriSAN string, err error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", "", fmt.Errorf("no PEM block found in %q", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	cn = cert.Subject.CommonName
	if len(cert.URIs) > 0 {
		uriSAN = cert.URIs[0].String()
	}
	if cn == "" && uriSAN == "" {
		return "", "", fmt.Errorf("certificate %q has neither a common name nor a URI SAN", certFile)
	}
	return cn, uriSAN, nil
}
