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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/snapshotdump"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
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
	socket      string
	server      string
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

By default it connects to the local Typha over the pod-private unix domain
socket (` + syncserver.DefaultSocketPath + `), which needs no TLS — this is the
intended in-pod usage. Pass --server to connect to a Typha over TCP instead, in
which case the TLS flags are used if Typha requires mutual TLS.

The --format flag controls the output encoding:
  ndjson       newline-delimited JSON, one object per key (default; human-readable)
  gzip-base64  the NDJSON stream, gzipped and base64-encoded, wrapped into short
               lines so it survives "kubectl exec" (decode with: base64 -d | gunzip)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientDump(cmd.Context(), f)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&f.socket, "socket", syncserver.DefaultSocketPath, "Path to Typha's local unix domain socket (used when --server is not set)")
	flags.StringVar(&f.server, "server", "", "Connect to a Typha over TCP at this host:port instead of the local unix socket")
	flags.StringVar(&f.syncerType, "type", "", "Syncer type to dump (felix, bgp, tunnel-ip-allocation, node-status); default: all types")
	flags.StringVar(&f.format, "format", string(snapshotdump.FormatNDJSON), "Output format: ndjson or gzip-base64")
	flags.StringVar(&f.logLevel, "log-level", "warn", "Log level for diagnostic logging (sent to stderr)")
	flags.DurationVar(&f.idleTimeout, "idle-timeout", 10*time.Second, "Per-syncer-type bound: if no updates arrive for this long and the snapshot is not yet in-sync, stop and emit a timed-out event. 0 disables the bound")

	flags.StringVar(&f.keyFile, "key-file", "", "TLS (with --server): private key file used to authenticate to the server")
	flags.StringVar(&f.certFile, "cert-file", "", "TLS (with --server): certificate file used to authenticate to the server")
	flags.StringVar(&f.caFile, "ca-file", "", "TLS (with --server): CA certificate file used to authenticate the server")
	flags.StringVar(&f.serverCN, "server-cn", "", "TLS (with --server): expected server common name")
	flags.StringVar(&f.serverURISAN, "server-uri", "", "TLS (with --server): expected server URI SAN")

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
		st := syncproto.SyncerType(f.syncerType)
		if !knownSyncerType(st) {
			return fmt.Errorf("unknown syncer type %q; supported types: %s", f.syncerType, supportedSyncerTypes())
		}
		syncerTypes = []syncproto.SyncerType{st}
	}

	if err := validateTLSFlags(f); err != nil {
		return err
	}

	server, clientOpts := resolveConnection(f)

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

// resolveConnection works out the address to dial and the client TLS options.
// With no --server it dials the local unix socket (no TLS); with --server it
// dials TCP and uses whatever TLS flags were supplied.
func resolveConnection(f dumpFlags) (string, syncclient.Options) {
	if f.server == "" {
		// Local unix socket: plaintext, no client identity needed.
		return "unix://" + f.socket, syncclient.Options{}
	}
	return f.server, syncclient.Options{
		KeyFile:      f.keyFile,
		CertFile:     f.certFile,
		CAFile:       f.caFile,
		ServerCN:     f.serverCN,
		ServerURISAN: f.serverURISAN,
	}
}

// knownSyncerType reports whether st is a syncer type Typha serves.  Validating
// up front lets the CLI fail with a clear message and the list of valid types,
// rather than connecting and having the server reject the unknown type with a
// less obvious ErrUnsupportedClientFeature.
func knownSyncerType(st syncproto.SyncerType) bool {
	for _, k := range syncproto.AllSyncerTypes {
		if k == st {
			return true
		}
	}
	return false
}

func supportedSyncerTypes() string {
	names := make([]string, len(syncproto.AllSyncerTypes))
	for i, st := range syncproto.AllSyncerTypes {
		names[i] = string(st)
	}
	return strings.Join(names, ", ")
}

// validateTLSFlags rejects an incomplete set of TLS flags up front with a normal
// error, instead of letting syncclient.New log.Fatal deep in the stack.  The
// rule mirrors syncclient.Options.validate: if any TLS flag is set they must all
// be set, except that either --server-cn or --server-uri may be omitted.  TLS
// only applies to the --server (TCP) path; the local unix socket is plaintext,
// so flags supplied without --server are simply ignored.
func validateTLSFlags(f dumpFlags) error {
	if f.server == "" {
		return nil
	}
	anySet := f.keyFile != "" || f.certFile != "" || f.caFile != "" || f.serverCN != "" || f.serverURISAN != ""
	if !anySet {
		return nil // Plaintext TCP: fine if the server doesn't require TLS.
	}
	if f.keyFile == "" || f.certFile == "" || f.caFile == "" || (f.serverCN == "" && f.serverURISAN == "") {
		return errors.New("incomplete TLS configuration: --key-file, --cert-file and --ca-file " +
			"are required together (plus either --server-cn or --server-uri)")
	}
	return nil
}
