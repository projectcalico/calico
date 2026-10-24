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

// Package runonvm runs a script on a GCE VM over SSH: the generic "runOn: vm"
// primitive. It ships files and secrets, runs a script (a FILE, never a command
// string, so nothing must survive three levels of shell quoting), pulls artifacts
// back on ANY exit, and exits with the script's own status.
//
// Meant to be the `command` of an Argo `script` template: Argo writes `source:` to
// a temp file and appends its path as the last argument, so that block just runs on
// the VM. Everything job-specific is a flag, so this stays generic.
//
//	command: [scratch-utils, runonvm,          # subcommand is an ARGUMENT: the
//	          --put-env, ENV_VAR:remote/path,  # ENTRYPOINT is the binary, so a bare
//	          --env,     ENV_VAR,              # command: [runonvm] fails to exec
//	          --get,     remote/dir:local/dir]
//	source: |
//	  ...
package runonvm

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/gce"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/util"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// setupTimeout bounds the compute-API phase (find zone, inject key, dial SSH). It
// deliberately excludes running the script: that is the CI job, and it takes as
// long as it takes.
const setupTimeout = 10 * time.Minute

// Run executes the runonvm subcommand and returns its exit code.
func Run() int {
	return run(context.Background())
}

func run(ctx context.Context) int {
	var puts, putEnvs, envs, gets stringList
	scriptFlag := flag.String("script", "", "script to run on the VM (Argo appends the source file as a trailing arg; --script is the CLI equivalent)")
	user := flag.String("user", util.EnvOr("VM_SSH_USER", "ubuntu"), "SSH user")
	flag.Var(&puts, "put", "LOCAL:REMOTE file or dir to upload before running (repeatable)")
	flag.Var(&putEnvs, "put-env", "ENVVAR:REMOTE -- write an env var's value to a 0600 remote file (repeatable)")
	flag.Var(&envs, "env", "ENVVAR to forward into an env file the script sources before running (repeatable)")
	flag.Var(&gets, "get", "REMOTE:LOCAL dir to pull back on exit, best-effort (repeatable)")
	flag.Parse()

	// Argo passes the staged source file as the trailing arg.
	script := *scriptFlag
	if flag.NArg() > 0 {
		script = flag.Arg(0)
	}
	if script == "" {
		fmt.Fprintln(os.Stderr, "runonvm: need a script (trailing arg or --script)")
		return 2
	}

	name := os.Getenv("VM_NAME")
	if name == "" {
		fmt.Fprintln(os.Stderr, "runonvm: VM_NAME must be set")
		return 2
	}
	project := util.EnvOr("GCP_VM_PROJECT", "unique-caldron-775")

	if err := util.SetupComputeADC(); err != nil {
		fmt.Fprintf(os.Stderr, "runonvm: %v\n", err)
		return 1
	}
	client, err := gce.New(ctx, project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runonvm: %v\n", err)
		return 1
	}

	// Bounds setup only; the script run below is unbounded.
	setupCtx, cancelSetup := context.WithTimeout(ctx, setupTimeout)
	defer cancelSetup()

	zone := os.Getenv("ZONE")
	if zone == "" {
		zone, err = client.FindLiveZone(setupCtx, name)
		if err != nil || zone == "" {
			fmt.Fprintf(os.Stderr, "runonvm: could not find zone for %s (set ZONE): %v\n", name, err)
			return 1
		}
	}

	fmt.Printf("[runonvm] connecting to %s in %s\n", name, zone)
	conn, err := client.DialSSH(setupCtx, zone, name, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runonvm: %v\n", err)
		return 1
	}
	defer conn.Close()
	cancelSetup()

	// On ANY exit, so a mid-run failure still returns logs.
	defer func() {
		for _, g := range gets {
			remote, local, ok := splitPair(g)
			if !ok {
				continue
			}
			if err := conn.GetDir(remote, local); err != nil {
				fmt.Fprintf(os.Stderr, "[runonvm] get %s: %v (continuing)\n", remote, err)
			} else {
				fmt.Printf("[runonvm] pulled %s -> %s\n", remote, local)
			}
		}
	}()

	// Ship files and secrets before running.
	for _, p := range puts {
		local, remote, ok := splitPair(p)
		if !ok {
			fmt.Fprintf(os.Stderr, "runonvm: bad --put %q (want LOCAL:REMOTE)\n", p)
			return 2
		}
		info, err := os.Stat(local)
		if err != nil {
			fmt.Fprintf(os.Stderr, "runonvm: --put %s: %v\n", local, err)
			return 1
		}
		if info.IsDir() {
			err = conn.PutDir(local, remote)
		} else {
			err = conn.PutFile(local, remote, 0o644)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "runonvm: %v\n", err)
			return 1
		}
		fmt.Printf("[runonvm] put %s -> %s\n", local, remote)
	}
	for _, pe := range putEnvs {
		envVar, remote, ok := splitPair(pe)
		if !ok {
			fmt.Fprintf(os.Stderr, "runonvm: bad --put-env %q (want ENVVAR:REMOTE)\n", pe)
			return 2
		}
		val, present := os.LookupEnv(envVar)
		if !present {
			fmt.Fprintf(os.Stderr, "runonvm: --put-env %s: env var not set\n", envVar)
			return 1
		}
		if err := conn.PutData([]byte(val), remote, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "runonvm: %v\n", err)
			return 1
		}
		fmt.Printf("[runonvm] put-env %s -> %s (0600)\n", envVar, remote)
	}

	// Forward env vars through a file the script sources -- the generic path for a
	// commit SHA, tokens, etc. Values are shell-quoted, so any content is safe. An
	// unset var is skipped; the script decides whether that is fatal.
	remoteEnv := "/tmp/runonvm.env"
	haveEnv := false
	if len(envs) > 0 {
		var b strings.Builder
		for _, name := range envs {
			// The value is quoted, but the NAME is interpolated bare, so a name like
			// "FOO; rm -rf /" would run when the script sources this file.
			if err := util.CheckShellName(name); err != nil {
				fmt.Fprintf(os.Stderr, "runonvm: --env %v\n", err)
				return 2
			}
			val, present := os.LookupEnv(name)
			if !present {
				fmt.Fprintf(os.Stderr, "[runonvm] --env %s not set, skipping\n", name)
				continue
			}
			fmt.Fprintf(&b, "export %s=%s\n", name, util.ShellQuote(val))
			haveEnv = true
		}
		if haveEnv {
			if err := conn.PutData([]byte(b.String()), remoteEnv, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "runonvm: write env file: %v\n", err)
				return 1
			}
		}
	}

	// A file, not a command string.
	remoteScript := path.Join("/tmp", path.Base(script))
	if err := conn.PutFile(script, remoteScript, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "runonvm: upload script: %v\n", err)
		return 1
	}

	qScript := util.ShellQuote(remoteScript)
	runCmd := "bash " + qScript
	if haveEnv {
		runCmd = fmt.Sprintf(". %s && bash %s", util.ShellQuote(remoteEnv), qScript)
	}
	fmt.Printf("[runonvm] running %s on %s\n", remoteScript, name)
	code, err := conn.Run(runCmd, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runonvm: run: %v\n", err)
		return 1
	}
	fmt.Printf("[runonvm] script finished (rc=%d)\n", code)
	return code
}

// splitPair splits "A:B" on the first colon.
func splitPair(s string) (a, b string, ok bool) {
	before, after, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", false
	}
	return before, after, true
}
