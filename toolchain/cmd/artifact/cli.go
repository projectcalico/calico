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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const usage = `artifact - store / fetch CI artifacts, modelled on the Semaphore ` + "`artifact`" + `
toolbox command (https://docs.semaphore.io/reference/toolbox#artifact), with a
` + "`cache`" + ` level modelled on its ` + "`cache`" + ` command
(https://docs.semaphore.io/reference/toolbox#cache).

Three storage levels are supported:
  job       -> $CI_ARTIFACT_STEP_STORAGE   (isolated to the current step/job)
  workflow  -> $CI_ARTIFACT_STORAGE        (shared across the whole workflow)
  cache     -> $CI_CACHE_STORAGE/$CI_GIT_REPO_NAME  (the repo; persists across runs)

Each level's full location is injected by the pre-processor, so this tool
knows nothing about buckets or layout: changing where things are stored is a
handler deploy, not a rebuild of every CI image.

It talks to Google Cloud Storage with the conventions we always want:
  - parallel transfers wherever more than one object moves
  - directories are handled recursively (like gsutil rsync -r), files are copied
  - fails immediately if the level's storage env var is unset

Usage:
  artifact push <job|workflow> <path>... [--destination <remote-path>] [--labels k=v,...] [--force]
      Upload one or more files/directories to the level's storage. With a
      single source the remote path defaults to its basename and --destination
      overrides it, letting you rename the artifact or place it under a
      subfolder, e.g.
        artifact push job ./report/ --destination semaphore/gateway-conformance-reports
      With multiple sources (e.g. a glob), each is uploaded by basename and
      --destination is treated as a remote subfolder prefix, e.g.
        artifact push job target/cargo-timings/cargo-timing*.html --destination timings
      --labels attaches GCS custom metadata (x-goog-meta-<k>:<v>) to every
      uploaded object.

  artifact pull <job|workflow> <remote-path> [--destination <local-path>] [--force]
      Download <remote-path> from the level's storage. The local path defaults
      to the basename of <remote-path>; --destination overrides it. Directories
      are pulled recursively.

  artifact yank <job|workflow> <remote-path> [--destination <local-path>] [--force]
      Download <remote-path> locally (like pull) and then delete it from the
      level's storage.

  artifact list <job|workflow> [<subpath>]
      List what is stored under the level's storage[/<subpath>].

  artifact cache store <key> <path>...
      Archive the given paths into a single cache object named <key>, replacing
      any existing one. Paths must be relative, because restore unpacks into
      the working directory and an absolute path could not be put back where it
      came from.

  artifact cache restore <key>[,<fallback-key>...]
      Unpack the first key that exists into the working directory. Keys are
      matched exactly — unlike Semaphore there is no prefix fallback, so name
      every candidate in the list.

  artifact cache has_key <key>
      Exit 0 if <key> exists, 1 if it does not.

  artifact cache delete <key>
      Remove <key>. Removing one that is already gone is not an error.

  artifact cache list
      List this repo's keys.

Cache notes:
  - A MISS from restore exits 0. Test for the file you wanted rather than the
    exit status: a repo with a cold cache is not a failing build. has_key is
    the operation whose exit status answers a question.
  - A key is a single object, so storing over one replaces it atomically.
    Semaphore has to delete before storing because its cache never overwrites;
    that dance is not needed here.
  - Entries are stored as uncompressed tar and are never expired by this tool.
    A lifecycle rule on the injected prefix is what cleans them up, which is
    why a key may not point outside it.

Examples:
  artifact push job ./report.html
  artifact push job ./report/ --destination semaphore/gateway-conformance-reports
  artifact push job target/cargo-timings/cargo-timing*.html --labels stage=e2e
  artifact push workflow build/app --destination bin/app
  artifact pull workflow bin/app
  artifact yank job semaphore/gateway-conformance-reports
  artifact list job
  artifact cache store deps-"$(md5sum go.sum | cut -c1-8)" vendor
  artifact cache restore deps-"$(md5sum go.sum | cut -c1-8)",deps-main
  artifact cache has_key deps-main && echo "warm"
`

// exitCode ends the run with a status and no error message, for answers that
// are not failures, such as a has_key miss.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

type app struct {
	getenv func(string) string
	stdout io.Writer
	// stderr takes progress lines from parallel transfers, so it must be safe
	// for concurrent use.
	stderr io.Writer
	open   bucketOpener
}

func (a *app) run(ctx context.Context, args []string) int {
	err := a.dispatch(ctx, args)
	if err == nil {
		return 0
	}
	var code exitCode
	if errors.As(err, &code) {
		return int(code)
	}
	fmt.Fprintf(a.stderr, "[ERROR] artifact: %v\n", err)
	return 1
}

func (a *app) dispatch(ctx context.Context, args []string) error {
	cmd, args := shift(args)
	switch cmd {
	case "", "help", "-h", "--help":
		fmt.Fprint(a.stdout, usage)
		return nil
	case "push", "pull", "yank", "list":
	case "cache":
		return a.cache(ctx, args)
	default:
		fmt.Fprintf(a.stderr, "[ERROR] artifact: unknown command '%s'\n", cmd)
		fmt.Fprint(a.stderr, usage)
		return exitCode(1)
	}

	lvl, args := shift(args)
	var envVar string
	switch lvl {
	case "job":
		envVar = "CI_ARTIFACT_STEP_STORAGE"
	case "workflow":
		envVar = "CI_ARTIFACT_STORAGE"
	case "":
		return fmt.Errorf("%s: missing storage level (expected 'job' or 'workflow')", cmd)
	default:
		return fmt.Errorf("%s: unknown storage level '%s' (expected 'job' or 'workflow')", cmd, lvl)
	}
	base := a.getenv(envVar)
	if base == "" {
		return fmt.Errorf("%s is not set", envVar)
	}
	loc, err := parseLocation(strings.TrimSuffix(base, "/"))
	if err != nil {
		return fmt.Errorf("%s: %w", envVar, err)
	}

	f, err := parseFlags(args)
	if err != nil {
		return err
	}
	labels, err := parseLabels(f.labels)
	if err != nil {
		return err
	}

	l := &level{app: a, cmd: cmd, loc: loc, force: f.force, labels: labels}
	switch cmd {
	case "push":
		return l.push(ctx, f.positional, f.destination)
	case "pull", "yank":
		return l.pull(ctx, f.positional, f.destination)
	default:
		sub := ""
		if len(f.positional) > 0 {
			sub = f.positional[0]
		}
		return l.list(ctx, sub)
	}
}

type flags struct {
	destination string
	labels      string
	force       bool
	positional  []string
}

// parseFlags accepts flags anywhere among the positional arguments, like the
// script's loop did, so `artifact push job --force a b` and
// `artifact push job a b --force` mean the same.
func parseFlags(args []string) (flags, error) {
	var f flags
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--destination="):
			f.destination = strings.TrimPrefix(arg, "--destination=")
		case arg == "--destination" || arg == "-d":
			if i+1 >= len(args) {
				return f, fmt.Errorf("option '%s' needs a value", arg)
			}
			i++
			f.destination = args[i]
		case strings.HasPrefix(arg, "--labels="):
			f.labels = strings.TrimPrefix(arg, "--labels=")
		case arg == "--labels":
			if i+1 >= len(args) {
				return f, fmt.Errorf("option '%s' needs a value", arg)
			}
			i++
			f.labels = args[i]
		case arg == "--force" || arg == "-f":
			f.force = true
		case arg == "--":
			f.positional = append(f.positional, args[i+1:]...)
			return f, nil
		case strings.HasPrefix(arg, "-"):
			return f, fmt.Errorf("unknown option '%s'", arg)
		default:
			f.positional = append(f.positional, arg)
		}
	}
	return f, nil
}

// parseLabels turns k=v,k2=v2 into custom metadata, which is what gsutil's
// -h x-goog-meta-<k>:<v> header set.
func parseLabels(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	labels := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--labels entry '%s' must be key=value", p)
		}
		labels[k] = v
	}
	return labels, nil
}

func shift(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

// basename matches basename(1), which path.Base does not for "" and "/".
func basename(p string) string {
	if p == "" {
		return ""
	}
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/"
	}
	return t[strings.LastIndex(t, "/")+1:]
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
