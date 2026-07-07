// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// CmdExecutor will execute a command and return its output and its error
type CmdExecutor interface {
	Execute(cmdStr string) (string, error)
}

// kubectlCmd is a kubectl wrapper for any query that will be executed
type kubectlCmd struct {
	kubeConfig string
}

// NewKubectlCmd return a CmdExecutor that uses kubectl
func NewKubectlCmd(kubeConfigPath string) *kubectlCmd {
	return &kubectlCmd{kubeConfig: kubeConfigPath}
}

func (k *kubectlCmd) Execute(cmdStr string) (string, error) {
	var out, err = ExecCmd(strings.Replace(cmdStr, "kubectl", fmt.Sprintf("kubectl --kubeconfig %s", k.kubeConfig), 1))
	if out != nil {
		return out.String(), err
	}
	return "", err
}

// ExecCmd is a convenience wrapper that runs a command with no cancellation and
// no inactivity timeout. Diags collection uses a Collector instead (which adds
// both); this is kept for the few one-off callers that don't need either.
func ExecCmd(cmdStr string) (*bytes.Buffer, error) {
	return backgroundCollector().ExecCmd(cmdStr)
}

// Exec is like ExecCmd but takes pre-separated command tokens, so an argument
// may itself contain spaces (e.g. a go-template). No cancellation or timeout.
func Exec(cmdParts []string) (*bytes.Buffer, error) {
	return backgroundCollector().Exec(cmdParts)
}

// backgroundCollector returns a Collector with no cancellation and no
// inactivity timeout, for callers outside a timed collection run.
func backgroundCollector() *Collector {
	return NewCollector(context.Background(), 0, 1)
}

// KubectlExists determines whether tar binary exists on the path.
func KubectlExists() error {
	_, err := exec.LookPath("kubectl")
	if err != nil {
		return fmt.Errorf("unable to locate kubectl in PATH")
	}
	return nil
}

// Cmd is a struct to hold a command to execute, info description to print and a
// filepath location for where output should be written to.
type Cmd struct {
	Info     string
	CmdStr   string
	FilePath string
	SymLink  string

	// FallbackCmdStr, if set, is run when CmdStr exits non-zero — for example
	// when collecting from an older component that doesn't understand a newer
	// flag or subcommand. Its output is written to FallbackFilePath (or to
	// FilePath if FallbackFilePath is empty). This keeps diags useful across
	// version skew: e.g. try a JSON dump, fall back to the plain-text dump.
	FallbackCmdStr   string
	FallbackFilePath string
}

// TimedOutCommand records a command that was killed because it produced no
// output for the collector's inactivity timeout. It is surfaced in the bundle
// (bundle-info.yaml) because a command that hangs is itself a diagnostic clue
// (e.g. a wedged `nft list ruleset`).
type TimedOutCommand struct {
	Info    string `json:"info,omitempty"`
	Command string `json:"command"`
	File    string `json:"file,omitempty"`
}

// Collector runs diagnostic commands under a shared cancellation context (an
// overall deadline plus Ctrl-C) and a per-command inactivity timeout: a command
// that produces no output for noOutputTimeout is killed. Commands killed that
// way are recorded so the bundle can report them.
type Collector struct {
	ctx             context.Context
	noOutputTimeout time.Duration
	maxParallelism  int

	mu       sync.Mutex
	timedOut []TimedOutCommand
}

// NewCollector returns a Collector bound to ctx. A noOutputTimeout <= 0 disables
// the per-command inactivity timeout (used for the always-silent archive step).
func NewCollector(ctx context.Context, noOutputTimeout time.Duration, maxParallelism int) *Collector {
	if maxParallelism < 1 {
		maxParallelism = 1
	}
	return &Collector{ctx: ctx, noOutputTimeout: noOutputTimeout, maxParallelism: maxParallelism}
}

// Ctx returns the collector's context, so callers can use the same cancellation
// (overall deadline / Ctrl-C) for their own operations, e.g. Kubernetes list calls.
func (c *Collector) Ctx() context.Context { return c.ctx }

// TimedOut returns the commands killed by the inactivity timeout so far.
func (c *Collector) TimedOut() []TimedOutCommand {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TimedOutCommand(nil), c.timedOut...)
}

// cmdOutcome is how a single command run ended.
type cmdOutcome int

const (
	outcomeOK        cmdOutcome = iota // ran and exited zero
	outcomeError                       // ran and exited non-zero (or failed to start)
	outcomeNoOutput                    // killed: no output for the inactivity timeout
	outcomeCancelled                   // killed by overall deadline / Ctrl-C
)

// activityWriter forwards writes to an inner writer, calling reset (to postpone
// the inactivity timer) on each write. The same instance is set as both a
// command's Stdout and Stderr; os/exec serialises writes in that case, so no
// locking is needed here.
type activityWriter struct {
	w     io.Writer
	reset func()
}

func (a *activityWriter) Write(p []byte) (int, error) {
	a.reset()
	return a.w.Write(p)
}

// runCommandParts runs a single command to completion under the collector's
// cancellation context and inactivity timeout, returning its combined output
// and how it ended.
func (c *Collector) runCommandParts(parts []string) ([]byte, cmdOutcome, error) {
	if len(parts) == 0 {
		return nil, outcomeError, fmt.Errorf("no command to execute")
	}
	// Don't start new work once the collection is being torn down.
	if c.ctx.Err() != nil {
		return nil, outcomeCancelled, c.ctx.Err()
	}

	cmdCtx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, parts[0], parts[1:]...)
	var buf bytes.Buffer
	w := &activityWriter{w: &buf, reset: func() {}}
	if c.noOutputTimeout > 0 {
		// The timer starts now: a command that never writes anything is killed
		// after noOutputTimeout. Each write postpones it.
		timer := time.AfterFunc(c.noOutputTimeout, cancel)
		defer timer.Stop()
		w.reset = func() { timer.Reset(c.noOutputTimeout) }
	}
	cmd.Stdout = w
	cmd.Stderr = w

	log.Debugf("Executing command: %+v ...", cmd)
	runErr := cmd.Run()

	switch {
	case c.ctx.Err() != nil:
		return buf.Bytes(), outcomeCancelled, c.ctx.Err()
	case cmdCtx.Err() != nil:
		// cmdCtx was cancelled but the parent wasn't: the inactivity timer fired.
		return buf.Bytes(), outcomeNoOutput, cmdCtx.Err()
	case runErr != nil:
		return buf.Bytes(), outcomeError, runErr
	}
	return buf.Bytes(), outcomeOK, nil
}

// Exec runs a command given pre-separated tokens and returns its combined
// output. On any non-success outcome it returns a non-nil error (with whatever
// partial output was captured), matching the "best effort, keep going" style of
// diags collection.
func (c *Collector) Exec(cmdParts []string) (*bytes.Buffer, error) {
	content, outcome, err := c.runCommandParts(cmdParts)
	buf := bytes.NewBuffer(content)
	if outcome == outcomeOK {
		return buf, nil
	}
	return buf, err
}

// ExecCmd is Exec for a single whitespace-separated command string.
func (c *Collector) ExecCmd(cmdStr string) (*bytes.Buffer, error) {
	return c.Exec(strings.Fields(cmdStr))
}

var nextPrefix atomic.Int64

// ExecAllWriteToFile runs each command, writing its output to the command's
// FilePath, up to maxParallelism at a time. It stops launching new commands once
// the collection is cancelled; in-flight commands are cancelled via the context.
func (c *Collector) ExecAllWriteToFile(cmds []Cmd) {
	var eg errgroup.Group
	eg.SetLimit(c.maxParallelism)

	for _, cmd := range cmds {
		if c.ctx.Err() != nil {
			break
		}
		id := nextPrefix.Add(1)
		prefix := fmt.Sprintf("[%d]", id)
		eg.Go(func() error {
			c.execWriteToFile(prefix, cmd)
			return nil // For diags collection, we want to continue even if one command fails
		})
		time.Sleep(20 * time.Millisecond)
	}

	if err := eg.Wait(); err != nil {
		log.Errorf("Unexpected error from background commands: %v", err)
	}
}

// execWriteToFile runs command c and writes its output to c.FilePath (creating
// parent directories and any requested symlink). On version-skew failure it
// falls back to c.FallbackCmdStr. A command killed by the inactivity timeout has
// a marker appended to its output file and is recorded for the bundle report.
func (c *Collector) execWriteToFile(logPrefix string, cmd Cmd) {
	if cmd.Info != "" {
		fmt.Println(logPrefix, cmd.Info)
	}
	logCtx := log.WithField("cmdID", logPrefix)

	dir := filepath.Dir(cmd.FilePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		fmt.Printf("%s Error creating directory for %v: %v\n", logPrefix, cmd.FilePath, err)
		return
	}

	content, outcome, runErr := c.runCommandParts(strings.Fields(cmd.CmdStr))
	filePath := cmd.FilePath

	// Version-skew fallback: the primary exited non-zero and a fallback is set
	// (e.g. an older calico-node that doesn't support --json). Don't bother if
	// the whole collection is being cancelled.
	if outcome == outcomeError && cmd.FallbackCmdStr != "" {
		logCtx.Debugf("Command failed, trying fallback: %s", cmd.FallbackCmdStr)
		fContent, fOutcome, fErr := c.runCommandParts(strings.Fields(cmd.FallbackCmdStr))
		if fOutcome != outcomeError {
			content, outcome, runErr = fContent, fOutcome, fErr
			if cmd.FallbackFilePath != "" {
				filePath = cmd.FallbackFilePath
			}
		}
	}

	switch outcome {
	case outcomeNoOutput:
		content = append(content, noOutputMarker(c.noOutputTimeout)...)
		c.recordTimeout(cmd, filePath)
		fmt.Printf("%s WARNING: command produced no output for %s and was killed: %s\n"+
			"  Re-run with a larger --command-timeout to wait longer.\n",
			logPrefix, c.noOutputTimeout, cmd.CmdStr)
	case outcomeCancelled:
		logCtx.Debugf("Command cancelled: %s", cmd.CmdStr)
		// Skip writing an empty file for work that never got to run.
		if len(content) == 0 {
			return
		}
	case outcomeError:
		fmt.Printf("%s Failed to run command: %s\nError: %s\n", logPrefix, cmd.CmdStr, string(content))
		log.WithError(runErr).Debug("command failed")
	}

	// This is for commands we run but don't want to save the output of.
	if filePath == "" {
		logCtx.Debugln("Command executed, skipping writing output (no filepath specified)")
		return
	}

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		logCtx.Errorf("Error writing diags to file: %s\n", err)
	}
	logCtx.Debugf("Command output written to %s", filePath)

	if cmd.SymLink != "" {
		dir = filepath.Dir(cmd.SymLink)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			fmt.Printf("%s Error creating directory for %v: %v\n", logPrefix, cmd.SymLink, err)
			return
		}
		relativeTarget, err := filepath.Rel(dir, filePath)
		if err != nil {
			fmt.Printf("%s Error computing relative path for %v: %v\n", logPrefix, cmd.SymLink, err)
			return
		}
		if err := os.Symlink(relativeTarget, cmd.SymLink); err != nil {
			fmt.Printf("%s Error making symlink %v: %v\n", logPrefix, cmd.SymLink, err)
			return
		}
	}
}

// noOutputMarker is appended to a command's captured output when it was killed
// for producing no output, so the bundle file itself explains the empty result.
func noOutputMarker(d time.Duration) string {
	return fmt.Sprintf("\n=== calicoctl cluster diags: no output for %s; command killed. "+
		"Re-run with a larger --command-timeout to wait longer. ===\n", d)
}

func (c *Collector) recordTimeout(cmd Cmd, filePath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timedOut = append(c.timedOut, TimedOutCommand{
		Info:    cmd.Info,
		Command: cmd.CmdStr,
		File:    filePath,
	})
}
