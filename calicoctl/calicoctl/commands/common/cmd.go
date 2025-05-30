// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// ExecCmd is a convenience function that wraps exec.Command.
func ExecCmd(cmdStr string) (*bytes.Buffer, error) {
	parts := strings.Fields(cmdStr)
	log.Debugf("cmd tokens: [%+v]", parts)

	if len(parts) == 0 {
		return nil, fmt.Errorf("no command to execute")
	}

	return Exec(parts)
}

// Exec is a convenience function that wraps exec.Command.
// Accepts pre-separated cmd strings.
func Exec(cmdParts []string) (*bytes.Buffer, error) {
	var result bytes.Buffer

	if len(cmdParts) == 0 {
		return nil, fmt.Errorf("no command to execute")
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
	cmd.Stdout = &result

	log.Debugf("Executing command: %+v ...", cmd)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("command execution failed: %s", err)
	}

	log.Debugln("Completed successfully.")
	return &result, nil
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
}

// ExecCmdWriteToFile executes the provided command c and outputs the result to a
// file with the given filepath.
func ExecCmdWriteToFile(logPrefix string, c Cmd) {

	if c.Info != "" {
		fmt.Println(logPrefix, c.Info)
	}
	logCtx := log.WithField("cmdID", logPrefix)

	// Create the containing directory, if needed.
	dir := filepath.Dir(c.FilePath)
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Printf("%s Error creating directory for %v: %v\n", logPrefix, c.FilePath, err)
		return
	}

	parts := strings.Fields(c.CmdStr)
	logCtx.Debugf("cmd tokens: [%+v]", parts)

	logCtx.Debugf("Executing command: %+v ... ", c.CmdStr)
	content, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	if err != nil {
		fmt.Printf("%s Failed to run command: %s\nError: %s\n", logPrefix, c.CmdStr, string(content))
	}

	// This is for the commands we want to run but don't want to save the output
	// or for commands that don't produce any output to stdout
	if c.FilePath == "" {
		logCtx.Debugln("Command executed successfully, skipping writing output (no filepath specified)")
		return
	}

	if err := os.WriteFile(c.FilePath, content, 0644); err != nil {
		logCtx.Errorf("Error writing diags to file: %s\n", err)
	}
	logCtx.Debugf("Command executed successfully and outputted to %s", c.FilePath)

	if c.SymLink != "" {
		dir = filepath.Dir(c.SymLink)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			fmt.Printf("%s Error creating directory for %v: %v\n", logPrefix, c.SymLink, err)
			return
		}
		relativeTarget, err := filepath.Rel(dir, c.FilePath)
		if err != nil {
			fmt.Printf("%s Error computing relative path for %v: %v\n", logPrefix, c.SymLink, err)
			return
		}
		err = os.Symlink(relativeTarget, c.SymLink)
		if err != nil {
			fmt.Printf("%s Error making symlink %v: %v\n", logPrefix, c.SymLink, err)
			return
		}
	}
}

var MaxParallelism = 10
var nextPrefix atomic.Int64

// ExecAllCmdsWriteToFile iterates through the provided list of Cmd objects and attempts
// to execute each one.
func ExecAllCmdsWriteToFile(cmds []Cmd) {
	var eg errgroup.Group
	eg.SetLimit(MaxParallelism)

	for _, c := range cmds {
		id := nextPrefix.Add(1)
		prefix := fmt.Sprintf("[%d]", id)
		eg.Go(func() error {
			ExecCmdWriteToFile(prefix, c)
			return nil // For diags collection, we want to continue even if one command fails
		})
		time.Sleep(20 * time.Millisecond)
	}

	err := eg.Wait()
	if err != nil {
		log.Errorf("Unexpected error from background commands: %v", err)
	}
}
