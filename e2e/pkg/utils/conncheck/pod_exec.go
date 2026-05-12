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

package conncheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

const deletionTimeout = 1 * time.Minute

// podReadyTimeout is longer on Windows because the server image is multi-GB.
func podReadyTimeout(_ context.Context) time.Duration {
	if windows.ClusterIsWindows() {
		return 15 * time.Minute
	}
	return 1 * time.Minute
}

// execShellInPod runs cmd in pod via sh -c (or powershell -Command on Windows).
func execShellInPod(pod *v1.Pod, cmd string) (string, error) {
	if windows.ClusterIsWindows() {
		return ExecInPod(pod, "powershell.exe", "-Command", cmd)
	}
	return ExecInPod(pod, "sh", "-c", cmd)
}

// execStreamInPod launches a long-lived command in pod via SPDY exec, writing
// merged stdout/stderr to w. The returned stop function closes stdin (which
// triggers the streamWrapper reaper to SIGTERM the child) and waits for the
// stream to drain.
func execStreamInPod(ctx context.Context, pod *v1.Pod, command []string, w io.Writer) (func() error, error) {
	if windows.ClusterIsWindows() {
		return nil, fmt.Errorf("execStreamInPod: streaming probes are not supported on Windows pods")
	}
	if len(pod.Spec.Containers) == 0 {
		return nil, fmt.Errorf("execStreamInPod: pod %s/%s has no containers", pod.Namespace, pod.Name)
	}
	container := pod.Spec.Containers[0].Name

	// "/bin/sh -c <wrapper> -- <user-argv>...": the "--" is consumed as $0,
	// user argv expands as "$@" in the wrapper.
	cmd := append([]string{"/bin/sh", "-c", streamWrapper, "--"}, command...)

	cfg, err := framework.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("execStreamInPod: load config: %w", err)
	}
	cs, err := framework.LoadClientset()
	if err != nil {
		return nil, fmt.Errorf("execStreamInPod: load clientset: %w", err)
	}

	req := cs.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return nil, fmt.Errorf("execStreamInPod: build executor: %w", err)
	}

	stdinR, stdinW := io.Pipe()
	doneCh := make(chan struct{})
	var (
		mu        sync.Mutex
		stopping  bool
		streamErr error
	)

	go func() {
		defer close(doneCh)
		err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  stdinR,
			Stdout: w,
			Stderr: w,
		})
		mu.Lock()
		s := stopping
		mu.Unlock()
		if err != nil && !errors.Is(err, io.EOF) && !s {
			mu.Lock()
			streamErr = err
			mu.Unlock()
		}
	}()

	stop := func() error {
		mu.Lock()
		stopping = true
		mu.Unlock()
		_ = stdinW.Close()
		<-doneCh
		mu.Lock()
		defer mu.Unlock()
		return streamErr
	}
	return stop, nil
}

// streamWrapper is the /bin/sh -c body used by execStreamInPod. Closing the
// SPDY stdin from outside causes the reaper subshell to read EOF and SIGTERM
// the child. This is the only reliable way to terminate a remote process via
// SPDY exec since signals are not forwarded.
//
// `exec 3<&0` saves the wrapper's stdin to fd 3 BEFORE backgrounding because
// non-interactive shells redirect backgrounded subshell stdin to /dev/null.
const streamWrapper = `exec 3<&0
"$@" </dev/null &
child=$!
( cat <&3 >/dev/null ; kill -TERM "$child" 2>/dev/null || true ) &
reaper=$!
wait "$child"
rc=$?
kill -TERM "$reaper" 2>/dev/null || true
exit "$rc"
`
