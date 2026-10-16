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

// SSH access to a GCE VM without gcloud: an ephemeral keypair goes in as the
// instance's `ssh-keys` metadata (the guest agent installs it), the external IP
// comes from the instance, and the connection is a plain x/crypto/ssh dial. This
// is what lets the run step drive the VM from the same distroless image.
package gce

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	compute "google.golang.org/api/compute/v1"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/util"
)

// SSH is a live connection to a VM. Close it when done.
type SSH struct {
	client *ssh.Client
}

// DialSSH injects an ephemeral keypair, reads the external IP and dials, retrying
// until reachable -- a fresh VM accepts SSH only once sshd, the guest agent and
// the key have caught up. This retry is the readiness check createvm skips. The
// host key is not verified: we just made the VM, it lives for minutes, and there
// is no prior key to pin.
func (c *Client) DialSSH(ctx context.Context, zone, name, user string) (*SSH, error) {
	signer, authorized, err := ephemeralKey()
	if err != nil {
		return nil, err
	}
	ip, err := c.injectKeyAndGetIP(ctx, zone, name, user, authorized)
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // ephemeral CI VM, no key to pin
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(ip, "22")

	deadline := time.Now().Add(3 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := dial(addr, cfg)
		if err == nil {
			go keepalive(client)
			return &SSH{client: client}, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return nil, fmt.Errorf("ssh to %s (%s) not ready after 3m: %w", name, addr, lastErr)
}

// dial bounds the handshake, not just the connect. ssh.Dial leaves NewClientConn
// with no deadline, so a VM whose sshd has bound the socket but is not answering
// stalls forever -- the exact state the retry loop above exists for, and it would
// never get back there.
func dial(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Clear it again: the deadline covered the handshake, and the session that
	// follows carries a CI job of unbounded length.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// keepalive stops GCP reaping the connection: a VPC drops an idle established flow
// after 10 minutes, untunable, and x/crypto/ssh sends nothing itself. A quiet
// stretch in the job would otherwise kill the session and the artifact pull with it.
func keepalive(client *ssh.Client) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			return // connection is gone; Run/GetDir will report it
		}
	}
}

// injectKeyAndGetIP sets the instance's ssh-keys metadata to authorize user with
// the given key (preserving any other metadata) and returns its external IP.
func (c *Client) injectKeyAndGetIP(ctx context.Context, zone, name, user, authorized string) (string, error) {
	var inst *compute.Instance
	if err := retry(ctx, "get instance "+name, func() (err error) {
		inst, err = c.svc.Instances.Get(c.project, zone, name).Context(ctx).Do()
		return err
	}); err != nil {
		return "", err
	}

	md := inst.Metadata
	if md == nil {
		md = &compute.Metadata{}
	}
	sshKeys := fmt.Sprintf("%s:%s", user, strings.TrimSpace(authorized))
	replaced := false
	for _, it := range md.Items {
		if it.Key == "ssh-keys" {
			it.Value = new(sshKeys)
			replaced = true
			break
		}
	}
	if !replaced {
		md.Items = append(md.Items, &compute.MetadataItems{Key: "ssh-keys", Value: new(sshKeys)})
	}
	var op *compute.Operation
	if err := retry(ctx, "set ssh-keys metadata on "+name, func() (err error) {
		op, err = c.svc.Instances.SetMetadata(c.project, zone, name, md).Context(ctx).Do()
		return err
	}); err != nil {
		return "", err
	}
	if err := c.waitZoneOp(ctx, zone, op.Name); err != nil {
		return "", fmt.Errorf("set-metadata op on %s: %w", name, err)
	}

	// Re-read rather than reuse the snapshot from before the metadata op: createvm
	// does not wait for readiness, so natIP can still be unset when the insert
	// reaches DONE, and it appears seconds later. Retried for the same reason.
	var ip string
	if err := retry(ctx, "external IP of "+name, func() error {
		fresh, err := c.svc.Instances.Get(c.project, zone, name).Context(ctx).Do()
		if err != nil {
			return err
		}
		if ip = externalIP(fresh); ip == "" {
			return fmt.Errorf("external IP of %s: %w", name, errNotReady)
		}
		return nil
	}); err != nil {
		return "", err
	}
	return ip, nil
}

func externalIP(inst *compute.Instance) string {
	for _, ni := range inst.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.NatIP != "" {
				return ac.NatIP
			}
		}
	}
	return ""
}

// ephemeralKey returns an ssh signer and its authorized_keys line.
func ephemeralKey() (ssh.Signer, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("public key: %w", err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(sshPub)), nil
}

// Close closes the underlying connection.
func (s *SSH) Close() error { return s.client.Close() }

// Run executes cmd on the VM, streaming output to the given writers. A non-zero
// exit comes back as exitCode with a nil error so the caller can propagate it;
// err is non-nil only for a connection or protocol failure.
func (s *SSH) Run(cmd string, stdout, stderr io.Writer) (exitCode int, err error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return -1, err
	}
	defer sess.Close()
	sess.Stdout = stdout
	sess.Stderr = stderr
	if err := sess.Run(cmd); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return ee.ExitStatus(), nil
		}
		return -1, err
	}
	return 0, nil
}

// PutData writes data to remote at the given mode, creating parent dirs.
func (s *SSH) PutData(data []byte, remote string, mode os.FileMode) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	// Capture remote stderr so a failing mkdir/chmod says why.
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf
	// Single-quoted, not %q: %q is double-quoted, and bash expands $(...) inside
	// double quotes, so a crafted remote path would execute on the VM.
	q := util.ShellQuote(remote)
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %o %s",
		util.ShellQuote(filepath.Dir(remote)), q, mode.Perm(), q)
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("put %s: %w: %s", remote, err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// PutFile uploads a single local file to remote at the given mode.
func (s *SSH) PutFile(local, remote string, mode os.FileMode) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	return s.PutData(data, remote, mode)
}

// PutDir uploads a local directory tree to a remote directory (created if absent)
// by streaming a tar over the connection and untarring on the VM.
func (s *SSH) PutDir(localDir, remoteDir string) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	pr, pw := io.Pipe()
	sess.Stdin = pr
	// Unblocks tarDir if the session dies before draining the pipe.
	defer pr.Close()
	// Buffered so the goroutine finishes even on the early returns below.
	tarErr := make(chan error, 1)
	go func() {
		err := tarDir(localDir, pw)
		pw.CloseWithError(err)
		tarErr <- err
	}()
	var errBuf bytes.Buffer
	sess.Stderr = &errBuf

	q := util.ShellQuote(remoteDir)
	cmd := fmt.Sprintf("mkdir -p %s && tar xzf - -C %s", q, q)
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("put dir %s: %w: %s", remoteDir, err, strings.TrimSpace(errBuf.String()))
	}
	// Run returned, so the tar is done. An error here means we shipped a truncated
	// tree the remote untarred without complaint.
	if err := <-tarErr; err != nil {
		return fmt.Errorf("tar %s for %s: %w", localDir, remoteDir, err)
	}
	return nil
}

// GetDir streams a remote directory's contents into localDir. Best-effort: a
// missing remote path is not an error, since an epilogue runs precisely when the
// files it wants may have never been produced.
func (s *SSH) GetDir(remoteDir, localDir string) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	// Tar the contents (not the dir itself) so they land directly under localDir.
	cmd := fmt.Sprintf("cd %s 2>/dev/null && tar czf - . || true", util.ShellQuote(remoteDir))
	if err := sess.Start(cmd); err != nil {
		return err
	}
	if err := untar(stdout, localDir); err != nil {
		// Drain first: abandoning the pipe while the remote tar writes blocks it
		// forever, and Wait with it.
		_, _ = io.Copy(io.Discard, stdout)
		_ = sess.Wait()
		return err
	}
	return sess.Wait()
}

// tarDir writes a gzipped tar of dir's contents (paths relative to dir) to w.
func tarDir(dir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		// Not deferred: that would hold every descriptor until the walk finished.
		_, err = io.Copy(tw, f)
		f.Close()
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// untar extracts a gzipped tar stream into destDir, guarding against paths that
// would escape it.
func untar(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		// An empty stream (missing remote dir) is not an error.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.Clean("/"+hdr.Name))
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) && target != destDir {
			return fmt.Errorf("tar entry escapes dest: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // CI artifacts we produced
				f.Close()
				return err
			}
			f.Close()
		}
	}
}
