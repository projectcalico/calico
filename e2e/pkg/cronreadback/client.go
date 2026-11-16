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

package cronreadback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultServer is the ArgoCI Argo server.
	DefaultServer = "https://argoci.dev.calicocloud.io"

	// DefaultNamespace is the namespace every cron lives in, whatever its repo.
	DefaultNamespace = "argoci"

	// repoLabel is the label the runs of a cron carry with its repo's name, at
	// spec.workflowMetadata.labels of the CronWorkflow.
	repoLabel = "CI_GIT_REPO_NAME"
)

// errNotFound is returned when the Argo server has no such CronWorkflow.
var errNotFound = errors.New("cron workflow not found")

// ErrUnauthorized is returned when the Argo server rejects the token.
var ErrUnauthorized = errors.New("argo server rejected the token")

// Client reads CronWorkflows from the Argo server's REST API. It only issues
// GET requests.
type Client struct {
	server    string
	namespace string
	token     string
	http      *http.Client
}

// NewClient returns a client for the Argo server at server, which may be a bare
// host:port as the argo CLI's ARGO_SERVER is. The token is the Authorization
// header value or a bare bearer token, as the argo CLI's ARGO_TOKEN is.
func NewClient(server, namespace, token string) *Client {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	if token != "" && !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "Basic ") {
		token = "Bearer " + token
	}
	return &Client{
		server:    strings.TrimSuffix(server, "/"),
		namespace: namespace,
		token:     token,
		http:      &http.Client{Timeout: 60 * time.Second},
	}
}

// GetRaw returns the JSON of the named CronWorkflow.
func (c *Client) GetRaw(ctx context.Context, name string) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/cron-workflows/%s/%s", url.PathEscape(c.namespace), url.PathEscape(name))
	return c.fetch(ctx, path)
}

// getCron returns the named CronWorkflow, or errNotFound.
func (c *Client) getCron(ctx context.Context, name string) (LiveCron, error) {
	data, err := c.GetRaw(ctx, name)
	if err != nil {
		return LiveCron{}, err
	}
	live, err := parseLive(data)
	if err != nil {
		return LiveCron{}, fmt.Errorf("%s: %w", name, err)
	}
	live.Name = name
	return live, nil
}

// listCronNames returns the names of the namespace's CronWorkflows that belong to
// repo on branch. It lists them all and filters here, since a server-side
// selector cannot match the repo.
func (c *Client) listCronNames(ctx context.Context, repo, branch string) ([]string, error) {
	data, err := c.fetch(ctx, fmt.Sprintf("/api/v1/cron-workflows/%s", url.PathEscape(c.namespace)))
	if err != nil {
		return nil, err
	}
	return parseNames(data, repo, branch)
}

// cronList is the part of an Argo CronWorkflow list response the check reads.
type cronList struct {
	Items []cronObject `json:"items"`
}

// parseNames returns the names of the CronWorkflows in an Argo list response
// that belong to repo on branch. A CronWorkflow belongs to a repo when the runs
// it spawns carry the repo's name in the repoLabel label. It is on a branch
// when its source-file annotation names that branch's cron directory, or, for
// one without the annotation, when its name ends with the branch.
func parseNames(data []byte, repo, branch string) ([]string, error) {
	var list cronList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decoding CronWorkflow list: %w", err)
	}
	var names []string
	for _, item := range list.Items {
		if item.Spec.WorkflowMetadata.Labels[repoLabel] == repo && item.onBranch(branch) {
			names = append(names, item.Metadata.Name)
		}
	}
	return names, nil
}

// onBranch reports whether the cron was applied from branch.
func (o cronObject) onBranch(branch string) bool {
	if source := o.Metadata.Annotations[sourceURLAnnotation]; source != "" {
		return strings.Contains(source, "/blob/"+branch+"/"+cronDir+"/")
	}
	return strings.HasSuffix(o.Metadata.Name, "-"+sanitizeBranch(branch))
}

// fetch issues one authenticated GET and maps the statuses a caller acts on.
func (c *Client) fetch(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logrus.WithError(err).Debug("Closing the response body failed")
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, errNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w (HTTP %d): %s", ErrUnauthorized, resp.StatusCode, strings.TrimSpace(string(body)))
	default:
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// ReadLive fetches every expected cron and the names of the repo's live crons
// on branch.
func ReadLive(ctx context.Context, c *Client, expected []ExpectedCron, repo, branch string) (LiveSet, error) {
	live := LiveSet{Crons: map[string]LiveCron{}}
	for _, want := range expected {
		cron, err := c.getCron(ctx, want.Name)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return LiveSet{}, err
		}
		live.Crons[want.Name] = cron
	}

	names, err := c.listCronNames(ctx, repo, branch)
	if err != nil {
		return LiveSet{}, err
	}
	live.Names = names
	return live, nil
}
