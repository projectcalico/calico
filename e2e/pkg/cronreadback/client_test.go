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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

// listFixture lists crons as the cluster holds them, with the repo on the runs'
// labels and the branch in the source annotation. Some are other branches, other
// repos, unlabelled, or without the annotation.
const listFixture = `{"items": [
  {"metadata": {"name": "e2e-bpf-master", "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/master/.argoci/cron/e2e-bpf.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}},
  {"metadata": {"name": "old-master", "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/master/.argoci/cron/old.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}},
  {"metadata": {"name": "e2e-bpf-release-v3-33", "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/release-v3.33/.argoci/cron/e2e-bpf.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}},
  {"metadata": {"name": "e2e-bpf-foo-master", "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/foo-master/.argoci/cron/e2e-bpf.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}},
  {"metadata": {"name": "e2e-private-master", "annotations": {"argoci-viewer/source-url": "https://github.com/example/calico-private/blob/master/.argoci/cron/e2e-private.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico-private"}}}},
  {"metadata": {"name": "unlabelled-master", "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/master/.argoci/cron/unlabelled.yaml"}},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY"}}}},
  {"metadata": {"name": "legacy-master"},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}},
  {"metadata": {"name": "legacy-release-v3-33"},
   "spec": {"workflowMetadata": {"labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"}}}}
]}`

// argoStub serves one cron and a list, and records what it was asked.
type argoStub struct {
	auth   string
	method string
	paths  []string
}

func (s *argoStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.auth = r.Header.Get("Authorization")
	s.method = r.Method
	s.paths = append(s.paths, r.URL.RequestURI())
	switch r.URL.Path {
	case "/api/v1/cron-workflows/argoci/e2e-bpf-master":
		reply(w, liveFixture)
	case "/api/v1/cron-workflows/argoci":
		reply(w, listFixture)
	case "/api/v1/cron-workflows/argoci/expired":
		http.Error(w, `{"message": "token is expired"}`, http.StatusUnauthorized)
	default:
		http.NotFound(w, r)
	}
}

// reply writes body to w, logging a failed write.
func reply(w http.ResponseWriter, body string) {
	if _, err := io.WriteString(w, body); err != nil {
		logrus.WithError(err).Warn("Writing the stub response failed")
	}
}

func TestClientGet(t *testing.T) {
	RegisterTestingT(t)
	stub := &argoStub{}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	live, err := NewClient(srv.URL, "argoci", "abc").getCron(context.Background(), "e2e-bpf-master")

	Expect(err).NotTo(HaveOccurred())
	Expect(live.Cells).To(HaveKey("wireguard"))
	Expect(live.Name).To(Equal("e2e-bpf-master"))
	Expect(stub.method).To(Equal(http.MethodGet))
	Expect(stub.auth).To(Equal("Bearer abc"))
}

func TestClientKeepsAuthorizationHeaderValue(t *testing.T) {
	RegisterTestingT(t)
	stub := &argoStub{}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	_, err := NewClient(srv.URL, "argoci", "Bearer already").getCron(context.Background(), "e2e-bpf-master")

	Expect(err).NotTo(HaveOccurred())
	Expect(stub.auth).To(Equal("Bearer already"))
}

func TestClientMissingCron(t *testing.T) {
	RegisterTestingT(t)
	srv := httptest.NewServer(&argoStub{})
	defer srv.Close()

	_, err := NewClient(srv.URL, "argoci", "abc").getCron(context.Background(), "nope")

	Expect(err).To(MatchError(errNotFound))
}

func TestClientRejectedToken(t *testing.T) {
	RegisterTestingT(t)
	srv := httptest.NewServer(&argoStub{})
	defer srv.Close()

	_, err := NewClient(srv.URL, "argoci", "abc").getCron(context.Background(), "expired")

	Expect(err).To(MatchError(ErrUnauthorized))
	Expect(err).NotTo(MatchError(errNotFound))
}

func TestReadLive(t *testing.T) {
	RegisterTestingT(t)
	stub := &argoStub{}
	srv := httptest.NewServer(stub)
	defer srv.Close()
	expected := []ExpectedCron{{Name: "e2e-bpf-master"}, {Name: "e2e-gone-master"}}

	live, err := ReadLive(context.Background(), NewClient(srv.URL, "argoci", "abc"), expected, "calico", "master")

	Expect(err).NotTo(HaveOccurred())
	Expect(live.Crons).To(HaveKey("e2e-bpf-master"))
	Expect(live.Crons).NotTo(HaveKey("e2e-gone-master"))

	// Only the repo's crons on the branch count. The source annotation tells
	// master from foo-master, which share a name suffix, and the name suffix
	// stands in for a cron without the annotation.
	Expect(live.Names).To(ConsistOf("e2e-bpf-master", "old-master", "legacy-master"))

	// The repo is not a label of the CronWorkflow, so no selector may ask the
	// server for it.
	Expect(stub.paths).NotTo(ContainElement(ContainSubstring("labelSelector")))
}

func TestListCronNamesOtherRepoAndBranch(t *testing.T) {
	RegisterTestingT(t)
	srv := httptest.NewServer(&argoStub{})
	defer srv.Close()
	client := NewClient(srv.URL, "argoci", "abc")

	private, err := client.listCronNames(context.Background(), "calico-private", "master")
	Expect(err).NotTo(HaveOccurred())
	Expect(private).To(ConsistOf("e2e-private-master"))

	release, err := client.listCronNames(context.Background(), "calico", "release-v3.33")
	Expect(err).NotTo(HaveOccurred())
	Expect(release).To(ConsistOf("e2e-bpf-release-v3-33", "legacy-release-v3-33"))

	none, err := client.listCronNames(context.Background(), "other", "master")
	Expect(err).NotTo(HaveOccurred())
	Expect(none).To(BeEmpty())
}
