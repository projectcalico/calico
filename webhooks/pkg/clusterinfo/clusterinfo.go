// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package clusterinfo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/webhooks/pkg/utils"
)

const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// allowedServiceAccounts is the set of service account names (not fully-qualified) that are
// permitted to write ClusterInformation. These are the Calico system components that need
// to create and update ClusterInformation during normal operation.
var allowedServiceAccounts = map[string]struct{}{
	"calico-node":             {},
	"calico-kube-controllers": {},
	"calico-typha":            {},
}

type webhook struct {
	namespace string
}

// RegisterHook registers the ClusterInformation write-protection webhook handler at the /cluster-info path.
func RegisterHook(handleFn utils.HandleFn) {
	ns, err := os.ReadFile(saNamespaceFile)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read pod namespace")
	}
	w := &webhook{namespace: strings.TrimSpace(string(ns))}
	logrus.WithFields(logrus.Fields{
		"path":      "/cluster-info",
		"namespace": w.namespace,
	}).Info("Registering ClusterInformation write-protection webhook")

	handler := utils.NewDelegateToV1AdmitHandler(w.admit)
	http.HandleFunc("/cluster-info", handleFn(handler))
}

// admit checks whether the admission request should be allowed. Calico system service accounts
// may make any write. Anyone else may only flip spec.datastoreReady, which is how
// `calicoctl datastore migrate lock` and `unlock` work, and RBAC decides who can do that. This
// matches API server mode, where calicoctl writes the v1 ClusterInformation CRD under RBAC alone.
func (w *webhook) admit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	logCtx := logrus.WithFields(logrus.Fields{
		"uid":       ar.Request.UID,
		"operation": ar.Request.Operation,
		"name":      ar.Request.Name,
		"user":      ar.Request.UserInfo.Username,
	})
	logCtx.Debug("Handling ClusterInformation admission review")

	if w.isAllowedUser(ar.Request.UserInfo.Username) {
		logCtx.Debug("Allowing write from system service account")
		return &v1.AdmissionResponse{Allowed: true}
	}

	// Anyone else gets through only with an update that locks or unlocks the
	// datastore and changes nothing else.
	if ar.Request.Operation == v1.Update {
		onlyLock, err := onlyDatastoreReadyChanged(ar.Request.OldObject.Raw, ar.Request.Object.Raw)
		if err != nil {
			logCtx.WithError(err).Warn("Failed to decode ClusterInformation update, denying it")
		} else if onlyLock {
			logCtx.Info("Allowing ClusterInformation update that only changes datastoreReady")
			return &v1.AdmissionResponse{Allowed: true}
		}
	}

	logCtx.Info("Denying write to ClusterInformation")
	return &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: fmt.Sprintf("ClusterInformation is read-only apart from spec.datastoreReady (user: %s)", ar.Request.UserInfo.Username),
			Reason:  metav1.StatusReasonMethodNotAllowed,
		},
	}
}

// onlyDatastoreReadyChanged reports whether an update to ClusterInformation changes
// spec.datastoreReady and nothing else. Labels, annotations, finalizers and owner references must
// stay as they were, since the migration controller keeps its lock markers in annotations.
func onlyDatastoreReadyChanged(oldRaw, newRaw []byte) (bool, error) {
	if len(oldRaw) == 0 || len(newRaw) == 0 {
		return false, fmt.Errorf("update is missing the old or new object")
	}
	oldCI := &apiv3.ClusterInformation{}
	if err := json.Unmarshal(oldRaw, oldCI); err != nil {
		return false, fmt.Errorf("decoding old ClusterInformation: %w", err)
	}
	newCI := &apiv3.ClusterInformation{}
	if err := json.Unmarshal(newRaw, newCI); err != nil {
		return false, fmt.Errorf("decoding new ClusterInformation: %w", err)
	}

	// Blank out datastoreReady on both sides, so any remaining difference in
	// the spec is a change to a protected field.
	oldSpec, newSpec := oldCI.Spec, newCI.Spec
	oldSpec.DatastoreReady, newSpec.DatastoreReady = nil, nil
	sameSpec := equality.Semantic.DeepEqual(oldSpec, newSpec)
	sameMeta := equality.Semantic.DeepEqual(oldCI.Labels, newCI.Labels) &&
		equality.Semantic.DeepEqual(oldCI.Annotations, newCI.Annotations) &&
		equality.Semantic.DeepEqual(oldCI.Finalizers, newCI.Finalizers) &&
		equality.Semantic.DeepEqual(oldCI.OwnerReferences, newCI.OwnerReferences)
	return sameSpec && sameMeta, nil
}

// isAllowedUser returns true if the given username corresponds to a Calico system service account
// that is permitted to write ClusterInformation. Service account usernames follow the format
// "system:serviceaccount:<namespace>:<name>". The service account must be in the same namespace
// as the webhook pod.
func (w *webhook) isAllowedUser(username string) bool {
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return false
	}
	if parts[2] != w.namespace {
		return false
	}
	_, ok := allowedServiceAccounts[parts[3]]
	return ok
}
