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
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
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

// admit checks whether the admission request should be allowed. It blocks Create, Update, and
// Delete operations on ClusterInformation unless the request originates from an allowed Calico
// system service account. This mirrors the write protection that the Calico API server provides
// when running in aggregated API mode.
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

	logCtx.Info("Denying write to ClusterInformation")
	return &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: fmt.Sprintf("ClusterInformation is a read-only resource (user: %s)", ar.Request.UserInfo.Username),
			Reason:  metav1.StatusReasonMethodNotAllowed,
		},
	}
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
