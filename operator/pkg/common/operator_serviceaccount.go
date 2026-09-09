// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cloudflare/cfssl/log"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var serviceAccount = ""

// once ensures that serviceAccount is initialized only once.
var once sync.Once

// OperatorServiceAccount returns the ServiceAccount name the operator is running in.
// The value returned is based on the following priority (these are evaluated at startup):
//
//	If the OPERATOR_SERVICEACCOUNT environment variable is non-empty then that is return.
//	If the file /var/run/secrets/kubernetes.io/serviceaccount/namespace is non-empty
//	then the contents is returned.
//	The default "tigera-operator" is returned.
func OperatorServiceAccount() string {
	once.Do(func() {
		serviceAccount = getServiceAccount()
	})
	return serviceAccount
}

func getServiceAccount() string {
	v, ok := os.LookupEnv("OPERATOR_SERVICEACCOUNT")
	if ok {
		log.Infof("Detected operator service account %q from environment variable", v)
		return v
	}

	sa := serviceAccountFromToken()
	if sa != "" {
		log.Infof("Detected operator service account %q from token review", sa)
		return sa
	}
	log.Infof("Falling back to default operator service account 'tigera-operator'")
	return "tigera-operator"
}

func serviceAccountFromToken() string {
	// Parse the JWT token to get the service account name.
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Infof("Failed to read serviceaccount token file: %s", err)
		return ""
	}
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Errorf("Failed to read namespace file: %v", err)
		return ""
	}
	prefix := fmt.Sprintf("system:serviceaccount:%s:", string(ns))

	// Send a TokenReview to the Kubernetes API to validate and parse the token.
	tokenReview := authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: string(token),
		},
	}

	// Create a Kubernetes client.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("Failed to create in-cluster config: %s", err)
		return ""
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Errorf("Failed to create Kubernetes client: %s", err)
		return ""
	}
	tr, err := cs.AuthenticationV1().TokenReviews().Create(context.Background(), &tokenReview, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("Failed to create TokenReview: %s", err)
		return ""
	}
	if !tr.Status.Authenticated {
		log.Errorf("Failed to authenticate serviceaccount token")
		return ""
	}
	if tr.Status.User.Username == "" || !strings.HasPrefix(tr.Status.User.Username, prefix) {
		log.Errorf("Failed to get serviceaccount username from token review")
		return ""
	}
	return strings.TrimPrefix(tr.Status.User.Username, prefix)
}
