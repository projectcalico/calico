// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package checker

import (
	. "github.com/onsi/gomega"
	"testing"

	"github.com/envoyproxy/data-plane-api/api/auth"

	"github.com/projectcalico/app-policy/proto"
)

// Successful parse should return name and namespace.
func TestParseSpiffeIdOk(t *testing.T) {
	g := NewGomegaWithT(t)

	id := "spiffe://foo.bar.com/ns/sandwich/sa/bacon"
	name, namespace, err := parseSpiffeId(id)
	g.Expect(name).To(Equal("bacon"))
	g.Expect(namespace).To(Equal("sandwich"))
	g.Expect(err).To(BeNil())
}

// Unsuccessful parse should return an error.
func TestParseSpiffeIdFail(t *testing.T) {
	g := NewGomegaWithT(t)

	id := "http://foo.bar.com/ns/sandwich/sa/bacon"
	_, _, err := parseSpiffeId(id)
	g.Expect(err).ToNot(BeNil())
}

// If no service account names are given, the clause matches any name.
func TestMatchServiceAccountNameEmpty(t *testing.T) {
	g := NewGomegaWithT(t)

	names := []string{}
	name := "reginald"
	result := matchServiceAccountName(names, name)
	g.Expect(result).To(BeTrue())
}

// If the name matches a name in the list, the clause matches.
func TestMatchServiceAccountNameMatch(t *testing.T) {
	g := NewGomegaWithT(t)

	names := []string{"susan", "jim", "reginald"}
	name := "reginald"
	result := matchServiceAccountName(names, name)
	g.Expect(result).To(BeTrue())
}

// If the list has names, but none match, the clause does not match.
func TestMatchServiceAccountNameNomatch(t *testing.T) {
	g := NewGomegaWithT(t)

	names := []string{"susan", "jim", "reginald"}
	name := "steven"
	result := matchServiceAccountName(names, name)
	g.Expect(result).To(BeFalse())
}

// An empty label selector matches any set of labels.
func TestMatchServiceAccoutLabelsEmpty(t *testing.T) {
	g := NewGomegaWithT(t)

	selector := ""
	labels := map[string]string{"app": "foo", "env": "prod"}
	result := matchServiceAccountLabels(selector, labels)
	g.Expect(result).To(BeTrue())
}

// An unparsable selector will not match.
func TestMatchServiceAccountLabelsBadSelector(t *testing.T) {
	g := NewGomegaWithT(t)

	selector := "not.a.real.selector"
	labels := map[string]string{"app": "foo", "env": "prod"}
	result := matchServiceAccountLabels(selector, labels)
	g.Expect(result).To(BeFalse())
}

// A correct label selector matches subsets of labels.
func TestMatchServiceAccountLabelsOk(t *testing.T) {
	g := NewGomegaWithT(t)

	selector := "app == 'foo'"
	labels := map[string]string{"app": "foo", "env": "prod"}
	result := matchServiceAccountLabels(selector, labels)
	g.Expect(result).To(BeTrue())
}

// If the Principle on the request cannot be parsed as a SPIFFE ID, service
// account clause cannot match (even if empty).
func TestMatchServiceAccountBadSpiffe(t *testing.T) {
	g := NewGomegaWithT(t)

	selector := &proto.ServiceAccountSelector{}
	peer := &auth.AttributeContext_Peer{
		Principal: "http://foo.com",
	}
	result := matchServiceAccounts(selector, peer)
	g.Expect(result).To(BeFalse())
}

// HTTP Methods clause with empty list will match any method.
func TestMatchHTTPMethodsEmpty(t *testing.T) {
	g := NewGomegaWithT(t)

	methods := []string{}
	method := "GET"
	g.Expect(matchHTTPMethods(methods, method)).To(BeTrue())
}

// Non-empty method list will exact match methods.
func TestMatchHTTPMethodsMatch(t *testing.T) {
	g := NewGomegaWithT(t)

	methods := []string{"GET", "HEAD"}
	method := "GET"
	g.Expect(matchHTTPMethods(methods, method)).To(BeTrue())
}

// HTTP methods are case sensitive. https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
func TestMatchHTTPMethodsCase(t *testing.T) {
	g := NewGomegaWithT(t)

	methods := []string{"get", "HEAD"}
	method := "GET"
	g.Expect(matchHTTPMethods(methods, method)).To(BeFalse())
}

// A * is a wildcard that matches any method.
func TestMatchHTTPMethodsWildcard(t *testing.T) {
	g := NewGomegaWithT(t)

	methods := []string{"*"}
	method := "MADNESS"
	g.Expect(matchHTTPMethods(methods, method)).To(BeTrue())
}

// An omitted HTTP Match clause always matches.
func TestMatchHTTPNil(t *testing.T) {
	g := NewGomegaWithT(t)

	req := &auth.AttributeContext_HTTPRequest{}
	g.Expect(matchHTTP(nil, req)).To(BeTrue())
}

// Matching a whole rule should require matching all subclauses.
func TestMatchRule(t *testing.T) {
	g := NewGomegaWithT(t)

	rule := &proto.Rule{
		SrcServiceAccount: &proto.ServiceAccountSelector{
			Names: []string{"john", "stevie", "sam"},
		},
		Http: &proto.HTTPSelector{
			Methods: []string{"GET", "POST"},
		},
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sam",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HTTPRequest{
				Method: "GET",
			},
		},
	}}
	g.Expect(match(rule, req)).To(BeTrue())
}
