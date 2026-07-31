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

package ec2query

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// staticCreds is a fixed credential provider for tests.
type staticCreds struct{}

func (staticCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"}, nil
}

func newTestClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{
		HTTPClient: srv.Client(),
		Signer:     v4.NewSigner(),
		Creds:      staticCreds{},
		Region:     "us-west-2",
		Endpoint:   srv.URL + "/",
	}, srv
}

func TestDescribeInstancesParsesResponse(t *testing.T) {
	const respBody = `<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse>
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <networkInterfaceSet>
            <item>
              <networkInterfaceId>eni-primary</networkInterfaceId>
              <attachment><deviceIndex>0</deviceIndex></attachment>
            </item>
            <item>
              <networkInterfaceId>eni-secondary</networkInterfaceId>
              <attachment><deviceIndex>1</deviceIndex></attachment>
            </item>
          </networkInterfaceSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>`

	var gotBody string
	var gotAuth string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(respBody))
	}))

	out, err := c.DescribeInstances(context.Background(), &DescribeInstancesInput{InstanceIds: []string{"i-abc"}})
	if err != nil {
		t.Fatalf("DescribeInstances: %v", err)
	}

	if !strings.Contains(gotBody, "Action=DescribeInstances") || !strings.Contains(gotBody, "Version="+APIVersion) {
		t.Errorf("request body missing required params: %q", gotBody)
	}
	if !strings.Contains(gotBody, "InstanceId.1=i-abc") {
		t.Errorf("request body missing InstanceId.1: %q", gotBody)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization header not SigV4: %q", gotAuth)
	}

	if len(out.Reservations) != 1 || len(out.Reservations[0].Instances) != 1 {
		t.Fatalf("unexpected reservations/instances: %+v", out)
	}
	ifaces := out.Reservations[0].Instances[0].NetworkInterfaces
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(ifaces))
	}
	if ifaces[0].NetworkInterfaceId == nil || *ifaces[0].NetworkInterfaceId != "eni-primary" ||
		ifaces[0].Attachment == nil || ifaces[0].Attachment.DeviceIndex == nil || *ifaces[0].Attachment.DeviceIndex != 0 {
		t.Errorf("interface 0 wrong: %+v / %+v", ifaces[0], ifaces[0].Attachment)
	}
	if ifaces[1].Attachment.DeviceIndex == nil || *ifaces[1].Attachment.DeviceIndex != 1 {
		t.Errorf("interface 1 device index wrong: %v", ifaces[1].Attachment.DeviceIndex)
	}
}

func TestModifyNetworkInterfaceAttributeEncodesParams(t *testing.T) {
	var gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))

	enabled := false
	niid := "eni-1"
	_, err := c.ModifyNetworkInterfaceAttribute(context.Background(), &ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: &niid,
		SourceDestCheck:    &AttributeBooleanValue{Value: &enabled},
	})
	if err != nil {
		t.Fatalf("ModifyNetworkInterfaceAttribute: %v", err)
	}
	if !strings.Contains(gotBody, "Action=ModifyNetworkInterfaceAttribute") {
		t.Errorf("missing Action: %q", gotBody)
	}
	if !strings.Contains(gotBody, "NetworkInterfaceId=eni-1") {
		t.Errorf("missing NetworkInterfaceId: %q", gotBody)
	}
	if !strings.Contains(gotBody, "SourceDestCheck.Value=false") {
		t.Errorf("missing SourceDestCheck.Value: %q", gotBody)
	}
}

func TestErrorResponseParsed(t *testing.T) {
	const errBody = `<?xml version="1.0"?>
<Response>
  <Errors>
    <Error>
      <Code>InternalError</Code>
      <Message>retry me</Message>
    </Error>
  </Errors>
</Response>`
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(errBody))
	}))

	_, err := c.DescribeInstances(context.Background(), &DescribeInstancesInput{InstanceIds: []string{"i-abc"}})
	if err == nil {
		t.Fatal("expected error")
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if ae.ErrorCode() != "InternalError" {
		t.Errorf("code: %q", ae.ErrorCode())
	}
	if ae.ErrorMessage() != "retry me" {
		t.Errorf("message: %q", ae.ErrorMessage())
	}
}

func TestDefaultEndpoint(t *testing.T) {
	cases := map[string]string{
		"us-west-2":     "https://ec2.us-west-2.amazonaws.com/",
		"us-gov-west-1": "https://ec2.us-gov-west-1.amazonaws.com/",
		"cn-north-1":    "https://ec2.cn-north-1.amazonaws.com.cn/",
	}
	for region, want := range cases {
		if got := defaultEndpoint(region); got != want {
			t.Errorf("defaultEndpoint(%q) = %q, want %q", region, got, want)
		}
	}
}

func TestNewFromConfigHonorsConfig(t *testing.T) {
	custom := &http.Client{}
	base := "https://ec2.example.local/"
	c := NewFromConfig(aws.Config{
		Region:       "us-west-2",
		Credentials:  staticCreds{},
		HTTPClient:   custom,
		BaseEndpoint: &base,
	})
	if c.HTTPClient != custom {
		t.Errorf("expected config HTTPClient to be used, got %v", c.HTTPClient)
	}
	if c.Endpoint != base {
		t.Errorf("expected endpoint %q, got %q", base, c.Endpoint)
	}

	// With no HTTPClient on the config, fall back to the default.
	c = NewFromConfig(aws.Config{Region: "us-west-2", Credentials: staticCreds{}})
	if c.HTTPClient != http.DefaultClient {
		t.Errorf("expected http.DefaultClient fallback, got %v", c.HTTPClient)
	}
}

func TestErrorResponseAlternateEnvelope(t *testing.T) {
	const errBody = `<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Code>AuthFailure</Code>
    <Message>nope</Message>
  </Error>
</ErrorResponse>`
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(errBody))
	}))

	_, err := c.DescribeInstances(context.Background(), &DescribeInstancesInput{InstanceIds: []string{"i-abc"}})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if ae.Code != "AuthFailure" {
		t.Errorf("code: %q", ae.Code)
	}
}
