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

// Package ec2query is a minimal client for the EC2 Query API. It exists so
// felix/aws can talk to a handful of EC2 operations without importing
// github.com/aws/aws-sdk-go-v2/service/ec2, whose generated types alone add
// ~30 MB to the compiled binary.
package ec2query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// APIVersion is the EC2 Query API version we target. Stable since 2016.
const APIVersion = "2016-11-15"

const service = "ec2"

// Client is a minimal EC2 Query API client. One Client is bound to one region.
type Client struct {
	HTTPClient aws.HTTPClient
	Signer     *v4.Signer
	Creds      aws.CredentialsProvider
	Region     string
	// Endpoint, if set, overrides the default https://ec2.<region>.amazonaws.com/.
	Endpoint string
}

// NewFromConfig builds a Client from a loaded aws.Config.
func NewFromConfig(cfg aws.Config) *Client {
	c := &Client{
		HTTPClient: cfg.HTTPClient,
		Signer:     v4.NewSigner(),
		Creds:      cfg.Credentials,
		Region:     cfg.Region,
	}
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	// Honor a custom endpoint (AWS_ENDPOINT_URL / config override) when set.
	if cfg.BaseEndpoint != nil {
		c.Endpoint = *cfg.BaseEndpoint
	}
	return c
}

// Do issues a signed POST to the EC2 Query API. params is form-encoded into
// the request body along with Action and Version. The XML response is
// unmarshalled into out; out should match the shape of the operation's
// <ActionResponse> element (the XML root is unwrapped automatically).
func (c *Client) Do(ctx context.Context, action string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", APIVersion)
	body := params.Encode()

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint(c.Region)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("ec2query: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	creds, err := c.Creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("ec2query: retrieve credentials: %w", err)
	}
	sum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(sum[:])
	if err := c.Signer.SignHTTP(ctx, creds, req, payloadHash, service, c.Region, time.Now()); err != nil {
		return fmt.Errorf("ec2query: sign request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("ec2query: %s: %w", action, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ec2query: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseError(action, resp.StatusCode, respBody)
	}

	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("ec2query: decode %s response: %w", action, err)
	}
	return nil
}

// defaultEndpoint returns the regional EC2 Query API endpoint. The China
// partition has a distinct DNS suffix; other partitions (including GovCloud)
// use the standard amazonaws.com suffix.
func defaultEndpoint(region string) string {
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	return fmt.Sprintf("https://ec2.%s.%s/", region, suffix)
}

// APIError is returned for non-2xx responses from the EC2 Query API. It
// mirrors the smithy.APIError shape (Code/Message) so callers can switch on
// the error code without depending on the smithy module.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrorCode returns the AWS error code (e.g. "InternalError"). Named to
// match smithy.APIError so existing call sites that switched on ErrorCode()
// don't need to change.
func (e *APIError) ErrorCode() string { return e.Code }

// ErrorMessage returns the AWS error message.
func (e *APIError) ErrorMessage() string { return e.Message }

// EC2 query errors come back as <Response><Errors><Error><Code>... or
// <ErrorResponse><Error><Code>... depending on the operation. We accept both.
type errorEnvelope struct {
	XMLName xml.Name
	Errors  struct {
		Error []struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
	} `xml:"Errors"`
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

func parseError(action string, status int, body []byte) error {
	var env errorEnvelope
	if err := xml.Unmarshal(body, &env); err == nil {
		if len(env.Errors.Error) > 0 {
			return &APIError{Status: status, Code: env.Errors.Error[0].Code, Message: env.Errors.Error[0].Message}
		}
		if env.Error.Code != "" {
			return &APIError{Status: status, Code: env.Error.Code, Message: env.Error.Message}
		}
	}
	return &APIError{Status: status, Code: fmt.Sprintf("HTTP%d", status), Message: fmt.Sprintf("%s failed: %s", action, strings.TrimSpace(string(body)))}
}
