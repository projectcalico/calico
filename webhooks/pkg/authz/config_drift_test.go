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

package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// The AuthorizationConfiguration is a file an operator copies onto control-plane nodes, so
// nothing at build or run time reconciles it against the Go constants that assume its values.
// These tests are that reconciliation.
const (
	authzConfigPath = "../../config/authorization-configuration.yaml"
	e2eSpecPath     = "../../../e2e/pkg/tests/policy/tiered_rbac_reads.go"
	policycachePath = "../policycache/policycache.go"
)

func TestDecisionTimeoutStaysBelowTheWebhookTimeout(t *testing.T) {
	timeout := webhookConfig(t).Timeout

	require.NotZero(t, timeout, "the webhook has no explicit timeout; decisionTimeout has nothing to sit below")
	assert.Less(t, decisionTimeout, timeout,
		"decisionTimeout (%s) must stay strictly below the webhook timeout (%s) in %s. Otherwise a slow "+
			"decision times out on the API server's side, which is a webhook failure, and under "+
			"failurePolicy: Deny that denies every projectcalico.org request from every non-exempt "+
			"identity rather than just the slow one.", decisionTimeout, timeout, authzConfigPath)
}

func TestNegativeCacheAssumptionAboutUnauthorizedTTL(t *testing.T) {
	ttl := webhookConfig(t).UnauthorizedTTL

	require.NotZero(t, ttl, "unauthorizedTTL is unset, so the API server's default applies and this "+
		"test is no longer checking what it thinks it is")
	// The cache's negative entries have to expire well inside the API server's own cache of a
	// NoOpinion, or a policy that appears after a miss stays invisible for longer than the
	// config file says it should.
	negativeTTL := durationConst(t, policycachePath, "negativeCacheTTL")
	assert.Less(t, negativeTTL, ttl,
		"negativeCacheTTL in %s (%s) must stay below unauthorizedTTL in %s (%s)",
		policycachePath, negativeTTL, authzConfigPath, ttl)

	// The e2e specs mirror unauthorizedTTL by hand, because they poll for longer than the API
	// server caches a Denied or NoOpinion. Nothing links the two but this assertion.
	mirrored := durationConst(t, e2eSpecPath, "authzUnauthorizedTTL")
	assert.Equal(t, ttl, mirrored,
		"authzUnauthorizedTTL in %s must match unauthorizedTTL in %s; the read-path specs poll "+
			"against it and silently assert on the wrong window if it drifts", e2eSpecPath, authzConfigPath)
}

// authorizationConfiguration is the subset of the AuthorizationConfiguration these tests read.
// Deliberately not the upstream type: apiserver's config types are internal to the API server
// and pulling them in for two duration fields is not worth the dependency.
type authorizationConfiguration struct {
	Authorizers []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Webhook *struct {
			Timeout         metaDuration `json:"timeout"`
			UnauthorizedTTL metaDuration `json:"unauthorizedTTL"`
			FailurePolicy   string       `json:"failurePolicy"`
		} `json:"webhook"`
	} `json:"authorizers"`
}

// metaDuration decodes the "3s" / "30s" / "5m" form the config file uses.
type metaDuration time.Duration

func (d *metaDuration) UnmarshalJSON(b []byte) error {
	// Unquote rather than slicing blindly: a bare number in the YAML (timeout: 3) would slice out
	// of range and panic, hiding the config error this test exists to report.
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration %q is not a string: %w", b, err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = metaDuration(parsed)
	return nil
}

type webhookSettings struct {
	Timeout         time.Duration
	UnauthorizedTTL time.Duration
}

// webhookConfig returns the calico-tiered-rbac webhook's settings from the shipped config file.
func webhookConfig(t *testing.T) webhookSettings {
	t.Helper()

	raw, err := os.ReadFile(authzConfigPath)
	require.NoError(t, err)

	var cfg authorizationConfiguration
	require.NoError(t, yaml.Unmarshal(raw, &cfg))

	for _, a := range cfg.Authorizers {
		if a.Name != "calico-tiered-rbac" {
			continue
		}
		require.NotNil(t, a.Webhook, "the calico-tiered-rbac authorizer has no webhook stanza")
		require.Equal(t, "Deny", a.Webhook.FailurePolicy,
			"this webhook fails closed by design; see the invariants in webhooks/DESIGN.md")
		return webhookSettings{
			Timeout:         time.Duration(a.Webhook.Timeout),
			UnauthorizedTTL: time.Duration(a.Webhook.UnauthorizedTTL),
		}
	}

	t.Fatalf("no authorizer named calico-tiered-rbac in %s", authzConfigPath)
	return webhookSettings{}
}

// durationConst reads a `name = <duration literal>` constant out of a Go source file. Textual
// because the constant is unexported and in another package (and another module).
func durationConst(t *testing.T, path, name string) time.Duration {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	re := regexp.MustCompile(name + `\s*=\s*(\d+)\s*\*\s*time\.(Millisecond|Second|Minute|Hour)`)
	m := re.FindSubmatch(raw)
	require.NotNil(t, m, "no %s duration constant found in %s", name, path)

	d, err := time.ParseDuration(string(m[1]) + map[string]string{
		"Millisecond": "ms", "Second": "s", "Minute": "m", "Hour": "h",
	}[string(m[2])])
	require.NoError(t, err)
	return d
}
