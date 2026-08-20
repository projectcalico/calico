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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
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
		"decisionTimeout (%s) must stay below the webhook timeout (%s) in %s, or a slow decision "+
			"becomes a webhook failure and denies every request the matchConditions route to it",
		decisionTimeout, timeout, authzConfigPath)
}

func TestNegativeCacheAssumptionAboutUnauthorizedTTL(t *testing.T) {
	ttl := webhookConfig(t).UnauthorizedTTL

	require.NotZero(t, ttl, "unauthorizedTTL is unset, so the API server's default applies and this "+
		"test is no longer checking what it thinks it is")
	// Negative entries must expire inside the API server's own cache of a NoOpinion, or a policy
	// created after a miss stays invisible for longer than the config file says.
	negativeTTL := durationConst(t, policycachePath, "negativeCacheTTL")
	assert.Less(t, negativeTTL, ttl,
		"negativeCacheTTL in %s (%s) must stay below unauthorizedTTL in %s (%s)",
		policycachePath, negativeTTL, authzConfigPath, ttl)

	// The e2e specs mirror unauthorizedTTL by hand, since they poll for longer than it.
	mirrored := durationConst(t, e2eSpecPath, "authzUnauthorizedTTL")
	assert.Equal(t, ttl, mirrored,
		"authzUnauthorizedTTL in %s must match unauthorizedTTL in %s, or those specs assert on "+
			"the wrong window", e2eSpecPath, authzConfigPath)
}

// A resource added to tierauth but not to the config's CEL filter would silently never reach the
// webhook, losing enforcement for it.
func TestMatchConditionsCoverEveryTieredResourceAndReadVerb(t *testing.T) {
	exprs := webhookConfig(t).MatchConditions
	require.NotEmpty(t, exprs, "the webhook has no matchConditions")

	joined := strings.Join(exprs, "\n")

	assert.ElementsMatch(t, tierauth.TieredPolicyResources(), celList(t, joined, "resource"),
		"the resource list in %s must match tierauth.TieredPolicyResources", authzConfigPath)

	verbs := make([]string, 0, len(readVerbs))
	for verb := range readVerbs {
		verbs = append(verbs, verb)
	}
	assert.ElementsMatch(t, verbs, celList(t, joined, "verb"),
		"the verb list in %s must match readVerbs", authzConfigPath)
}

// celList pulls the quoted strings out of a `request.resourceAttributes.<field> in [...]` clause.
func celList(t *testing.T, expr, field string) []string {
	t.Helper()

	clause := regexp.MustCompile(`request\.resourceAttributes\.` + field + `\s+in\s+\[([^\]]*)\]`).FindStringSubmatch(expr)
	require.NotNil(t, clause, "no `resourceAttributes.%s in [...]` clause in the matchConditions", field)

	var out []string
	for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(clause[1], -1) {
		out = append(out, m[1])
	}
	return out
}

// authorizationConfiguration is the subset of the AuthorizationConfiguration these tests read.
// Not the upstream type: apiserver's config types are internal to the API server.
type authorizationConfiguration struct {
	Authorizers []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Webhook *struct {
			Timeout         metaDuration `json:"timeout"`
			UnauthorizedTTL metaDuration `json:"unauthorizedTTL"`
			FailurePolicy   string       `json:"failurePolicy"`
			MatchConditions []struct {
				Expression string `json:"expression"`
			} `json:"matchConditions"`
		} `json:"webhook"`
	} `json:"authorizers"`
}

// metaDuration decodes the "3s" / "30s" / "5m" form the config file uses.
type metaDuration time.Duration

func (d *metaDuration) UnmarshalJSON(b []byte) error {
	// Unquote rather than slicing: a bare number in the YAML (timeout: 3) would panic and hide
	// the config error this test exists to report.
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
	MatchConditions []string
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
		settings := webhookSettings{
			Timeout:         time.Duration(a.Webhook.Timeout),
			UnauthorizedTTL: time.Duration(a.Webhook.UnauthorizedTTL),
		}
		for _, mc := range a.Webhook.MatchConditions {
			settings.MatchConditions = append(settings.MatchConditions, mc.Expression)
		}
		return settings
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
