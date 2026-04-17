// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

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
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/checker/mocks"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	libnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	socketAddressProtocolTCP = &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_TCP,
			},
		},
	}

	socketAddressProtocolUDP = &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_UDP,
			},
		},
	}
)

// If no service account names are given, the clause matches any name.
func TestMatchName(t *testing.T) {
	testCases := []struct {
		title  string
		names  []string
		name   string
		result bool
	}{
		{"empty", []string{}, "reginald", true},
		{"match", []string{"susan", "jim", "reginald"}, "reginald", true},
		{"no match", []string{"susan", "jim", "reginald"}, "steven", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchName(tc.names, tc.name)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// An empty label selector matches any set of labels.
func TestMatchLabels(t *testing.T) {
	testCases := []struct {
		title    string
		selector string
		labels   map[string]string
		result   bool
	}{
		{"empty", "", map[string]string{"app": "foo", "env": "prod"}, true},
		{"bad selector", "not.a.real.selector", map[string]string{"app": "foo", "env": "prod"}, false},
		{"good selector", "app == 'foo'", map[string]string{"app": "foo", "env": "prod"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchLabels(tc.selector, tc.labels)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// HTTP Methods clause with empty list will match any method.
func TestMatchHTTPMethods(t *testing.T) {
	testCases := []struct {
		title   string
		methods []string
		method  string
		result  bool
	}{
		{"empty", []string{}, "GET", true},
		{"match", []string{"GET", "HEAD"}, "GET", true},
		// HTTP methods are case-sensitive. https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
		{"case-sensitive", []string{"get", "HEAD"}, "GET", false},
		{"wildcard", []string{"*"}, "MADNESS", true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPMethods(tc.methods, &tc.method)).To(Equal(tc.result))
		})
	}
}

// HTTP Paths clause with empty list will match any path.
func TestMatchHTTPPaths(t *testing.T) {
	testCases := []struct {
		title   string
		paths   []*proto.HTTPMatch_PathMatch
		reqPath string
		result  bool
	}{
		{"empty", []*proto.HTTPMatch_PathMatch{}, "/foo", true},
		{"exact", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo", true},
		{"prefix segment boundary", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}}}, "/foo/bar", true},
		{"prefix not segment aligned", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}}}, "/foobar", false},
		{"exact fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/joo", false},
		{"exact not match prefix", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foobar", false},
		{"prefix fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}}}, "/joobar", false},
		{"multiple none match", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/joo"}}, {PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/joobar", false},
		{"multiple one matches", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/joo"}}, {PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/joo/bar", true},
		{"exact path with query", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo?xyz", true},
		{"exact path with fragment", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo#xyz", true},
		{"prefix path with query fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foobar"}}}, "/foo?bar", false},
		{"prefix path with fragment fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foobar"}}}, "/foo#bar", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPPaths(tc.paths, &tc.reqPath)).To(Equal(tc.result))
		})
	}
}

// TestMatchHTTPPaths_Normalization pins down the expected behaviour of
// matchHTTPPaths when the incoming request-target contains characters that
// change meaning after RFC 3986 / RFC 7230 normalisation.
//
// Upstream HTTP servers (Nginx, Apache, Envoy with normalize_path, Go's
// net/http, most language frameworks) collapse ".", "..", and repeated "/"
// segments, and most decode unreserved percent-escapes, before dispatching
// the request to a handler. If matchHTTPPaths decides Allow/Deny against the
// raw request-target, the upstream server can serve a resource different
// from the one Dikastes authorised — which is a path-traversal style
// authorisation bypass (CWE-22 / CWE-23).
//
// Prefix matches must also be anchored to a path-segment boundary, otherwise
// prefix "/pub" authorises "/public-leak-endpoint". RFC 7230 §5.3 and
// common L7 matcher semantics (Envoy, Istio AuthorizationPolicy) treat path
// prefixes as segment-aligned.
//
// Cases below provide regression coverage for normalisation and
// segment-aligned prefix matching.
func TestMatchHTTPPaths_Normalization(t *testing.T) {
	exact := func(p string) *proto.HTTPMatch_PathMatch {
		return &proto.HTTPMatch_PathMatch{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: p}}
	}
	prefix := func(p string) *proto.HTTPMatch_PathMatch {
		return &proto.HTTPMatch_PathMatch{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: p}}
	}

	testCases := []struct {
		title   string
		paths   []*proto.HTTPMatch_PathMatch
		reqPath string
		result  bool
	}{
		// --- Regression guards: legitimate requests must stay matched ---
		{"prefix baseline", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public", true},
		{"prefix with trailing slash", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/", true},
		{"prefix with subpath", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/index.html", true},
		{"exact baseline", []*proto.HTTPMatch_PathMatch{exact("/public")}, "/public", true},
		{"trailing dot-segment collapses to exact", []*proto.HTTPMatch_PathMatch{exact("/public")}, "/public/.", true},

		// --- Dotdot traversal: must NOT match prefix /public ---
		{"dotdot escapes prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/../admin", false},
		{"dotdot nested escapes prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/a/../../admin", false},
		{"dotdot escapes exact", []*proto.HTTPMatch_PathMatch{exact("/public")}, "/public/../public", true}, // normalises to /public
		{"dotdot changes exact", []*proto.HTTPMatch_PathMatch{exact("/public/foo")}, "/public/bar/../foo", true},

		// --- Percent-encoded slashes and dots ---
		{"percent-encoded slash traversal", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public%2F..%2Fadmin", false},
		{"percent-encoded dots traversal", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/%2e%2e/admin", false},
		{"percent-encoded uppercase dots", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/%2E%2E/admin", false},
		{"percent-encoded unreserved should not be re-escaped", []*proto.HTTPMatch_PathMatch{exact("/public/file")}, "/public/%66ile", true}, // %66 = 'f'

		// --- Repeated slash collapse ---
		{"double slash traversal", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public//../admin", false},
		{"leading double slash", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "//public", true},
		{"interior double slash collapsed still matches prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public//foo", true},

		// --- Prefix not anchored to segment boundary ---
		{"short-prefix sibling leak", []*proto.HTTPMatch_PathMatch{prefix("/pub")}, "/public-leak-endpoint", false},
		{"short-prefix sibling path", []*proto.HTTPMatch_PathMatch{prefix("/pub")}, "/public", false},
		{"short-prefix matches own segment", []*proto.HTTPMatch_PathMatch{prefix("/pub")}, "/pub", true},
		{"short-prefix matches deeper segment", []*proto.HTTPMatch_PathMatch{prefix("/pub")}, "/pub/x", true},

		// --- Query/fragment retained after normalisation ---
		{"query stripped then normalised", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/../admin?x=1", false},
		{"fragment stripped then normalised", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/../admin#frag", false},

		// --- Backslash separator: Windows / IIS backends may treat "\" as a path
		// separator. "\" is not a valid HTTP path character per RFC 3986, so we
		// normalise it to "/" before resolving dot-segments to stay aligned with
		// the most permissive (Windows) upstream interpretation. ---
		{"backslash traversal escapes prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public\\..\\admin", false},
		{"backslash mixed with slash", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/..\\admin", false},
		{"percent-encoded backslash traversal", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public%5C..%5Cadmin", false},
		{"backslash within legitimate segment still inside prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/foo\\bar", true},

		// --- Matrix parameters on traversal segments (JSR-339 / Servlet
		// 3.0+). Tomcat, Jetty, Jersey, Spring MVC and Resin strip ";..."
		// per path segment before dispatch, so an attacker can hide a
		// traversal dot-segment inside a matrix parameter suffix: a request
		// like /public/..;x/admin is authorised here as literal segment
		// "..;x" (matches prefix /public), but the upstream strips ";x",
		// resolves the remaining "..", and serves /admin. Strip matrix
		// parameters per segment before dot-segment resolution so we see
		// the same path shape the upstream will. ---
		{"matrix param on dotdot escapes prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/..;x/admin", false},
		{"matrix param jsessionid on dotdot", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/..;jsessionid=abc/admin", false},
		{"matrix param percent-encoded semicolon on dotdot", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/..%3Bx/admin", false},
		{"matrix param on leaf segment still under prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/foo;jsessionid=abc", true},
		{"matrix param on middle segment still under prefix", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/foo;x=1/bar", true},

		// --- Still-encoded separators after single decode. A compliant
		// upstream decodes once, but Spring Security
		// (setAllowUrlEncodedSlash), some nginx merge_slashes=off
		// configurations, and some WAF placements decode twice. A request
		// whose single-decode form still contains a path-sensitive
		// percent-escape (%2e / %2f / %5c) carries a second layer of
		// traversal payload that a double-decoding upstream would resolve
		// into a different path than the one we authorise here. Reject so
		// the authorisation view stays aligned with the most permissive
		// upstream. ---
		{"double-encoded dotdot rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/%252e%252e/admin", false},
		{"double-encoded slash rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public%252fadmin", false},
		{"double-encoded backslash rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public%255c..%255cadmin", false},
		{"deep double-encoded dot rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/%25%32%65%25%32%65/admin", false},

		// --- Null byte. Some Java stacks and any C-string-aware upstream
		// treat a null byte as end-of-string: "/admin%00/../public" on
		// such a stack truncates to "/admin" at dispatch, which would let
		// a request bypass a rule targeting the truncated prefix. Reject
		// null bytes so the authorisation view stays aligned. ---
		{"percent-null in traversal rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public%00/admin", false},
		{"percent-null mid-segment rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/foo%00bar", false},
		{"raw null byte rejected", []*proto.HTTPMatch_PathMatch{prefix("/public")}, "/public/foo\x00", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPPaths(tc.paths, &tc.reqPath)).To(Equal(tc.result))
		})
	}
}

// TestNormalizeHTTPPath exercises normalizeHTTPPath directly so its contract
// is pinned independently of the matchHTTPPaths rule-iteration logic. Each
// case lists the raw path Envoy may deliver and the canonical path that must
// be used for authorisation decisions.
func TestNormalizeHTTPPath(t *testing.T) {
	cases := []struct {
		title string
		in    string
		want  string
		ok    bool
	}{
		{"root", "/", "/", true},
		{"plain", "/public", "/public", true},
		{"trailing slash stripped", "/public/", "/public", true},
		{"single dot segment", "/public/.", "/public", true},
		{"dotdot resolved", "/public/../admin", "/admin", true},
		{"nested dotdot resolved", "/public/a/../../admin", "/admin", true},
		{"dotdot above root clamped", "/..", "/", true},
		{"repeated slash collapsed", "/public//foo", "/public/foo", true},
		{"leading repeated slash collapsed", "//public", "/public", true},
		{"percent-encoded slash decoded", "/public%2F..%2Fadmin", "/admin", true},
		{"percent-encoded dot decoded", "/public/%2e%2e/admin", "/admin", true},
		{"percent-encoded unreserved decoded", "/public/%66ile", "/public/file", true},
		{"query stripped before decode", "/public/../admin?q=1", "/admin", true},
		{"fragment stripped before decode", "/public/../admin#x", "/admin", true},
		{"encoded query marker stays literal", "/public%3Ffoo", "/public?foo", true},
		{"backslash converted to slash", "/public/..\\admin", "/admin", true},
		{"only backslash separators", "\\public\\..\\admin", "/admin", true},
		{"percent-encoded backslash decoded and normalised", "/public%5C..%5Cadmin", "/admin", true},
		{"matrix param on leaf stripped", "/public/foo;x=1", "/public/foo", true},
		{"matrix param jsessionid stripped", "/public/foo;jsessionid=abc", "/public/foo", true},
		{"matrix param on dotdot resolves traversal", "/public/..;x/admin", "/admin", true},
		{"matrix param on every segment stripped", "/a;p=1/b;q=2/c;r=3", "/a/b/c", true},
		{"percent-encoded semicolon stripped", "/public/..%3Bx/admin", "/admin", true},
		{"double percent-encoded dot rejected", "/public/%252e%252e/admin", "", false},
		{"double percent-encoded slash rejected", "/public%252fadmin", "", false},
		{"double percent-encoded backslash rejected", "/public%255c..%255cadmin", "", false},
		{"deep double-encoded dot rejected", "/public/%25%32%65%25%32%65/admin", "", false},
		{"mixed-case double-encoded dot rejected", "/public/%252E%252E/admin", "", false},
		{"percent-null rejected", "/public%00/admin", "", false},
		{"raw null byte rejected", "/public/foo\x00bar", "", false},
		{"invalid percent escape rejected", "/%XY/admin", "", false},
		{"non-absolute rejected", "relative/path", "", false},
		{"absolute URI form rejected", "http://example.com/admin", "", false},
		{"empty rejected", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			got, ok := normalizeHTTPPath(tc.in)
			Expect(ok).To(Equal(tc.ok), "ok mismatch for input %q", tc.in)
			if tc.ok {
				Expect(got).To(Equal(tc.want), "normalised form mismatch for input %q", tc.in)
			}
		})
	}
}

// FuzzMatchHTTPPaths is a canary that explores arbitrary request paths and
// asserts structural invariants on the normalised form whenever normalisation
// succeeds:
//
//   - Starts with "/".
//   - Contains no "\" separator (backslashes are folded during normalisation).
//   - Contains no "//" (repeated slashes collapsed).
//   - Contains no "." or ".." path segments (dot-segments resolved).
//
// Idempotence is intentionally not asserted: the normaliser is a deliberate
// single-decode to match a compliant upstream HTTP server. An input with two
// layers of percent-encoding (e.g. "%252e%252e") normalises to one with a
// literal "%2e%2e" segment; a second normalisation would decode further and
// diverge. See the "double percent-encoded traversal stays literal" case in
// TestMatchHTTPPaths_Normalization for the pinned behaviour.
func FuzzMatchHTTPPaths(f *testing.F) {
	seeds := []string{
		"/public",
		"/public/",
		"/public/index.html",
		"/public/../admin",
		"/public%2F..%2Fadmin",
		"/public//../admin",
		"/public-leak",
		"/public/%2e%2e/admin",
		"/public/..\\admin",
		"/public%5C..%5Cadmin",
		"/public/%252e%252e/admin",
		"/%2e%2e/admin",
		"/public/foo%00bar",
		"/public/.",
		"/public/./././foo",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// Reject inputs that the matcher is documented to panic on — those are
		// filtered before the matcher would ever see them in production.
		if raw == "" || raw[0] != '/' {
			return
		}
		got, ok := normalizeHTTPPath(raw)
		if !ok {
			return
		}
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("normalised path %q (from %q) does not start with /", got, raw)
		}
		if strings.Contains(got, "\\") {
			t.Fatalf("normalised path %q (from %q) still contains backslash", got, raw)
		}
		if strings.Contains(got, "//") {
			t.Fatalf("normalised path %q (from %q) still contains repeated slash", got, raw)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("normalised path %q (from %q) still contains dot-segment", got, raw)
			}
		}
	})
}

// An omitted HTTP Match clause always matches.
func TestMatchHTTPNil(t *testing.T) {
	RegisterTestingT(t)

	Expect(matchHTTP(nil, nil, nil)).To(BeTrue())
}

// Test HTTPPaths panic on invalid data.
func TestPanicHTTPPaths(t *testing.T) {
	RegisterTestingT(t)

	defer func() {
		Expect(recover()).To(BeAssignableToTypeOf(&InvalidDataFromDataPlane{}))
	}()
	paths := []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}
	reqPath := "foo"
	matchHTTPPaths(paths, &reqPath)
}

// Matching a whole rule should require matching all subclauses.
func TestMatchRule(t *testing.T) {
	RegisterTestingT(t)
	srcAddr := "192.168.4.22"
	dstAddr := "10.54.44.23"

	rule := &proto.Rule{
		SrcServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"john", "stevie", "sam"},
		},
		DstServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"ian"},
		},
		SrcIpSetIds:    []string{"src0", "src1"},
		NotSrcIpSetIds: []string{"notSrc0", "notSrc1"},
		DstIpSetIds:    []string{"dst0", "dst1"},
		NotDstIpSetIds: []string{"notDst0", "notDst1"},

		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET", "POST"},
			Paths:   []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/path"}}, {PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/pathlong"}}},
		},
		Protocol: &proto.Protocol{
			NumberOrName: &proto.Protocol_Name{
				Name: "TCP",
			},
		},
		SrcPorts: []*proto.PortRange{
			{First: 8458, Last: 8460},
			{First: 12, Last: 12},
		},
		DstPorts: []*proto.PortRange{
			{First: 76, Last: 80},
			{First: 70, Last: 79},
		},
		SrcNet: []string{"192.168.4.0/24"},
		DstNet: []string{"10.54.0.0/16"},
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sam",
			Address: &core.Address{Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address:       srcAddr,
					Protocol:      core.SocketAddress_TCP,
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 8458},
				}}},
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/ian",
			Address: &core.Address{Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address:       dstAddr,
					Protocol:      core.SocketAddress_TCP,
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 80},
				}}},
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
				Path:   "/path",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	addIPSet(store, "src0", srcAddr)
	addIPSet(store, "src1", srcAddr, dstAddr)
	addIPSet(store, "notSrc0", "5.6.7.8", dstAddr)
	addIPSet(store, "notSrc1", "5.6.7.8")
	addIPSet(store, "dst0", dstAddr)
	addIPSet(store, "dst1", srcAddr, dstAddr)
	addIPSet(store, "notDst0", "5.6.7.8")
	addIPSet(store, "notDst1", "5.6.7.8", srcAddr)

	flow := NewCheckRequestToFlowAdapter(req)
	reqCache := NewRequestCache(store, flow)
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcServiceAccountMatch
	ossan := rule.SrcServiceAccountMatch.Names
	rule.SrcServiceAccountMatch.Names = []string{"wendy"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcServiceAccountMatch.Names = ossan
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstServiceAccountMatch
	odsan := rule.DstServiceAccountMatch.Names
	rule.DstServiceAccountMatch.Names = []string{"wendy"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstServiceAccountMatch.Names = odsan
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcIpSetIds
	osipi := rule.SrcIpSetIds
	rule.SrcIpSetIds = []string{"notSrc0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcIpSetIds = osipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstIpSetIds
	odipi := rule.DstIpSetIds
	rule.DstIpSetIds = []string{"notDst0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstIpSetIds = odipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// NotSrcIpSetIds
	onsipi := rule.NotSrcIpSetIds
	rule.NotSrcIpSetIds = []string{"src0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.NotSrcIpSetIds = onsipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// NotDstIpSetIds
	ondipi := rule.NotDstIpSetIds
	rule.NotDstIpSetIds = []string{"dst0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.NotDstIpSetIds = ondipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// HTTPMatch
	ohm := rule.HttpMatch.Methods
	rule.HttpMatch.Methods = []string{"HEAD"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.HttpMatch.Methods = ohm
	Expect(match("", rule, reqCache)).To(BeTrue())

	// HTTPPath
	ohp := rule.HttpMatch.Paths
	rule.HttpMatch.Paths = []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/nopath"}}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.HttpMatch.Paths = ohp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// Protocol
	op := rule.Protocol.GetName()
	rule.Protocol.NumberOrName = &proto.Protocol_Name{Name: "UDP"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.Protocol.NumberOrName = &proto.Protocol_Name{Name: op}
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcPorts
	osp := rule.SrcPorts
	rule.SrcPorts = []*proto.PortRange{{First: 25, Last: 25}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcPorts = osp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstPorts
	odp := rule.DstPorts
	rule.DstPorts = []*proto.PortRange{{First: 25, Last: 25}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstPorts = odp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcNet
	osn := rule.SrcNet
	rule.SrcNet = []string{"30.0.0.0/8"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcNet = osn
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstNet
	odn := rule.DstNet
	rule.DstNet = []string{"30.0.0.0/8"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstNet = odn
	Expect(match("", rule, reqCache)).To(BeTrue())
}

// Test namespace selectors are handled correctly
func TestMatchRuleNamespaceSelectors(t *testing.T) {
	RegisterTestingT(t)

	rule := &proto.Rule{
		OriginalSrcNamespaceSelector: "place == 'src'",
		OriginalDstNamespaceSelector: "place == 'dst'",
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/src/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/dst/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	id := proto.NamespaceID{Name: "src"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "src"}}
	id = proto.NamespaceID{Name: "dst"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "dst"}}
	reqCache := NewRequestCache(store, flow)
	Expect(match("", rule, reqCache)).To(BeTrue())
}

// Test that rules only match same namespace if pod selector or service account is set
func TestMatchRulePolicyNamespace(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	reqCache := NewRequestCache(store, flow)

	// With pod selector
	rule := &proto.Rule{
		OriginalSrcSelector: "has(app)",
	}
	Expect(match("different", rule, reqCache)).To(BeFalse())
	Expect(match("testns", rule, reqCache)).To(BeTrue())

	// With no pod selector or SA selector
	rule.OriginalSrcSelector = ""
	Expect(match("different", rule, reqCache)).To(BeTrue())

	// With SA selector
	rule.SrcServiceAccountMatch = &proto.ServiceAccountMatch{Names: []string{"sam"}}
	Expect(match("different", rule, reqCache)).To(BeFalse())
	Expect(match("testns", rule, reqCache)).To(BeTrue())
}

func addIPSet(store *policystore.PolicyStore, id string, addr ...string) {
	s := policystore.NewIPSet(proto.IPSetUpdate_IP)
	for _, a := range addr {
		s.AddString(a)
	}
	store.IPSetByID[id] = s
}

// Test that rules match L4 protocol.
func TestMatchL4Protocol(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	reqCache := NewRequestCache(store, flow)

	// With empty rule and default request.
	rule := &proto.Rule{}
	Expect(match("testns", rule, reqCache)).To(BeTrue())

	// With empty rule and UDP request
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	req.GetAttributes().GetDestination().Address = nil

	// With Protocol=TCP rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=6 rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 6,
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=17 rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 17,
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol!=UDP rule and default request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "UDP",
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol!=6 rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 6,
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and UDP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol == 1 rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 1,
		},
	}
	Expect(matchL4Protocol(rule, 1)).To(BeTrue())
	Expect(matchL4Protocol(rule, 100)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != 1 rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 1,
		},
	}
	Expect(matchL4Protocol(rule, 1)).To(BeFalse())
	Expect(matchL4Protocol(rule, 100)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == ICMP rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "ICMP",
		},
	}
	Expect(matchL4Protocol(rule, 1)).To(BeTrue())
	Expect(matchL4Protocol(rule, 99)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != ICMP rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "ICMP",
		},
	}
	Expect(matchL4Protocol(rule, 1)).To(BeFalse())
	Expect(matchL4Protocol(rule, 99)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == 132 (SCTP) rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 132,
		},
	}
	Expect(matchL4Protocol(rule, 132)).To(BeTrue())
	Expect(matchL4Protocol(rule, 110)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != 132 (SCTP) rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 132,
		},
	}
	Expect(matchL4Protocol(rule, 132)).To(BeFalse())
	Expect(matchL4Protocol(rule, 110)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == SCTP rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "SCTP",
		},
	}
	Expect(matchL4Protocol(rule, 132)).To(BeTrue())
	Expect(matchL4Protocol(rule, 120)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != SCTP rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "SCTP",
		},
	}
	Expect(matchL4Protocol(rule, 132)).To(BeFalse())
	Expect(matchL4Protocol(rule, 120)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == 58 (ICMPv6) rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 58,
		},
	}
	Expect(matchL4Protocol(rule, 58)).To(BeTrue())
	Expect(matchL4Protocol(rule, 60)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != 58 (ICMPv6) rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 58,
		},
	}
	Expect(matchL4Protocol(rule, 58)).To(BeFalse())
	Expect(matchL4Protocol(rule, 60)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == ICMPv6 rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "ICMPv6",
		},
	}
	Expect(matchL4Protocol(rule, 58)).To(BeTrue())
	Expect(matchL4Protocol(rule, 40)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != ICMPv6 rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "ICMPv6",
		},
	}
	Expect(matchL4Protocol(rule, 58)).To(BeFalse())
	Expect(matchL4Protocol(rule, 40)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == 136 (UDPLite) rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 136,
		},
	}
	Expect(matchL4Protocol(rule, 136)).To(BeTrue())
	Expect(matchL4Protocol(rule, 60)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != 136 (UDPLite) rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 136,
		},
	}
	Expect(matchL4Protocol(rule, 136)).To(BeFalse())
	Expect(matchL4Protocol(rule, 60)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol == ICMPv6 rule.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "UDPLite",
		},
	}
	Expect(matchL4Protocol(rule, 136)).To(BeTrue())
	Expect(matchL4Protocol(rule, 80)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol != ICMPv6 rule.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "UDPLite",
		},
	}
	Expect(matchL4Protocol(rule, 136)).To(BeFalse())
	Expect(matchL4Protocol(rule, 80)).To(BeTrue())
	rule.NotProtocol = nil

	// With an random protocol.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 99,
		},
	}
	Expect(matchL4Protocol(rule, 99)).To(BeTrue())
	Expect(matchL4Protocol(rule, 80)).To(BeFalse())
	rule.Protocol = nil

	// With an randome protocol NOT selected.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 99,
		},
	}
	Expect(matchL4Protocol(rule, 99)).To(BeFalse())
	Expect(matchL4Protocol(rule, 80)).To(BeTrue())
	rule.NotProtocol = nil

	// With a randome protocol name.
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "protoX",
		},
	}
	Expect(matchL4Protocol(rule, 99)).To(BeFalse())
	Expect(matchL4Protocol(rule, 0)).To(BeFalse())
	Expect(matchL4Protocol(rule, 300)).To(BeFalse())
	Expect(matchL4Protocol(rule, -30)).To(BeFalse())
	rule.Protocol = nil

	// With a randome protocol name NOT selecte.
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "protoX",
		},
	}
	Expect(matchL4Protocol(rule, 99)).To(BeTrue())
	Expect(matchL4Protocol(rule, 0)).To(BeFalse())
	Expect(matchL4Protocol(rule, 300)).To(BeFalse())
	Expect(matchL4Protocol(rule, -30)).To(BeFalse())
	rule.NotProtocol = nil
}

func TestMatchNet(t *testing.T) {
	testCases := []struct {
		title string
		nets  []string
		ip    string
		match bool
	}{
		{
			title: "empty",
			nets:  nil,
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "single v4 net match",
			nets:  []string{"192.168.3.0/24"},
			ip:    "192.168.3.145",
			match: true,
		},
		{
			title: "single v6 net match",
			nets:  []string{"45ab:0023::/32"},
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "v4 ip v6 net no match",
			nets:  []string{"55ae:4481::/0"},
			ip:    "192.168.3.145",
			match: false,
		},
		{
			title: "v6 ip v4 set no match",
			nets:  []string{"10.0.0.0/0"},
			ip:    "45ab:0023::abcd",
			match: false,
		},
		{
			title: "mixed v6 net match",
			nets:  []string{"45ab:0023::/32", "192.168.0.0/16"},
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "mixed v4 net match",
			nets:  []string{"45ab:0023::/32", "192.168.0.0/16"},
			ip:    "192.168.21.21",
			match: true,
		},
		{
			title: "single v4 net no match",
			nets:  []string{"192.168.0.0/16"},
			ip:    "55.39.128.9",
			match: false,
		},
		{
			title: "single v6 net no match",
			nets:  []string{"45ab:0023::/32"},
			ip:    "85ab:0023::abcd",
			match: false,
		},
		{
			title: "multiple nets no match",
			nets:  []string{"45.81.99.128/25", "10.0.0.0/8", "13.12.0.0/16"},
			ip:    "45.81.99.1",
			match: false,
		},
		{
			title: "multiple nets match",
			nets:  []string{"45.81.99.0/24", "10.0.0.0/8", "13.12.0.0/16"},
			ip:    "45.81.99.1",
			match: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)

			ip := libnet.ParseIP(tc.ip)
			Expect(matchNet("test", tc.nets, ip.Network().IP)).To(Equal(tc.match))
		})
	}
}

func TestMatchNetBadCIDR(t *testing.T) {
	RegisterTestingT(t)

	ip := libnet.ParseIP("192.168.5.6")
	nets := []string{"192.168.0.0.0/16"}
	Expect(matchNet("test", nets, ip.Network().IP)).To(BeFalse())
}

func TestMatchNets(t *testing.T) {
	RegisterTestingT(t)

	testCases := []struct {
		title     string
		nets      []string
		srcIP     string
		dstIP     string
		srcResult bool
		dstResult bool
	}{
		{"empty nets", nil, "192.168.1.1", "192.168.1.1", true, true},
		{"single net match", []string{"192.168.1.0/24"}, "192.168.1.1", "192.168.1.1", true, true},
		{"single net no match", []string{"192.168.2.0/24"}, "192.168.1.1", "192.168.1.1", false, false},
		{"multiple nets match", []string{"192.168.2.0/24", "192.168.1.0/24"}, "192.168.1.1", "192.168.1.1", true, true},
		{"multiple nets no match", []string{"192.168.2.0/24", "192.168.3.0/24"}, "192.168.1.1", "192.168.1.1", false, false},
		{"invalid net", []string{"invalid"}, "192.168.1.1", "192.168.1.1", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			srcIP := libnet.ParseIP(tc.srcIP).IP
			dstIP := libnet.ParseIP(tc.dstIP).IP

			srcFlow := &mocks.Flow{}
			srcFlow.On("GetSourceIP").Return(srcIP)

			dstFlow := &mocks.Flow{}
			dstFlow.On("GetDestIP").Return(dstIP)

			srcResult := matchSrcNet(&proto.Rule{SrcNet: tc.nets}, &requestCache{srcFlow, nil})
			dstResult := matchDstNet(&proto.Rule{DstNet: tc.nets}, &requestCache{dstFlow, nil})

			Expect(srcResult).To(Equal(tc.srcResult), "Test case: %s", tc.title)
			Expect(dstResult).To(Equal(tc.dstResult), "Test case: %s", tc.title)
		})
	}
}

func TestMatchDstIPPortSetIds(t *testing.T) {
	RegisterTestingT(t)

	testCases := []struct {
		title    string
		rule     *proto.Rule
		destIP   string
		destPort int
		proto    int
		expected bool
	}{
		{
			title: "match IP in set80",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set80"},
			},
			destIP:   "192.168.1.1",
			destPort: 80,
			proto:    6,
			expected: true,
		},
		{
			title: "no match IP in set80",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set80"},
			},
			destIP:   "192.168.1.3",
			destPort: 80,
			proto:    6,
			expected: false,
		},
		{
			title: "match IP in set443",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set443"},
			},
			destIP:   "192.168.1.2",
			destPort: 443,
			proto:    17,
			expected: true,
		},
		{
			title: "no match IP in set443",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set443"},
			},
			destIP:   "192.168.1.4",
			destPort: 443,
			proto:    17,
			expected: false,
		},
		{
			title: "match IP in set with multiple entries",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setMulti"},
			},
			destIP:   "192.168.1.5",
			destPort: 8080,
			proto:    6,
			expected: true,
		},
		{
			title: "no match IP in set with multiple entries",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setMulti"},
			},
			destIP:   "192.168.1.6",
			destPort: 8080,
			proto:    6,
			expected: false,
		},
		{
			title: "match IP in set with different protocol",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setProto"},
			},
			destIP:   "192.168.1.7",
			destPort: 53,
			proto:    17,
			expected: true,
		},
		{
			title: "no match IP in set with different protocol",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setProto"},
			},
			destIP:   "192.168.1.7",
			destPort: 53,
			proto:    6,
			expected: false,
		},
	}

	store := policystore.NewPolicyStore()
	set80 := policystore.NewIPSet(proto.IPSetUpdate_IP)
	set80.AddString("192.168.1.1,tcp:80")
	set443 := policystore.NewIPSet(proto.IPSetUpdate_IP)
	set443.AddString("192.168.1.2,udp:443")
	setMulti := policystore.NewIPSet(proto.IPSetUpdate_IP)
	setMulti.AddString("192.168.1.5,tcp:8080")
	setMulti.AddString("192.168.1.5,tcp:9090")
	setProto := policystore.NewIPSet(proto.IPSetUpdate_IP)
	setProto.AddString("192.168.1.7,udp:53")
	store.IPSetByID["set80"] = set80
	store.IPSetByID["set443"] = set443
	store.IPSetByID["setMulti"] = setMulti
	store.IPSetByID["setProto"] = setProto

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			fl := &mocks.Flow{}
			fl.On("GetDestIP").Return(libnet.ParseIP(tc.destIP).IP)
			fl.On("GetDestPort").Return(tc.destPort)
			fl.On("GetProtocol").Return(tc.proto)

			req := &requestCache{fl, store}
			Expect(matchDstIPPortSetIds(tc.rule, req)).To(Equal(tc.expected), "Test case: %s", tc.title)
		})
	}
}
