// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package logcollector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/url"
)

// renderFluentBitConf renders the fluent-bit configuration (in fluent-bit's
// YAML schema) that fluentBitConfigMap ships: the service and parser
// definitions, then the inputs → filters → outputs pipeline.
func (c *fluentBitComponent) renderFluentBitConf() string {
	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":       5,
			"log_level":   "info",
			"http_server": true,
			"http_port":   FluentBitMetricsPort,
			// Enable the /api/v1/health endpoint the readiness probe hits
			// (without this it returns 404 and pods never become Ready).
			"health_check": true,
			// Filesystem buffering under the same hostPath-backed state dir as
			// the tail offset DBs, so buffered-but-unsent chunks survive pod
			// restarts — an improvement over fluentd, whose buffers were
			// memory-only (the on-disk pos file tracked what had been read,
			// not what had been delivered).
			"storage.path": c.path("/var/log/calico/calico-fluent-bit/storage"),
		},
		// Parsers referenced by the tail inputs. Defined inline so the config is
		// self-contained and does not depend on the image's parsers.conf.
		Parsers: []map[string]interface{}{
			{"name": "json", "format": "json"},
			// Audit events carry their event time in the `time` key; parse it so
			// time-partitioned sinks (S3 day keys, syslog timestamps) use event
			// time, matching fluentd's `time_key time` on the audit sources. Like
			// fluentd (no keep_time_key), the key is consumed by the parser.
			{"name": "json_audit", "format": "json", "time_key": "time", "time_format": "%Y-%m-%dT%H:%M:%S.%L%z"},
			// IDS events carry a unix-seconds `time` key; fluentd parsed it with
			// `time_type unixtime` and kept the key in the record.
			{"name": "json_ids_events", "format": "json", "time_key": "time", "time_format": "%s", "time_keep": true},
			{"name": "bird_regex", "format": "regex", "regex": `^(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{5} bird: (?<message>.*)`},
		},
	}

	c.addInputs(&cfg)
	c.addFilters(&cfg)
	c.addOutputs(&cfg)

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out) + "\n"
}

// addInputs wires the tail inputs (one per log file) and, when non-cluster
// hosts are enabled, the HTTP input their logs arrive on.
func (c *fluentBitComponent) addInputs(cfg *fluentBitConfig) {
	for _, in := range c.logInputs() {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name": "tail",
			"path": c.path(in.path),
			"tag":  in.tag,
			// Persist read offsets in SQLite under /var/log/calico/calico-fluent-bit
			// — the same directory the host rpm/deb package uses, and a subdir of the
			// already-mounted var-log-calico volume — so the tail resumes across
			// restarts instead of re-shipping from the head. The pos-migrator init
			// container seeds these DBs from the legacy fluentd .pos files at cutover;
			// read_from_head only applies to files with no prior offset (first install).
			"db":             c.path(fmt.Sprintf("/var/log/calico/calico-fluent-bit/in_tail_%s.db", in.tag)),
			"parser":         in.parser,
			"read_from_head": true,
			"storage.type":   "filesystem",
			// A line longer than buffer_max_size (32K default) makes in_tail
			// abandon the whole file until it rotates, and kube-audit events
			// routinely exceed 32K (fluentd had no line-length cap). 10M
			// covers anything the apiserver can log — etcd caps objects at
			// ~1.5MiB — and skip_long_lines confines anything larger to
			// dropping that line instead of the file. buffer_chunk_size is
			// the initial per-file buffer and the increment it grows by, so
			// 256K keeps a long line to a few reallocations at trivial cost
			// (only ~a dozen files are tailed per node).
			"buffer_chunk_size": "256K",
			"buffer_max_size":   "10M",
			"skip_long_lines":   true,
		})
	}

	// The ingress path for non-cluster-host log forwarding: voltron relays the
	// hosts' posts to this input, and in_http derives the non_cluster_* tags
	// from the request paths.
	if c.cfg.NonClusterHost != nil && c.osType == rmeta.OSTypeLinux {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name":   "http",
			"listen": "0.0.0.0",
			"port":   FluentBitInputPort,
			// fluentd's http source accepted bodies up to `body_size_limit
			// 100m`; in_http instead rejects anything over buffer_max_size
			// (default ~4M), so keep parity or large relayed batches are
			// silently dropped. buffer_chunk_size is the growth increment for
			// a connection's buffer (the 512K default would mean ~200
			// reallocations for a full-size post).
			"buffer_chunk_size": "5M",
			"buffer_max_size":   "100M",
			"tls":               "on",
			"tls.ca_file":       c.trustedBundlePath(),
			"tls.crt_file":      c.certPath(),
			"tls.key_file":      c.keyPath(),
			// Require a Tigera-CA-signed client certificate: voltron presents its
			// internal client certificate when relaying non-cluster-host posts.
			"tls.verify_client_cert": "on",
			"storage.type":           "filesystem",
		})
	}
}

// addFilters wires the record transforms and any user-provided filters
// between the inputs and the outputs.
func (c *fluentBitComponent) addFilters(cfg *fluentBitConfig) {
	// Per-log-type transforms (host injection, flows @timestamp, audit name
	// derivation, BIRD ip_version + noise drop) live in the image's
	// record_transformer.lua, keyed by tag. The same script also provides
	// syslog_pack, which the syslog outputs run as a per-output processor
	// (see addSyslogOutputs).
	cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, map[string]interface{}{
		"name":   "lua",
		"match":  "*",
		"script": c.luaScriptPath(),
		"call":   "record_transformer",
	})

	// User-provided flow/dns filters: each fluent-bit-filters ConfigMap key
	// holds a YAML list of fluent-bit filter entries, inlined here.
	c.addUserFilters(cfg)
}

// parseUserFilter parses a user-provided filter snippet (the content of a
// fluent-bit-filters ConfigMap key) as a YAML list of fluent-bit filter maps.
func parseUserFilter(content string) ([]map[string]interface{}, error) {
	var filters []map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &filters); err != nil {
		return nil, err
	}
	return filters, nil
}

// InvalidKeys returns the names of the fluent-bit-filters ConfigMap keys whose
// content is non-empty but does not parse as a fluent-bit YAML filter list — for
// example a leftover fluentd <filter> block after an upgrade. addUserFilters skips
// these during render so the pipeline still starts; callers use this to surface the
// misconfiguration to the user without failing the whole LogCollector.
func (f *FluentBitFilters) InvalidKeys() []string {
	if f == nil {
		return nil
	}
	var bad []string
	for _, uf := range []struct{ name, content string }{
		{FluentBitFilterFlowName, f.Flow},
		{FluentBitFilterDNSName, f.DNS},
	} {
		if uf.content == "" {
			continue
		}
		if _, err := parseUserFilter(uf.content); err != nil {
			bad = append(bad, uf.name)
		}
	}
	return bad
}

// addUserFilters inlines the user-provided filter snippets into the pipeline.
// The fluent-bit-filters ConfigMap keys (flow, dns) each hold a YAML list of
// fluent-bit filter maps; entries without an explicit match are scoped to the
// key's log tag. Invalid YAML is skipped (and logged) rather than breaking the
// whole pipeline; the controller surfaces it as a TigeraStatus warning (see
// InvalidKeys).
func (c *fluentBitComponent) addUserFilters(cfg *fluentBitConfig) {
	if c.cfg.Filters == nil || c.osType != rmeta.OSTypeLinux {
		return
	}
	for _, uf := range []struct{ content, tag string }{
		{c.cfg.Filters.Flow, "flows"},
		{c.cfg.Filters.DNS, "dns"},
	} {
		if uf.content == "" {
			continue
		}
		filters, err := parseUserFilter(uf.content)
		if err != nil {
			log.Error(err, "skipping invalid user filter content", "tag", uf.tag)
			continue
		}
		for _, f := range filters {
			if _, ok := f["match"]; !ok {
				if _, ok := f["match_regex"]; !ok {
					f["match"] = uf.tag
				}
			}
			cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, f)
		}
	}
}

// addOutputs wires one Linseed http output per Linseed-bound tag, plus the
// user-enabled additional stores.
func (c *fluentBitComponent) addOutputs(cfg *fluentBitConfig) {
	// One built-in http output per Linseed-bound tag: chunks are per-tag, so
	// an exact match per block routes every record to its bulk endpoint.
	for _, tag := range c.linseedTags() {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs,
			c.linseedHTTPOutput(tag, c.certPath(), c.keyPath(), linseedStorageLimit(tag)))
	}

	// Additional stores are Linux-only, matching the fluentd Windows variant
	// (Linseed only).
	if c.cfg.LogCollector.Spec.AdditionalStores != nil && c.osType == rmeta.OSTypeLinux {
		c.addS3Outputs(cfg)
		c.addSyslogOutputs(cfg)
		c.addSplunkOutputs(cfg)
	}
}

// linseedTags lists the tags shipped to Linseed: every tailed tag except
// ids.events and compliance.reports — those are deliberately not
// Linseed-bound (IDS events use a different ingestion path; compliance
// reports are S3-only). The non_cluster_* tags are produced by the
// voltron-facing http input relaying non-cluster host posts; hosts ship
// flow, DNS and policy activity logs.
func (c *fluentBitComponent) linseedTags() []string {
	var tags []string
	for _, in := range c.logInputs() {
		if in.tag == "ids.events" || in.tag == "compliance.reports" {
			continue
		}
		if c.cloudSuppressesFromLinseed(in.tag) {
			continue
		}
		tags = append(tags, in.tag)
	}
	if c.cfg.NonClusterHost != nil && c.osType == rmeta.OSTypeLinux {
		for _, tag := range []string{"non_cluster_flows", "non_cluster_dns", "non_cluster_policy_activity"} {
			if c.cloudSuppressesFromLinseed(tag) {
				continue
			}
			tags = append(tags, tag)
		}
	}
	return tags
}

// cloudSuppressesFromLinseed reports whether a Calico Cloud install omits a
// tag's Linseed output, preserving the fluentd-era cloud/enterprise feature
// split: cloud never stores DNS, EE/kube audit or BGP logs, and stores flow
// logs only for multi-tenant management clusters. Non-cluster host variants of
// those log types are suppressed alongside their base tag. (Formerly the
// fluentd DISABLE_ES_{DNS,AUDIT_EE,AUDIT_KUBE,BGP,FLOW}_LOG env vars; the
// DISABLE_ES_* toggles died with the fluentd ES output, so the equivalent is
// simply not wiring the Linseed output for these tags.) Enterprise (Cloud
// false) ships every tag as before.
func (c *fluentBitComponent) cloudSuppressesFromLinseed(tag string) bool {
	if !c.cfg.Cloud {
		return false
	}
	switch tag {
	case "dns", "non_cluster_dns", "audit.tsee", "audit.kube", "bird", "bird6":
		return true
	case "flows", "non_cluster_flows":
		return !c.cfg.Tenant.MultiTenant()
	default:
		return false
	}
}

// linseedBulkURI maps a tag to its Linseed bulk-ingestion URI. Voltron-relayed
// non_cluster_* tags post to the same path as their base tag.
func linseedBulkURI(tag string) string {
	tag = strings.TrimPrefix(tag, "non_cluster_")
	switch tag {
	case "runtime":
		return "/api/v1/runtime/reports/bulk"
	case "audit.tsee":
		return "/api/v1/audit/logs/ee/bulk"
	case "audit.kube":
		return "/api/v1/audit/logs/kube/bulk"
	case "bird", "bird6":
		return "/api/v1/bgp/logs/bulk"
	default:
		// flows, dns, l7, waf, policy_activity
		return fmt.Sprintf("/api/v1/%s/logs/bulk", tag)
	}
}

// splitEndpoint splits an https:// endpoint into the host and port fields
// fluent-bit's native net layer expects (the port defaults to 443). Plain
// string handling: pkg/url's ParseEndpoint rejects endpoints without an
// explicit port, and Linseed endpoints usually carry none.
func splitEndpoint(endpoint string) (string, int) {
	host := strings.TrimPrefix(endpoint, "https://")
	host = strings.TrimSuffix(host, "/")
	port := 443
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if n, err := strconv.Atoi(host[i+1:]); err == nil {
			host, port = host[:i], n
		}
	}
	return host, port
}

// linseedHTTPOutput renders one built-in http output block shipping a tag's
// chunks to its Linseed bulk endpoint. The http output is plain C compiled
// into fluent-bit — no Go proxy plugin is involved — and `format json_lines`
// with the date key disabled produces exactly the NDJSON body Linseed's bulk
// APIs expect. The bearer token file is re-read on every request (a Tigera
// patch carried by the fluent-bit base build), so kubelet-rotated
// ServiceAccount tokens and operator-refreshed managed-cluster tokens are
// picked up without a restart. certPath/keyPath are the mTLS client keypair;
// storageLimit, when non-empty, caps this output's filesystem buffer.
func (c *fluentBitComponent) linseedHTTPOutput(tag, certPath, keyPath, storageLimit string) map[string]interface{} {
	host, port := splitEndpoint(relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, render.LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, true))
	out := map[string]interface{}{
		"name":   "http",
		"match":  tag,
		"host":   host,
		"port":   port,
		"uri":    linseedBulkURI(tag),
		"format": "json_lines",
		// One record per line, nothing else: Linseed parses each line as the
		// log document itself, so no synthetic date field is added.
		"json_date_key": false,
		"tls":           "on",
		"tls.verify":    "on",
		// tls.verify only checks the chain; hostname/SAN verification is a
		// separate knob that defaults off in fluent-bit. The Go plugin this
		// replaces verified hostnames (crypto/tls default), so keep parity.
		"tls.verify_hostname": "on",
		"tls.ca_file":         c.trustedBundlePath(),
		"tls.crt_file":        certPath,
		"tls.key_file":        keyPath,
		"bearer_token_file":   c.path(render.GetLinseedTokenPath(c.cfg.ManagedCluster)),
		// Retry failed chunks until they send instead of dropping them after
		// the default single retry; the filesystem storage bounds what can
		// accumulate during a Linseed outage.
		"retry_limit": "no_limits",
	}
	if storageLimit != "" {
		out["storage.total_limit_size"] = storageLimit
	}
	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		out["header"] = fmt.Sprintf("x-tenant-id %s", c.cfg.Tenant.Spec.ID)
	}
	return out
}

// linseedStorageLimit caps a tag's filesystem buffer — storage.total_limit_size
// bounds all of an output's buffered chunks, first-try and retries alike. Flow
// logs are the dominant volume and keep the budget the single shared output
// used to have; everything else is low-volume.
func linseedStorageLimit(tag string) string {
	if tag == "flows" || tag == "non_cluster_flows" {
		return "500M"
	}
	return "100M"
}

// hostScopeIncludesCluster reports whether a store's hostScope includes
// cluster logs. Fluentd's envVarsForHostScope semantics: cluster *flow* logs
// are the only cluster type the scope gates (FORWARD_CLUSTER_LOGS_TO_<STORE>),
// and non-cluster flows always ship when the store is enabled
// (FORWARD_NON_CLUSTER_LOGS_TO_<STORE> was true for both All and
// NonClusterOnly).
func hostScopeIncludesCluster(hostScope *operatorv1.HostScope) bool {
	return hostScope == nil || *hostScope != operatorv1.HostScopeNonClusterOnly
}

func (c *fluentBitComponent) addS3Outputs(cfg *fluentBitConfig) {
	s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3
	if s3 == nil {
		return
	}
	// tag → S3 key directory. This is a deliberate, documented layout change
	// from fluentd (release-noted): fluentd's fluent-plugin-s3 default object
	// key format produced flat keys with the date concatenated straight onto
	// the type segment (`<bucketPath>/flows20260101_<n>.gz`); the keys are now
	// directory-style, one directory per log type, and non-cluster flows get
	// their own directory instead of being mixed into flows/. Anything
	// downstream anchored to the old flat patterns must be updated once.
	//
	// The type set is unchanged from fluentd: the cluster types below always
	// shipped when S3 was enabled — ee_entrypoint.sh copied their output confs
	// unconditionally under S3_STORAGE=true; only cluster *flows* honored the
	// hostScope gate, and non-cluster flows ship whatever the hostScope. WAF,
	// BGP, IDS events and policy activity were never S3-archived
	// (out-s3-waf.conf existed but was never copied).
	type s3Output struct{ tag, path string }
	outputs := []s3Output{
		{"dns", "dns"},
		{"l7", "l7"},
		{"runtime", "runtime"},
		{"audit.tsee", "audit_tsee"},
		{"audit.kube", "audit_kube"},
		{"compliance.reports", "compliance_reports"},
		{"non_cluster_flows", "non_cluster_flows"},
	}
	if hostScopeIncludesCluster(s3.HostScope) {
		outputs = append([]s3Output{{"flows", "flows"}}, outputs...)
	}
	for _, o := range outputs {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, map[string]interface{}{
			"name":   "s3",
			"match":  o.tag,
			"bucket": s3.BucketName,
			"region": s3.Region,
			// $UUID rather than fluentd's `_<index>` object names: out_s3
			// tracks $INDEX in its store_dir, which is not persisted across
			// pod restarts, so a restarted pod would silently overwrite the
			// day's earlier objects (fluent-plugin-s3 avoided collisions by
			// checking object existence before upload; out_s3 does not).
			"s3_key_format": fmt.Sprintf("%s/%s/%%Y%%m%%d_$UUID.gz", s3.BucketPath, o.path),
			// fluent-plugin-s3's default store_as was gzip, so the legacy
			// archives were gzipped; keep the objects compressed to match
			// their .gz suffix.
			"compression":              "gzip",
			"total_file_size":          "10M",
			"upload_timeout":           fluentBitDefaultFlush,
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		})
	}
}

func (c *fluentBitComponent) addSyslogOutputs(cfg *fluentBitConfig) {
	syslog := c.cfg.LogCollector.Spec.AdditionalStores.Syslog
	if syslog == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(syslog.Endpoint)
	mode := proto
	var syslogTags []string
	for _, t := range syslog.LogTypes {
		switch t {
		case operatorv1.SyslogLogAudit:
			syslogTags = append(syslogTags, "audit.tsee", "audit.kube")
		case operatorv1.SyslogLogDNS:
			syslogTags = append(syslogTags, "dns")
		case operatorv1.SyslogLogFlows:
			// Cluster flows are the only type the hostScope gates
			// (FORWARD_CLUSTER_LOGS_TO_SYSLOG); non-cluster flows always ship
			// when the Flows type is enabled — fluentd copied the NCH syslog
			// output (out-syslog-nch.conf) for both All and NonClusterOnly.
			if hostScopeIncludesCluster(syslog.HostScope) {
				syslogTags = append(syslogTags, "flows")
			}
			syslogTags = append(syslogTags, "non_cluster_flows")
		case operatorv1.SyslogLogIDSEvents:
			syslogTags = append(syslogTags, "ids.events")
		}
	}
	for _, tag := range syslogTags {
		out := map[string]interface{}{
			"name":                  "syslog",
			"match":                 tag,
			"host":                  host,
			"port":                  port,
			"mode":                  mode,
			"syslog_format":         "rfc5424",
			"syslog_hostname_key":   "host",
			"syslog_appname_preset": "tigera_secure",
			// The record's host key wins when present (flows/dns/l7/runtime/waf,
			// stamped by record_transformer.lua, and non-cluster flows, stamped
			// by the sending host); the preset is the fallback for tags without
			// it (audit.*, ids.events), matching fluentd's static
			// `hostname SYSLOG_HOSTNAME` (the node name, injected here through
			// fluent-bit's env-var substitution of the NODENAME pod env var).
			"syslog_hostname_preset": "${NODENAME}",
			// No syslog_severity_preset: it is an integer property (a string
			// like "info" would atoi() to 0 = Emergency); the default, 6, is
			// already info — what fluentd's `severity info` sent.
			//
			// The whole record is shipped as one JSON MSG, preserving fluentd
			// remote_syslog's `<format> @type json` wire format: the per-output
			// lua processor below packs the record into the `log` key, so other
			// outputs still see the unpacked record.
			"syslog_message_key": "log",
			"processors": map[string]interface{}{
				"logs": []map[string]interface{}{{
					"name":   "lua",
					"script": c.luaScriptPath(),
					"call":   "syslog_pack",
				}},
			},
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		if syslog.Encryption == operatorv1.EncryptionTLS {
			out["mode"] = "tls"
			// `mode tls` only selects the framing; the tls property is what
			// actually enables TLS on the upstream connection.
			out["tls"] = "on"
			out["tls.verify"] = "on"
			if c.cfg.UseSyslogCertificate {
				// The user-provided syslog CA is part of the trusted bundle
				// (fluentd pointed SYSLOG_CA_FILE at the same bundle).
				out["tls.ca_file"] = c.trustedBundlePath()
			}
		}
		if syslog.PacketSize != nil {
			out["syslog_maxsize"] = *syslog.PacketSize
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}

func (c *fluentBitComponent) addSplunkOutputs(cfg *fluentBitConfig) {
	splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk
	if splunk == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(splunk.Endpoint)
	// The log types deployed fluentd forwarded to Splunk HEC: the operator only
	// ever enabled SPLUNK_FLOW_LOG, SPLUNK_AUDIT_LOG and SPLUNK_DNS_LOG (the
	// l7/waf/runtime output templates existed but were never wired in). As with
	// the other stores, cluster flows are the only type the hostScope gates
	// (FORWARD_CLUSTER_LOGS_TO_SPLUNK), and non-cluster flows always ship.
	tags := []string{"dns", "audit.tsee", "audit.kube", "non_cluster_flows"}
	if hostScopeIncludesCluster(splunk.HostScope) {
		tags = append([]string{"flows"}, tags...)
	}
	for _, tag := range tags {
		out := map[string]interface{}{
			"name":                     "splunk",
			"match":                    tag,
			"host":                     host,
			"port":                     port,
			"splunk_token":             "${SPLUNK_HEC_TOKEN}",
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		// Honor the endpoint scheme like fluentd's SPLUNK_PROTOCOL did: an
		// http:// HEC endpoint stays plaintext, https:// gets verified TLS
		// against the trusted bundle (which carries any private CA).
		if proto != "http" {
			out["tls"] = "on"
			out["tls.verify"] = "on"
			out["tls.ca_file"] = c.trustedBundlePath()
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}
