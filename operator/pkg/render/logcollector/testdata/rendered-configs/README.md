# Rendered fluent-bit config goldens

Each file is the full `fluent-bit.yaml` the operator renders (the
`calico-fluent-bit-conf` ConfigMap; `eks-*` goldens are the
`eks-log-forwarder-conf` ConfigMap) for one configuration scenario, pinned
byte-for-byte by `TestRenderedConfigGoldens` in `golden_test.go`. The rendered
content is JSON (a strict subset of YAML), so per-case commentary lives here
and in the test table rather than inside the files.

The scenario set mirrors fluentd's config test harness
(`calico-private/fluentd/test/test.sh`), which generated `fluent.conf` from a
case's env vars and compared it against a golden `.cfg`. Store endpoints,
buckets and log-type selections reuse the same values test.sh used, so a
golden here can be read side-by-side with its fluentd `.cfg` counterpart.

To accept an intentional rendering change:

    UPDATE_RENDERED_CONFIGS=1 go test ./pkg/render/logcollector/ -run TestRenderedConfigGoldens

## fluentd test.sh case → golden mapping

| fluentd test.sh case | Golden | Notes |
|---|---|---|
| `linseed` | `linseed.yaml` | Default render: per-tag Linseed http outputs, tail inputs, lua transforms. |
| `es-no-secure` | n/a | The Elasticsearch output was retired with fluentd (EV-6164); Linseed is the sole structured-log sink. |
| `es-secure` | n/a | Same — ES output retired. |
| `disable-es-secure` | n/a | Same — the `DISABLE_ES_*_LOG` toggles died with the ES output. |
| `disable-some-es-secure` | n/a | Same. |
| `disable-es-unsecure` | n/a | Same. |
| `disable-some-es-unsecure` | n/a | Same. |
| `es-secure-with-s3` | `s3.yaml` | ES part n/a; S3 store with test.sh's bucket/region/path. |
| `es-secure-with-s3-nch` | `s3-non-cluster-only.yaml` | test.sh's `FORWARD_CLUSTER_LOGS_TO_S3=false` ≙ `hostScope: NonClusterOnly`. |
| `es-no-secure-with-syslog-no-tls` | `syslog-no-tls.yaml` | udp endpoint, flows only — mirrors `SYSLOG_NO_TLS_VARS`. |
| `es-secure-with-syslog-with-tls` | `syslog-tls.yaml` | tcp+TLS, flows/audit/IDS. fluentd's case enabled kube-audit only; the operator's `Audit` type always enables audit.tsee **and** audit.kube (there is no per-audit-kind CRD knob), so `audit.tsee` appears here where the fluentd golden had kube-audit alone. |
| `es-secure-with-syslog-with-tls-all-log-types` | `syslog-tls-all-log-types.yaml` | All CRD-legal types (Audit, DNS, Flows, IDSEvents). fluentd's case also toggled the container's L7/runtime/WAF syslog envs, which the operator API never exposed (the CRD enum is Audit;DNS;Flows;IDSEvents). |
| `es-secure-with-syslog-with-tls-nch` | `syslog-tls-non-cluster-only.yaml` | `FORWARD_CLUSTER_LOGS_TO_SYSLOG=false` ≙ `hostScope: NonClusterOnly`: cluster flows drop out, non-cluster flows keep shipping, other enabled types are unaffected (only flows were ever hostScope-gated). |
| `es-secure-with-syslog-with-tls-all-log-types-nch` | `syslog-tls-all-log-types-non-cluster-only.yaml` | See above. |
| `es-secure-with-syslog-and-s3` | `syslog-and-s3.yaml` | Both stores together. |
| `es-secure-with-syslog-and-s3-nch` | `syslog-and-s3-non-cluster-only.yaml` | Both stores `NonClusterOnly`. |
| `splunk-trusted-http-https` | `splunk-https.yaml`, `splunk-http.yaml` | The fluentd case exercised both schemes in one golden; the operator takes a single endpoint, so one golden per scheme (https verifies against the trusted bundle, http stays plaintext). |
| `splunk-trusted-http-https-nch` | `splunk-non-cluster-only.yaml` | |
| `eks` | `eks.yaml` | The eks-log-forwarder ConfigMap: `in_eks` input → Linseed http output. fluentd's separate init container / filter stages are folded into the in_eks plugin itself. |
| `eks-log-stream-pfx` | `eks-log-stream-prefix.yaml` | `EKS_CLOUDWATCH_LOG_STREAM_PREFIX` override ≙ `additionalSources.eksCloudwatchLog.streamPrefix`. |
| — | `linseed-nch.yaml` | No direct test.sh case: fluentd rendered its :9880 http source unconditionally; fluent-bit renders it (and the `non_cluster_*` outputs) only when a NonClusterHost resource exists. |
| — | `windows.yaml` | No test.sh case (the fluentd Windows variant had a separate static config); pins the Windows daemonset config: flows/audit tails only, `C:\` paths, Linseed-only outputs. |
