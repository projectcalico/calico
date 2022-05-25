{{- define "nodeName" -}}
{{- if and (eq .Values.network "flannel") (eq .Values.datastore "etcd") -}}
canal-node
{{- else if eq .Values.network "flannel" -}}
canal
{{- else -}}
calico-node
{{- end -}}
{{- end -}}


{{- define "variant_name" -}}
{{- if eq .Values.network "flannel" -}}
Canal
{{- else -}}
Calico
{{- end -}}
{{- end -}}

{{- define "calico.etcd.tls" -}}
{{- if or (or .Values.etcd.tls.crt .Values.etcd.tls.ca) .Values.etcd.tls.key -}}
{{- $_ := required "Must specify all or none of etcd_crt, etcd_ca, etcd_key" .Values.etcd.tls.crt -}}
{{- $_ := required "Must specify all or none of etcd_crt, etcd_ca, etcd_key" .Values.etcd.tls.ca -}}
{{- $_ := required "Must specify all or none of etcd_crt, etcd_ca, etcd_key" .Values.etcd.tls.key -}}
true
{{- end -}}
{{- end -}}
