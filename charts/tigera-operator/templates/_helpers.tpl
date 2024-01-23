{{/* generate the image name for a component*/}}
{{- define "tigera-operator.image" -}}
{{- if .registry -}}
    {{- .registry | trimSuffix "/" -}}/
{{- end -}}
{{- .image -}}:{{- .version -}}
{{- end -}}

{{/*
generate imagePullSecrets for installation and deployments
by combining installation.imagePullSecrets with toplevel imagePullSecrets.
*/}}

{{- define "tigera-operator.imagePullSecrets" -}}
{{- $secrets := default list .Values.installation.imagePullSecrets -}}
{{- range $key, $val := .Values.imagePullSecrets -}}
  {{- $secrets = append $secrets (dict "name" $key) -}}
{{- end -}}
{{ $secrets | toYaml }}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "tigera-operator.labels" -}}
k8s-app: tigera-operator
{{- with .context.Values.additionalLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}