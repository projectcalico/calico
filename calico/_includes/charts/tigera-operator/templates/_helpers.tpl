{{/* generate the image name for a component*/}}
{{- define "tigera-operator.image" -}}
{{- if .registry -}}
    {{- .registry | trimSuffix "/" -}}/
{{- end -}}
{{- .image -}}:{{- .version -}}
{{- end -}}
