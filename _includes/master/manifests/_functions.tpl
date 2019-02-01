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

{{/*

Resolves the correct tag for a given image. The input should
be the name of the component as it appears in versions.yml.
In order to function, user must pass in versions.yml, _config.yml,
and a value "page.version" which instructs helm which set of images to use.
e.g. "-f _config.yml -f _data/versions.yml --set page.version=v3.3"

usage: |
  {{ tuple "calico/cni" . | include "tag" }}
return: |
  v3.3.2
*/}}
{{- define "tag" -}}
{{- /* unpack the passed in args */ -}}
{{- $component := index . 0 -}}
{{- $ctx := index . 1 -}}

{{- /* The remaining lines parse versions.yml to get the tag for the "component" for the given "page.version". */ -}}
{{- /* First, grab the latest revision release from versions.yml for the given "page.version"  */ -}}
{{- $release := index $ctx.Values $ctx.Values.page.version | first -}}

{{- /* get the specified component  */ -}}
{{- $component := index $release.components $component -}}

{{- /* get the 'version' of that component */ -}}
{{- $component.version -}}
{{- end -}}
