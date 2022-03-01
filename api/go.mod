module github.com/projectcalico/api

go 1.16

require (
	github.com/emicklei/go-restful v2.11.2-0.20200112161605-a7c079c43d51+incompatible // indirect
	github.com/go-openapi/jsonreference v0.19.4-0.20191224164422-1f9748e5f45e // indirect
	github.com/go-openapi/swag v0.19.7 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/mailru/easyjson v0.7.0 // indirect
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.1
	k8s.io/api v0.23.2
	k8s.io/apimachinery v0.23.2
	k8s.io/client-go v0.23.2
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
)

replace (
	k8s.io/api => k8s.io/api v0.23.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.23.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.23.2
	k8s.io/apiserver => k8s.io/apiserver v0.23.2
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.23.2
	k8s.io/client-go => k8s.io/client-go v0.23.2
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.23.2
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.23.2
	k8s.io/code-generator => k8s.io/code-generator v0.23.2
	k8s.io/component-base => k8s.io/component-base v0.23.2
	k8s.io/component-helpers => k8s.io/component-helpers v0.23.2
	k8s.io/controller-manager => k8s.io/controller-manager v0.23.2
	k8s.io/cri-api => k8s.io/cri-api v0.23.2
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.23.2
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.23.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.23.2
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20220114203427-a0453230fd26
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.23.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.23.2
	k8s.io/kubectl => k8s.io/kubectl v0.23.2
	k8s.io/kubelet => k8s.io/kubelet v0.23.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.23.2
	k8s.io/metrics => k8s.io/metrics v0.23.2
	k8s.io/mount-utils => k8s.io/mount-utils v0.23.2
	k8s.io/node-api => k8s.io/node-api v0.23.2
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.23.2
)
