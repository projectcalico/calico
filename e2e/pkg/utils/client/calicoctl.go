package client

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ client.Client = &calicoctlExecClient{}

// calicoctlExecClient client that meets the controller-runtime client.Client interface but implements it using exec commands into a calicoctl pod.
// This allows us to run tests that interact with Calico's projectcalico.org/v3 API without needing to run Calico's API server directly.
type calicoctlExecClient struct {
	// The pod to exec into.
	namespace string
	name      string

	// The scheme is used to encode and decode objects correctly.
	scheme *runtime.Scheme
}

// Create saves the object obj in the Kubernetes cluster. obj must be a
// struct pointer so that obj can be updated with the content returned by the Server.
func (c *calicoctlExecClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	// Create the stdin input for the calicoctl command.
	serializer := json.NewSerializer(json.DefaultMetaFactory, c.scheme, c.scheme, false)

	w := &strings.Builder{}
	serializer.Encode(obj, w)

	// Create a calicoctl command to create the object.
	cmd := []string{"exec", "-i", c.name, "--", "calicoctl", "create", "-f", "-"}

	// Execute the command in the specified pod.
	_, err := kubectl.RunKubectlInput(c.namespace, w.String(), cmd...)
	if err != nil {
		return err
	}
	return nil
}

// Delete deletes the given obj from Kubernetes cluster.
func (c *calicoctlExecClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	kind, err := c.kindFromObject(obj)
	if err != nil {
		return err
	}

	// Create a calicoctl command to delete the object.
	cmd := []string{"exec", c.name, "--", "calicoctl", "delete", kind, obj.GetName()}
	if obj.GetNamespace() != "" {
		cmd = append(cmd, "--namespace="+obj.GetNamespace())
	}

	// Execute the command in the specified pod.
	out, err := kubectl.RunKubectl(c.namespace, cmd...)
	logrus.WithFields(logrus.Fields{"output": out}).Info("calicoctl delete output")
	return err
}

// Update updates the given obj in the Kubernetes cluster. obj must be a
// struct pointer so that obj can be updated with the content returned by the Server.
func (c *calicoctlExecClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	// Create the stdin input for the calicoctl command.
	serializer := json.NewSerializer(json.DefaultMetaFactory, c.scheme, c.scheme, false)

	w := &strings.Builder{}
	if err := serializer.Encode(obj, w); err != nil {
		return err
	}

	// Create a calicoctl command to update the object.
	cmd := []string{"exec", "-i", c.name, "--", "calicoctl", "apply", "-f", "-"}

	// Execute the command in the specified pod.
	_, err := kubectl.RunKubectlInput(c.namespace, w.String(), cmd...)
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves an obj for the given object key from the Kubernetes Cluster.
// obj must be a struct pointer so that obj can be updated with the response
// returned by the Server.
func (c *calicoctlExecClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	kind, err := c.kindFromObject(obj)
	if err != nil {
		return err
	}

	// Create a calicoctl command to get the object.
	cmd := []string{"exec", c.name, "--", "calicoctl", "get", kind, key.Name}
	if key.Namespace != "" {
		cmd = append(cmd, "--namespace="+key.Namespace)
	}
	cmd = append(cmd, "-o", "yaml")

	// Execute the command in the specified pod.
	out, err := kubectl.RunKubectl(c.namespace, cmd...)
	logrus.WithFields(logrus.Fields{"output": out}).Debug("calicoctl get output")
	if err != nil {
		return err
	}

	f := serializer.NewCodecFactory(c.scheme)
	if err := runtime.DecodeInto(f.UniversalDecoder(), []byte(out), obj); err != nil {
		logrus.WithError(err).Error("failed to decode calicoctl get output")
		return err
	}
	return nil
}

// List retrieves list of objects for a given namespace and list options. On a
// successful call, Items field in the list will be populated with the
// result returned from the server.
func (c *calicoctlExecClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	kind, err := c.kindFromObject(list)
	if err != nil {
		return err
	}
	out, err := kubectl.RunKubectl(c.namespace, "exec", c.name, "--", "calicoctl", "get", kind, "-o", "yaml")
	logrus.WithFields(logrus.Fields{"output": out}).Debug("calicoctl list output")
	if err != nil {
		return err
	}

	f := serializer.NewCodecFactory(c.scheme)
	if err := runtime.DecodeInto(f.UniversalDecoder(), []byte(out), list); err != nil {
		logrus.WithError(err).Error("failed to decode calicoctl list output")
		return err
	}
	return nil
}

func (c *calicoctlExecClient) kindFromObject(obj runtime.Object) (string, error) {
	// Get the kind of the object from the scheme.
	kinds, _, err := c.scheme.ObjectKinds(obj)
	if err != nil {
		return "", err
	}
	if len(kinds) == 0 {
		return "", nil // No kind found, return empty string.
	}

	// If the kind is a list, return the kind without "List" suffix.
	return strings.TrimSuffix(kinds[0].Kind, "List"), nil
}

// The following methods are not implemented in this client,

func (c *calicoctlExecClient) Scheme() *runtime.Scheme {
	panic("not implemented")
}

func (c *calicoctlExecClient) RESTMapper() meta.RESTMapper {
	panic("not implemented")
}

func (c *calicoctlExecClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	panic("not implemented")
}

func (c *calicoctlExecClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	panic("not implemented")
}

func (c *calicoctlExecClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	panic("not implemented")
}

func (c *calicoctlExecClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	panic("not implemented")
}

func (c *calicoctlExecClient) SubResource(subResource string) client.SubResourceClient {
	panic("not implemented")
}

func (c *calicoctlExecClient) Status() client.SubResourceWriter {
	panic("not implemented")
}
