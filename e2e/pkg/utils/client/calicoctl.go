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

	// The base client is used to interact with non-projectcalico.org/v3 resources.
	base client.Client
}

// Create saves the object obj in the Kubernetes cluster. obj must be a
// struct pointer so that obj can be updated with the content returned by the Server.
func (c *calicoctlExecClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if ok, err := c.isV3Request(obj); err != nil {
		return err
	} else if !ok {
		// If this is not a v3 request, use the base client to create the object, as the calicoctl exec client
		// does not support creating non-projectcalico.org/v3 resources.
		return c.base.Create(ctx, obj, opts...)
	}

	// calicoctl requires typemeta to be set for create operations, so set it here.
	kind, err := c.kindFromObject(obj)
	if err != nil {
		return err
	}
	obj.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "projectcalico.org",
		Version: "v3",
		Kind:    kind,
	})

	// Create the stdin input for the calicoctl command.
	serializer := json.NewSerializer(json.DefaultMetaFactory, c.scheme, c.scheme, false)

	w := &strings.Builder{}
	err = serializer.Encode(obj, w)
	if err != nil {
		return err
	}

	// Create a calicoctl command to create the object.
	cmd := []string{"exec", "-i", c.name, "--", "calicoctl", "create", "-f", "-"}

	logrus.WithFields(logrus.Fields{
		"data": w.String(),
	}).Info("Executing calicoctl create command")

	// Execute the command in the specified pod.
	_, err = kubectl.RunKubectlInput(c.namespace, w.String(), cmd...)
	if err != nil {
		return err
	}
	return nil
}

// Delete deletes the given obj from Kubernetes cluster.
func (c *calicoctlExecClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	// Check if the object is a v3 request, if not, use the base client to delete the object.
	if ok, err := c.isV3Request(obj); err != nil {
		return err
	} else if !ok {
		// If this is not a v3 request, use the base client to delete the object, as the calicoctl exec client
		// does not support deleting non-projectcalico.org/v3 resources.
		return c.base.Delete(ctx, obj, opts...)
	}

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
	// Check if the object is a v3 request, if not, use the base client to update the object.
	if ok, err := c.isV3Request(obj); err != nil {
		return err
	} else if !ok {
		// If this is not a v3 request, use the base client to update the object, as the calicoctl exec client
		// does not support updating non-projectcalico.org/v3 resources.
		return c.base.Update(ctx, obj, opts...)
	}

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
	// Check if the object is a v3 request, if not, use the base client to get the object.
	if ok, err := c.isV3Request(obj); err != nil {
		return err
	} else if !ok {
		// If this is not a v3 request, use the base client to get the object, as the calicoctl exec client
		// does not support getting non-projectcalico.org/v3 resources.
		return c.base.Get(ctx, key, obj, opts...)
	}

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
	// Check if the object is a v3 request, if not, use the base client to list the objects.
	if ok, err := c.isV3Request(list); err != nil {
		return err
	} else if !ok {
		// If this is not a v3 request, use the base client to list the objects, as the calicoctl exec client
		// does not support listing non-projectcalico.org/v3 resources.
		return c.base.List(ctx, list, opts...)
	}

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

func (c *calicoctlExecClient) Scheme() *runtime.Scheme {
	return c.scheme
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

func (c *calicoctlExecClient) isV3Request(obj runtime.Object) (bool, error) {
	// Use the scheme to lookup which API group this object belongs to.
	kinds, _, err := c.scheme.ObjectKinds(obj)
	if err != nil {
		return false, err
	}
	for _, kind := range kinds {
		if kind.Group == "projectcalico.org" && kind.Version == "v3" {
			return true, nil // This is a v3 request.
		}
	}
	return false, nil // Not a v3 request.
}

func (c *calicoctlExecClient) RESTMapper() meta.RESTMapper {
	return c.base.RESTMapper()
}

func (c *calicoctlExecClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return c.base.GroupVersionKindFor(obj)
}

func (c *calicoctlExecClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return c.base.IsObjectNamespaced(obj)
}

func (c *calicoctlExecClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
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
