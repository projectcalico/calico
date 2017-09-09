package converter_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/k8s-policy/pkg/converter"
	"github.com/projectcalico/libcalico-go/lib/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sapi "k8s.io/client-go/pkg/api/v1"
)

var _ = Describe("NamespaceConverter", func() {
	nsConverter := converter.NewNamespaceConverter()
	Context("should parse a Namespace to a Profile", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo.org/bar": "baz",
					"roger":       "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := nsConverter.Convert(&ns)
		It("should not generate a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "k8s_ns.default"
		actualName := p.(api.Profile).Metadata.Name
		It("should return calico profile with expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		// Ensure rules are correct for profile.
		inboundRules := p.(api.Profile).Spec.IngressRules
		outboundRules := p.(api.Profile).Spec.EgressRules
		It("should return calico profile with single rules", func() {
			Expect(len(inboundRules)).To(Equal(1))
			Expect(len(outboundRules)).To(Equal(1))
		})

		// Ensure both inbound and outbound rules are set to allow.
		It("should return calico profile with rules set to allow", func() {
			Expect(inboundRules[0]).To(Equal(api.Rule{Action: "allow"}))
			Expect(outboundRules[0]).To(Equal(api.Rule{Action: "allow"}))
		})

		// Check labels.
		labels := p.(api.Profile).Metadata.Labels
		It("should return calico profile with correct labels", func() {
			Expect(labels["pcns.foo.org/bar"]).To(Equal("baz"))
			Expect(labels["pcns.roger"]).To(Equal("rabbit"))
		})
	})

	Context("should parse a Namespace to a Profile with no labels", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "default",
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}
		p, err := nsConverter.Convert(&ns)
		It("should not generate a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Ensure correct profile name
		expectedName := "k8s_ns.default"
		actualName := p.(api.Profile).Metadata.Name
		It("should return calico profile with expected name", func() {
			Expect(actualName).Should(Equal(expectedName))
		})

		// Ensure rules are correct for profile.
		inboundRules := p.(api.Profile).Spec.IngressRules
		outboundRules := p.(api.Profile).Spec.EgressRules
		It("should return calico profile with single rules", func() {
			Expect(len(inboundRules)).To(Equal(1))
			Expect(len(outboundRules)).To(Equal(1))
		})

		// Ensure both inbound and outbound rules are set to allow.
		It("should return calico profile with rules set to allow", func() {
			Expect(inboundRules[0]).To(Equal(api.Rule{Action: "allow"}))
			Expect(outboundRules[0]).To(Equal(api.Rule{Action: "allow"}))
		})

		// Check labels.
		labels := p.(api.Profile).Metadata.Labels
		It("should return calico profile with no labels", func() {
			Expect(len(labels)).To(Equal(0))
		})
	})

	Context("GetKey should return the right key", func() {
		profileName := "k8s_ns.default"
		profile := api.Profile{
			Metadata: api.ProfileMetadata{
				Name: profileName,
			},
			Spec: api.ProfileSpec{},
		}

		// Get key of profile
		key := nsConverter.GetKey(profile)
		It("should return name as key", func() {
			Expect(key).To(Equal(profileName))
		})
	})
})
