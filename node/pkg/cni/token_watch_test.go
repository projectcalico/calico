package cni_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/node/pkg/cni"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var _ = Describe("FV tests", func() {
	const serviceAccountName = "cni-token-watch-test"
	const namespace = metav1.NamespaceSystem

	It("should create a token successfully", func() {
		clientset := createKubernetesClient()
		setupServiceAccount(clientset, serviceAccountName, namespace)
		defer cleanupServiceAccount(clientset, serviceAccountName, namespace)

		tr := cni.NewTokenRefresher(clientset, namespace, serviceAccountName)
		tu, err := tr.UpdateToken()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tu.Token).NotTo(BeEmpty())
	})

	It("should create a token successfully and deliver it through the channel", func() {
		clientset := createKubernetesClient()
		setupServiceAccount(clientset, serviceAccountName, namespace)
		defer cleanupServiceAccount(clientset, serviceAccountName, namespace)

		tr := cni.NewTokenRefresher(clientset, namespace, serviceAccountName)
		tokenChan := tr.TokenChan()
		go tr.Run()
		tu := <-tokenChan
		Expect(tu.Token).NotTo(BeEmpty())
	})

	It("should create multiple tokens successfully and deliver them through the channel", func() {
		const iterations = 5
		// kube-apiserver does not allow smaller validity periods than 10 minutes
		const tokenValiditySeconds = 600

		clientset := createKubernetesClient()
		setupServiceAccount(clientset, serviceAccountName, namespace)
		defer cleanupServiceAccount(clientset, serviceAccountName, namespace)

		tr := cni.NewTokenRefresherWithCustomTiming(clientset, namespace, serviceAccountName, tokenValiditySeconds, 1*time.Nanosecond, 600000)
		tokenChan := tr.TokenChan()
		go tr.Run()
		for i := 0; i < iterations; i++ {
			tu := <-tokenChan
			Expect(tu.Token).NotTo(BeEmpty())
		}
	})
})

func createKubernetesClient() *kubernetes.Clientset {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	kubeconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create kubernetes config: %v", err))
	}
	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		Fail(fmt.Sprintf("Could not create kubernetes client: %v", err))
	}
	return clientset
}

func setupServiceAccount(clientset *kubernetes.Clientset, name string, namespace string) {
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_, err := clientset.CoreV1().ServiceAccounts(namespace).Create(context.Background(), serviceAccount, metav1.CreateOptions{})
	Expect(err).ShouldNot(HaveOccurred())
}

func cleanupServiceAccount(clientset *kubernetes.Clientset, name string, namespace string) {
	err := clientset.CoreV1().ServiceAccounts(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	Expect(err).ShouldNot(HaveOccurred())
}
