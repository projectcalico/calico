package cni

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const DefaultServiceAccountName = "calico-node"
const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const defaultCNITokenValiditySeconds = 24 * 60 * 60
const minTokenRetryDuration = 5 * time.Second
const defaultRefreshFraction = 4

var kubeconfigPath string = "/host/etc/cni/net.d/calico-kubeconfig"

type TokenRefresher struct {
	tokenSupported bool
	tokenOnce      *sync.Once

	tokenValiditySeconds   int64
	minTokenRetryDuration  time.Duration
	defaultRefreshFraction time.Duration

	clientset *kubernetes.Clientset

	namespace          string
	serviceAccountName string

	tokenChan chan TokenUpdate
	stopChan  chan struct{}
}

type TokenUpdate struct {
	Token          string
	ExpirationTime time.Time
}

func NamespaceOfUsedServiceAccount() string {
	namespace, err := ioutil.ReadFile(serviceAccountNamespace)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read service account namespace file")
	}
	return string(namespace)
}

func BuildClientSet() (*kubernetes.Clientset, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func NewTokenRefresher(clientset *kubernetes.Clientset, namespace string, serviceAccountName string) *TokenRefresher {
	return NewTokenRefresherWithCustomTiming(clientset, namespace, serviceAccountName, defaultCNITokenValiditySeconds, minTokenRetryDuration, defaultRefreshFraction)
}

func NewTokenRefresherWithCustomTiming(clientset *kubernetes.Clientset, namespace string, serviceAccountName string, tokenValiditySeconds int64, minTokenRetryDuration time.Duration, defaultRefreshFraction time.Duration) *TokenRefresher {
	return &TokenRefresher{
		tokenSupported:         false,
		tokenOnce:              &sync.Once{},
		tokenValiditySeconds:   tokenValiditySeconds,
		minTokenRetryDuration:  minTokenRetryDuration,
		defaultRefreshFraction: defaultRefreshFraction,
		clientset:              clientset,
		namespace:              namespace,
		serviceAccountName:     serviceAccountName,
		tokenChan:              make(chan TokenUpdate),
		stopChan:               make(chan struct{}),
	}
}

func (t *TokenRefresher) UpdateToken() (TokenUpdate, error) {
	validity := t.tokenValiditySeconds
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{},
			ExpirationSeconds: &validity,
		},
	}

	tokenRequest, err := t.clientset.CoreV1().ServiceAccounts(t.namespace).CreateToken(context.TODO(), t.serviceAccountName, tr, metav1.CreateOptions{})
	if apierrors.IsNotFound(err) && !t.tokenRequestSupported(t.clientset) {
		logrus.WithError(err).Debug("Unable to create token for CNI kubeconfig as token request api is not supported, falling back to local service account token")
		return tokenUpdateFromFile()
	}
	if err != nil {
		logrus.WithError(err).Error("Unable to create token for CNI kubeconfig")
		return TokenUpdate{}, err
	}

	return TokenUpdate{
		Token:          tokenRequest.Status.Token,
		ExpirationTime: tokenRequest.Status.ExpirationTimestamp.Time,
	}, nil
}

func (t *TokenRefresher) TokenChan() <-chan TokenUpdate {
	return t.tokenChan
}

func (t *TokenRefresher) Stop() {
	close(t.stopChan)
}

func (t *TokenRefresher) Run() {
	var nextExpiration time.Time
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		tu, err := t.UpdateToken()
		if err != nil {
			logrus.WithError(err).Error("Failed to update CNI token, retrying...")
			// Reset nextExpiration to retry directly
			nextExpiration = time.Time{}
		} else {
			nextExpiration = tu.ExpirationTime
			select {
			case t.tokenChan <- tu:
			case <-t.stopChan:
				return
			}

		}
		now := time.Now()
		var sleepTime time.Duration
		// Do some basic rate limiting to prevent flooding the kube apiserver with requests
		if nextExpiration.Before(now.Add(t.minTokenRetryDuration * t.defaultRefreshFraction)) {
			sleepTime = t.minTokenRetryDuration
		} else {
			sleepTime = nextExpiration.Sub(now) / t.defaultRefreshFraction
		}
		jitter := rand.Float32() * float32(sleepTime)
		sleepTime += time.Duration(jitter)
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("Going to sleep for %s", sleepTime.String())
		}
		select {
		case <-time.After(sleepTime):
		case <-t.stopChan:
			return
		}
	}
}

func (t *TokenRefresher) tokenRequestSupported(clientset *kubernetes.Clientset) bool {
	t.tokenOnce.Do(func() {
		resources, err := clientset.Discovery().ServerResourcesForGroupVersion("v1")
		if err != nil {
			return
		}
		for _, resource := range resources.APIResources {
			if resource.Name == "serviceaccounts/token" {
				t.tokenSupported = true
				return
			}
		}
	})
	return t.tokenSupported
}

func tokenUpdateFromFile() (TokenUpdate, error) {
	tokenBytes, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		logrus.WithError(err).Error("Failed to read service account token file")
		return TokenUpdate{}, err
	}
	token := string(tokenBytes)
	tokenSegments := strings.Split(token, ".")
	if len(tokenSegments) != 3 {
		err := fmt.Errorf("invalid token segment size: %d", len(tokenSegments))
		logrus.WithError(err).Error("Failed parsing service account token")
		return TokenUpdate{}, err
	}
	unparsedClaims := tokenSegments[1]
	// Padding may be missing, hence check and append it
	if l := len(unparsedClaims) % 4; l > 0 {
		unparsedClaims += strings.Repeat("=", 4-l)
	}
	decodedClaims, err := base64.URLEncoding.DecodeString(unparsedClaims)
	if err != nil {
		logrus.WithError(err).Error("Failed to decode service account token claims")
		return TokenUpdate{}, err
	}
	var claimMap map[string]interface{}
	err = json.Unmarshal(decodedClaims, &claimMap)
	if err != nil {
		logrus.WithError(err).Error("Failed to unmarshal service account token claims")
		return TokenUpdate{}, err
	}
	return TokenUpdate{
		Token:          token,
		ExpirationTime: time.Unix(int64(claimMap["exp"].(float64)), 0),
	}, nil
}

func Run() {
	clientset, err := BuildClientSet()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create in cluster client set")
	}
	tr := NewTokenRefresher(clientset, NamespaceOfUsedServiceAccount(), DefaultServiceAccountName)
	tokenChan := tr.TokenChan()
	go tr.Run()

	for tu := range tokenChan {
		logrus.Info("Update of CNI kubeconfig triggered based on elapsed time.")
		cfg, err := rest.InClusterConfig()
		if err != nil {
			logrus.WithError(err).Error("Error generating kube config.")
			continue
		}
		err = rest.LoadTLSFiles(cfg)
		if err != nil {
			logrus.WithError(err).Error("Error loading TLS files.")
			continue
		}
		writeKubeconfig(cfg, tu.Token)
	}
}

// writeKubeconfig writes an updated kubeconfig file to disk that the CNI plugin can use to access the Kubernetes API.
func writeKubeconfig(cfg *rest.Config, token string) {
	template := `# Kubeconfig file for Calico CNI plugin. Installed by calico/node.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: %s
    certificate-authority-data: "%s"
users:
- name: calico
  user:
    token: %s
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico
current-context: calico-context`

	// Replace the placeholders.
	data := fmt.Sprintf(template, cfg.Host, base64.StdEncoding.EncodeToString(cfg.CAData), token)

	// Write the filled out config to disk.
	if err := ioutil.WriteFile(kubeconfigPath, []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return
	}
	logrus.WithField("path", kubeconfigPath).Info("Wrote updated CNI kubeconfig file.")
}
