package cni

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

const (
	defaultServiceAccountName      = "calico-cni-plugin"
	serviceAccountNamespace        = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	tokenFile                      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCNITokenValiditySeconds = 24 * 60 * 60
	minTokenRetryDuration          = 5 * time.Second
	defaultRefreshFraction         = 4
	kubeconfigPath                 = "/host/etc/cni/net.d/calico-kubeconfig"
)

type TokenRefresher struct {
	tokenSupported bool
	tokenOnce      *sync.Once

	tokenValiditySeconds   int64
	minTokenRetryDuration  time.Duration
	defaultRefreshFraction time.Duration

	clientset kubernetes.Interface

	namespace          string
	serviceAccountName string

	// tokenFilePath is the path to the in-pod projected service account token
	// that this TokenRefresher uses (via the in-cluster client) to authenticate
	// to the API server. The directory containing this file is watched with
	// fsnotify so that the refresh loop wakes up immediately when kubelet
	// rotates the projected token — otherwise an externally-invalidated CNI
	// kubeconfig token can sit on disk for up to 12 hours before we notice.
	// Overridable for tests.
	tokenFilePath string

	tokenChan chan TokenUpdate
	stopChan  chan struct{}
}

type TokenUpdate struct {
	Token          string
	ExpirationTime time.Time
}

func NamespaceOfUsedServiceAccount() string {
	namespace, err := os.ReadFile(winutils.GetHostPath(serviceAccountNamespace))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to read service account namespace file")
	}
	return string(namespace)
}

func BuildClientSet() (kubernetes.Interface, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	cfg, err := winutils.BuildConfigFromFlags("", kubeconfig)
	logrus.WithFields(logrus.Fields{"KUBECONFIG": kubeconfig, "cfg": cfg}).Debug("running cni.BuildClientSet")
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func NewTokenRefresher(clientset kubernetes.Interface, namespace string, serviceAccountName string) *TokenRefresher {
	return NewTokenRefresherWithCustomTiming(clientset, namespace, serviceAccountName, defaultCNITokenValiditySeconds, minTokenRetryDuration, defaultRefreshFraction)
}

func NewTokenRefresherWithCustomTiming(clientset kubernetes.Interface, namespace string, serviceAccountName string, tokenValiditySeconds int64, minTokenRetryDuration time.Duration, defaultRefreshFraction time.Duration) *TokenRefresher {
	return &TokenRefresher{
		tokenSupported:         false,
		tokenOnce:              &sync.Once{},
		tokenValiditySeconds:   tokenValiditySeconds,
		minTokenRetryDuration:  minTokenRetryDuration,
		defaultRefreshFraction: defaultRefreshFraction,
		clientset:              clientset,
		namespace:              namespace,
		serviceAccountName:     serviceAccountName,
		tokenFilePath:          winutils.GetHostPath(tokenFile),
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
	// Watch the directory containing our own projected service account token
	// so that we wake up as soon as kubelet rotates it. Two common cases make
	// this important: (a) a signing-key rotation invalidates every
	// previously-issued token while the exp claim is still in the future, so
	// the timer alone wouldn't notice until the next scheduled refresh (up to
	// ~12 hours later); (b) kubelet may re-project the token faster than our
	// refresh cadence, and picking up the new token promptly keeps the CNI
	// kubeconfig as fresh as possible.
	tokenRotated, cleanupWatcher := t.startTokenFileWatcher()
	defer cleanupWatcher()

	var nextExpiration time.Time
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
		// Do some basic rate limiting to prevent flooding the kube apiserver with requests
		sleepTime := t.getSleepTime(&nextExpiration)
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.Debugf("Going to sleep for %s", sleepTime.String())
		}
		timer := time.NewTimer(sleepTime)
		select {
		case <-timer.C:
		case ev, ok := <-tokenRotated:
			if !timer.Stop() {
				<-timer.C
			}
			if !ok {
				// Watcher was closed — fall back to timer-only behaviour.
				tokenRotated = nil
			} else {
				logrus.WithField("event", ev.String()).Info("Projected service account token changed; refreshing CNI kubeconfig immediately")
				// Drain any additional events the watcher may have queued so
				// we don't thrash on a burst of rotations in quick succession.
				drainEvents(tokenRotated)
			}
		case <-t.stopChan:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

// startTokenFileWatcher sets up an fsnotify watcher on the directory
// containing the projected service account token. It returns a receive-only
// events channel and a cleanup func. On any error it logs and returns a nil
// channel plus a no-op cleanup so the caller can fall back to timer-only
// behaviour — this preserves the original semantics on platforms where
// fsnotify isn't supported.
func (t *TokenRefresher) startTokenFileWatcher() (<-chan fsnotify.Event, func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.WithError(err).Warn("Failed to create fsnotify watcher; CNI token refresh will rely on timer only")
		return nil, func() {}
	}
	dir := filepath.Dir(t.tokenFilePath)
	if err := watcher.Add(dir); err != nil {
		logrus.WithError(err).WithField("dir", dir).Warn("Failed to watch service account token directory; CNI token refresh will rely on timer only")
		_ = watcher.Close()
		return nil, func() {}
	}

	// fsnotify requires both Events and Errors channels to be drained.
	// Leaving Errors unread can block the watcher's internal goroutine and
	// stop further events from being delivered. Spawn a drainer that exits
	// naturally when the watcher is closed — the Errors channel closes too.
	errorsDone := make(chan struct{})
	go func() {
		defer close(errorsDone)
		for err := range watcher.Errors {
			logrus.WithError(err).WithField("dir", dir).Warn("fsnotify error on service account token directory")
		}
	}()

	logrus.WithField("dir", dir).Info("Watching service account token directory for rotation")
	cleanup := func() {
		_ = watcher.Close()
		<-errorsDone
	}
	return watcher.Events, cleanup
}

// drainEvents non-blockingly drains any events queued on ch.
func drainEvents(ch <-chan fsnotify.Event) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func (t *TokenRefresher) getSleepTime(nextExpiration *time.Time) time.Duration {
	now := time.Now()
	sleepTime := nextExpiration.Sub(now) / t.defaultRefreshFraction
	const cniTokenRefreshIntervalName = "CNI_TOKEN_REFRESH_INTERVAL"
	cniTokenRefreshInterval := os.Getenv(cniTokenRefreshIntervalName)
	if cniTokenRefreshInterval != "" {
		duration, err := time.ParseDuration(cniTokenRefreshInterval)
		if err == nil {
			logrus.WithField("interval", duration).Debugf("Detected a valid %s", cniTokenRefreshIntervalName)
			sleepTime = duration
		} else {
			logrus.WithError(err).WithField(cniTokenRefreshIntervalName, cniTokenRefreshInterval).Errorf("Detected an invalid %s.", cniTokenRefreshIntervalName)
		}
	}
	if nextExpiration.Before(now.Add(t.minTokenRetryDuration * t.defaultRefreshFraction)) {
		sleepTime = t.minTokenRetryDuration
	}
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	jitter := rand.Float32() * float32(sleepTime)
	sleepTime += time.Duration(jitter)
	return sleepTime
}

func (t *TokenRefresher) tokenRequestSupported(clientset kubernetes.Interface) bool {
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
	tokenBytes, err := os.ReadFile(winutils.GetHostPath(tokenFile))
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
	var claimMap map[string]any
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

// RunWithContext is the context-aware variant of Run for use when running
// as a goroutine in a consolidated process.
func RunWithContext(ctx context.Context) error {
	clientset, err := BuildClientSet()
	if err != nil {
		return fmt.Errorf("failed to create in-cluster client set: %w", err)
	}

	namespace, err := readNamespace()
	if err != nil {
		return fmt.Errorf("failed to read service account namespace: %w", err)
	}

	tr := NewTokenRefresher(clientset, namespace, CNIServiceAccountName())
	tokenChan := tr.TokenChan()
	go tr.Run()

	// Stop the refresher when the context is cancelled.
	go func() {
		<-ctx.Done()
		tr.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case tu, ok := <-tokenChan:
			if !ok {
				return nil
			}
			logrus.Info("Update of CNI kubeconfig triggered based on elapsed time.")
			kubeconfig := os.Getenv("KUBECONFIG")
			cfg, err := winutils.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				logrus.WithError(err).Error("Error generating kube config.")
				continue
			}
			if err = rest.LoadTLSFiles(cfg); err != nil {
				logrus.WithError(err).Error("Error loading TLS files.")
				continue
			}
			writeKubeconfig(cfg, tu.Token)
		}
	}
}

// readNamespace reads the service account namespace from the mounted secret.
func readNamespace() (string, error) {
	namespace, err := os.ReadFile(winutils.GetHostPath(serviceAccountNamespace))
	if err != nil {
		return "", err
	}
	return string(namespace), nil
}

// CNIServiceAccountName returns the name of the serviceaccount to use for the CNI plugin token request.
// This can be set via the CALICO_CNI_SERVICE_ACCOUNT environment variable, and defaults to "calico-cni-plugin" (on Linux, "calico-cni-plugin-windows" on Windows) otherwise.
func CNIServiceAccountName() string {
	if sa := os.Getenv("CALICO_CNI_SERVICE_ACCOUNT"); sa != "" {
		logrus.WithField("name", sa).Debug("Using service account from CALICO_CNI_SERVICE_ACCOUNT")
		return sa
	}
	return defaultServiceAccountName
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

	path := winutils.GetHostPath(kubeconfigPath)
	if err := writeFileAtomic(path, []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return
	}
	logrus.WithField("path", path).Info("Wrote updated CNI kubeconfig file.")
}

// writeFileAtomic writes data to path by first writing to a temporary file in
// the same directory, fsyncing, and then renaming into place. On POSIX this
// guarantees a concurrent reader — in particular the CNI plugin invoked by
// containerd between refreshes — sees either the old complete contents or the
// new complete contents, never a partially written or zero-length file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	committed = true
	return nil
}
