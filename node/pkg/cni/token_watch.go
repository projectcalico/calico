package cni

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
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

	// coalesceWindow is how long the file notifier waits for activity to
	// stop before emitting one coalesced "directory changed" event.
	coalesceWindow = 50 * time.Millisecond
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
	// that this TokenRefresher uses.
	tokenFilePath string

	// notifier delivers a coalesced "token directory changed" signal so the
	// refresh loop can wake up promptly on a rotation. Tests assign a fake;
	// if nil at Run time, a default fsnotify-backed one is created.
	notifier FileNotifier

	tokenChan chan TokenUpdate
	stopChan  chan struct{}
	stopOnce  sync.Once
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
	t := &TokenRefresher{
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
	return t
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

// Stop signals Run to exit. Idempotent (sync.Once), so a second call
// is safe and won't panic on close-of-closed-channel.
func (t *TokenRefresher) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopChan)
	})
}

func (t *TokenRefresher) Run() {
	// Wake up immediately when kubelet rotates our projected SA token,
	// without waiting for the next timer tick (up to ~12 h with default
	// settings). Particularly relevant on signing-key rotation, which
	// invalidates every previously-issued token while their exp claim is
	// still in the future.
	if t.notifier == nil {
		n, err := NewFsnotifyFileNotifier(filepath.Dir(t.tokenFilePath))
		if err != nil {
			logrus.WithError(err).Warn("Failed to set up CNI token directory watcher; refresh will rely on timer only")
			t.notifier = noopFileNotifier{}
		} else {
			t.notifier = n
		}
	}
	defer t.notifier.Close()
	rotated := t.notifier.Events()

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
		case _, ok := <-rotated:
			if !timer.Stop() {
				<-timer.C
			}
			if !ok {
				logrus.Warn("Token directory watcher channel closed unexpectedly; falling back to timer-only refresh")
				rotated = nil
			} else {
				logrus.Info("Projected service account token changed; refreshing CNI kubeconfig immediately")
			}
		case <-t.stopChan:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

// FileNotifier delivers a coalesced "watched directory changed" signal:
// one channel send per logical change, regardless of how many raw
// filesystem events the OS produced (kubelet's atomic-writer fires ~5
// per rotation).
type FileNotifier interface {
	// Events returns a receive-only channel. A nil channel means the
	// notifier is inert (e.g. unsupported platform); callers should
	// rely on their timer.
	Events() <-chan struct{}
	// Close releases resources. Idempotent.
	Close()
}

// NewFsnotifyFileNotifier watches dir with fsnotify and emits one event per
// coalesceWindow of activity. Windows projected-SA volumes don't follow the
// kubelet atomic-writer pattern, so we return a no-op notifier there and
// consumers fall back to their timer.
func NewFsnotifyFileNotifier(dir string) (FileNotifier, error) {
	if runtime.GOOS == "windows" {
		logrus.Info("fsnotify-based CNI token fast path is disabled on Windows; refresh will rely on timer only")
		return noopFileNotifier{}, nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("add %q to fsnotify watcher: %w", dir, err)
	}
	logrus.WithField("dir", dir).Info("Watching service account token directory for rotation")
	n := &fsnotifyFileNotifier{
		dir:     dir,
		watcher: watcher,
		events:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go n.run()
	return n, nil
}

type fsnotifyFileNotifier struct {
	dir       string
	watcher   *fsnotify.Watcher
	events    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (n *fsnotifyFileNotifier) Events() <-chan struct{} { return n.events }

func (n *fsnotifyFileNotifier) Close() {
	n.closeOnce.Do(func() {
		close(n.done)
		_ = n.watcher.Close()
	})
}

// run waits for the watcher to fall silent for coalesceWindow before
// emitting a single "directory changed" event, so cluster-wide SA
// signing-key rotation doesn't multiply at kube-apiserver.
func (n *fsnotifyFileNotifier) run() {
	defer close(n.events)
	// settle is non-nil only while inside a coalesce window.
	var settle *time.Timer
	settleC := func() <-chan time.Time {
		if settle == nil {
			return nil
		}
		return settle.C
	}
	for {
		select {
		case <-n.done:
			return
		case _, ok := <-n.watcher.Events:
			if !ok {
				return
			}
			// First event of a burst: arm the timer.
			// Subsequent events: slide the window forward.
			if settle == nil {
				settle = time.NewTimer(coalesceWindow)
			} else {
				if !settle.Stop() {
					<-settle.C
				}
				settle.Reset(coalesceWindow)
			}
		case err, ok := <-n.watcher.Errors:
			// fsnotify requires both channels to be drained; leaving
			// Errors unread can block the watcher's internal goroutine.
			if !ok {
				return
			}
			logrus.WithError(err).WithField("dir", n.dir).Warn("fsnotify error on service account token directory")
		case <-settleC():
			// Burst is over; emit one coalesced event. If the previous
			// send is still pending, drop this one (the consumer will
			// see the latest state on its next read).
			select {
			case n.events <- struct{}{}:
			default:
			}
			settle = nil
		}
	}
}

// noopFileNotifier is used when directory watching isn't viable (e.g.
// Windows projected-SA volumes) or when fsnotify setup fails.
type noopFileNotifier struct{}

func (noopFileNotifier) Events() <-chan struct{} { return nil }
func (noopFileNotifier) Close()                  {}

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
	return parseTokenUpdate(tokenBytes)
}

// parseTokenUpdate decodes a JWT-formatted service account token into a
// TokenUpdate and returns an error if it is invalid or doesn't meet our
// requirements.
func parseTokenUpdate(tokenBytes []byte) (TokenUpdate, error) {
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
	if err := json.Unmarshal(decodedClaims, &claimMap); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal service account token claims")
		return TokenUpdate{}, err
	}
	expRaw, ok := claimMap["exp"]
	if !ok {
		err := fmt.Errorf("token claims are missing 'exp'")
		logrus.WithError(err).Error("Service account token has no expiration claim")
		return TokenUpdate{}, err
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		err := fmt.Errorf("token claims 'exp' has unexpected type %T", expRaw)
		logrus.WithError(err).Error("Service account token expiration claim is not a number")
		return TokenUpdate{}, err
	}
	return TokenUpdate{
		Token:          token,
		ExpirationTime: time.Unix(int64(expFloat), 0),
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

	// Write the filled out config to disk.
	if err := os.WriteFile(winutils.GetHostPath(kubeconfigPath), []byte(data), 0600); err != nil {
		logrus.WithError(err).Error("Failed to write CNI plugin kubeconfig file")
		return
	}
	logrus.WithField("path", winutils.GetHostPath(kubeconfigPath)).Info("Wrote updated CNI kubeconfig file.")
}
