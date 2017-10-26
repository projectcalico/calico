package server

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	spireauth "github.com/spiffe/spire/pkg/agent/auth"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getCallerInfo(ctx context.Context) (pid int32, err error) {
	info, ok := spireauth.CallerFromContext(ctx)
	if ok == false {
		return 0, errors.New("Not able to get caller pid")
	}
	log.Debugf("Caller context is %v", info)
	return info.PID, nil
}

// Given the gRPC context, return the corresponding workload labels for the client.
func (as *auth_server) getLabelsFromContext(ctx context.Context) (map[string]string, error) {
	// Resolve the caller info
	pid, err := getCallerInfo(ctx)
	if err != nil {
		return nil, err
	}
	cid, err := getContainerId("/host", pid)
	if err != nil {
		return nil, err
	}
	wep, err := getPodLabels(as.kubeClient, cid, as.NodeName)
	if err != nil {
		return nil, err
	}
	return wep, nil
}

func getContainerId(pathPrefix string, pid int32) (cid string, err error) {
	path := pathPrefix + "/proc/" + strconv.Itoa(int(pid)) + "/cgroup"
	re := regexp.MustCompile("^1:name")
	file, err := os.Open(path)
	if err != nil {
		errS := "Not able to open proc file " + path + " (" + err.Error() + ")"
		return "", errors.New(errS)
	}
	defer file.Close()

	var rstr string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rstr = scanner.Text()
		r := re.FindString(rstr)
		if r != "" {
			break
		}
	}
	if rstr == "" {
		return "", errors.New("Not able to find the container id")
	}

	vals := strings.Split(rstr, "/")
	if vals[0] == rstr {
		log.Errorf("%v", vals)
		return "", errors.New("The cgroups does not contain CID")
	}

	return vals[len(vals)-1], nil
}

func getPodLabels(cset *kubernetes.Clientset, cid string, nodeName string) (map[string]string, error) {
	qStr := "spec.nodeName=" + nodeName
	opts := metav1.ListOptions{}
	opts.FieldSelector = qStr
	pods, err := cset.CoreV1().Pods("").List(opts)
	if err != nil {
		return nil, err
	}
	log.Debugf("Number of pods on %v %v", qStr, len(pods.Items))

	matchCid := "docker://" + cid
	for _, pod := range pods.Items {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.ContainerID == matchCid {
				return pod.GetLabels(), nil
			}
		}
	}
	return nil, errors.New("Unable to find pod.")
}
