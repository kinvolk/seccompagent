package k8s

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
}

func NewK8sClient(nodeName string) (*K8sClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
	}, nil
}

func (k *K8sClient) ContainerLookup(pid int) (*v1.Pod, error) {
	cgroupPathV1, cgroupPathV2, err := getCgroupPaths(pid)

	pods, err := k.clientset.CoreV1().Pods("").List(metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	// Unfortunately, we cannot check pod.Status.ContainerStatuses because
	// it might not be set yet at this stage. We try to match the pod uid
	// with the cgroup instead.

	for _, pod := range pods.Items {
		uid := string(pod.ObjectMeta.UID)
		// check if this container is associated to this pod
		uidWithUnderscores := strings.ReplaceAll(uid, "-", "_")

		if !strings.Contains(cgroupPathV2, uidWithUnderscores) &&
			!strings.Contains(cgroupPathV2, uid) &&
			!strings.Contains(cgroupPathV1, uidWithUnderscores) &&
			!strings.Contains(cgroupPathV1, uid) {
			continue
		}

		log.WithFields(log.Fields{
			"pid":          pid,
			"cgroupPathV1": cgroupPathV1,
			"cgroupPathV2": cgroupPathV2,
			"namespace":    pod.ObjectMeta.Namespace,
			"pod":          pod.ObjectMeta.Name,
		}).Trace("Found pod from pid")

		return &pod, nil
	}
	return nil, errors.New("Container ID not found")
}

// getCgroupPaths returns the cgroup1 and cgroup2 paths of a process.
// It does not include the "/sys/fs/cgroup/{unified,systemd,}" prefix.
func getCgroupPaths(pid int) (string, string, error) {
	cgroupPathV1 := ""
	cgroupPathV2 := ""
	if cgroupFile, err := os.Open(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")); err == nil {
		defer cgroupFile.Close()
		reader := bufio.NewReader(cgroupFile)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "1:name=systemd:") {
				cgroupPathV1 = strings.TrimPrefix(line, "1:name=systemd:")
				cgroupPathV1 = strings.TrimSuffix(cgroupPathV1, "\n")
				continue
			}
			if strings.HasPrefix(line, "0::") {
				cgroupPathV2 = strings.TrimPrefix(line, "0::")
				cgroupPathV2 = strings.TrimSuffix(cgroupPathV2, "\n")
				continue
			}
		}
	} else {
		return "", "", fmt.Errorf("cannot parse cgroup: %v", err)
	}

	if cgroupPathV1 == "/" {
		cgroupPathV1 = ""
	}

	if cgroupPathV2 == "/" {
		cgroupPathV2 = ""
	}

	if cgroupPathV2 == "" && cgroupPathV1 == "" {
		return "", "", fmt.Errorf("cannot find cgroup path in /proc/PID/cgroup")
	}

	return cgroupPathV1, cgroupPathV2, nil
}
