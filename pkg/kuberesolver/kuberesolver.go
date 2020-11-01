package kuberesolver

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver/k8s"
	"github.com/kinvolk/seccompagent/pkg/registry"
)

type KubeResolverFunc func(namespace string, podname string) *registry.Registry

func KubeResolver(f KubeResolverFunc) (registry.ResolverFunc, error) {
	nodeName := os.Getenv("NODE_NAME")
	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil, errors.New("cannot create kubernetes client")
	}

	re := regexp.MustCompile(`"pid":([0-9]*),`)

	return func(state []byte) *registry.Registry {
		found := re.FindStringSubmatch(string(state))
		if len(found) < 2 {
			fmt.Printf("cannot find id in state %q\n", string(state))
			return f("unknown", "unknown")
		}
		pid, err := strconv.Atoi(found[1])
		if err != nil {
			fmt.Printf("cannot find pid in %q\n", found[1])
			return f("unknown", "unknown")
		}

		pod, err := k8sClient.ContainerLookup(pid)
		if err != nil {
			fmt.Printf("cannot find container with pid %q\n", pid)
			return f("unknown", "unknown")
		}
		return f(pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	}, nil
}
