package kuberesolver

import (
	"errors"
	"os"
	"strings"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver/k8s"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
)

type PodContext struct {
	Namespace string
	Pod       string
	Container string
}

type KubeResolverFunc func(pod *PodContext, metadata map[string]string) *registry.Registry

func parseKV(metadata string) map[string]string {
	vars := map[string]string{}
	varsArr := strings.Split(metadata, "\n")
	for _, line := range varsArr {
		idx := strings.Index(line, "=")
		switch idx {
		case -1:
			vars[line] = ""
		case 0:
			// skip
		default:
			k := line[0:idx]
			v := line[idx+1:]
			vars[k] = v
		}
	}
	return vars
}

func KubeResolver(f KubeResolverFunc) (registry.ResolverFunc, error) {
	nodeName := os.Getenv("NODE_NAME")
	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil, errors.New("cannot create kubernetes client")
	}

	return func(state *specs.ContainerProcessState) *registry.Registry {
		vars := parseKV(state.Metadata)

		pod, err := k8sClient.ContainerLookup(state.State.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"pid": state.State.Pid,
				"err": err,
			}).Error("Cannot find container in Kubernetes")
			return f(nil, vars)
		}
		podCtx := &PodContext{
			Namespace: pod.ObjectMeta.Namespace,
			Pod:       pod.ObjectMeta.Name,
			Container: "TODO",
		}
		return f(podCtx, vars)
	}, nil
}
