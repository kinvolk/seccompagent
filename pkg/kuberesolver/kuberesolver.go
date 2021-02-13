package kuberesolver

import (
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver/k8s"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
)

const (
	// containerd annotations
	// https://github.com/containerd/containerd/blob/master/pkg/cri/annotations/annotations.go

	containerdContainerName = "io.kubernetes.cri.container-name"

	// cri-o annotations
	// https://github.com/containers/podman/blob/master/pkg/annotations/annotations.go

	crioContainerType = "io.kubernetes.cri-o.ContainerType"
	crioContainerName = "io.kubernetes.cri-o.ContainerName"
	crioPodName       = "io.kubernetes.cri-o.Name"
	crioPodNamespace  = "io.kubernetes.cri-o.Namespace"
)

type PodContext struct {
	// Namespace is the Kubernetes namespace of the pod
	Namespace string

	// Pod is the name of the Kubernetes pod
	Pod string

	// Container is the name of the container in the Kubernetes pod
	Container string

	// Pid is the process is that is traced by the seccomp filter
	Pid int

	// Pid1 is the first process in the container
	Pid1 int
}

type KubeResolverFunc func(pod *PodContext, metadata map[string]string) registry.Filter

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

func readAnnotations(ann map[string]string) (podCtx *PodContext) {
	podCtx = &PodContext{}
	if ann == nil {
		return
	}
	if val, ok := ann[crioPodNamespace]; ok {
		podCtx.Pod = val
	}
	if val, ok := ann[crioPodName]; ok {
		podCtx.Pod = val
	}
	if val, ok := ann[containerdContainerName]; ok {
		podCtx.Container = val
	} else if val, ok := ann[crioContainerName]; ok {
		podCtx.Container = val
	}
	return
}

func KubeResolver(f KubeResolverFunc) (registry.ResolverFunc, error) {
	nodeName := os.Getenv("NODE_NAME")
	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil, fmt.Errorf("cannot create kubernetes client: %v", err)
	}

	return func(state *specs.ContainerProcessState) registry.Filter {
		vars := parseKV(state.Metadata)

		podCtx := readAnnotations(state.State.Annotations)

		podCtx.Pid = state.Pid
		podCtx.Pid1 = state.State.Pid

		if podCtx.Pod != "" && podCtx.Namespace != "" {
			log.WithFields(log.Fields{
				"namespace": podCtx.Namespace,
				"pod":       podCtx.Pod,
				"container": podCtx.Container,
				"err":       err,
			}).Trace("Pod details found from annotations")
			return f(nil, vars)
		}

		pod, err := k8sClient.ContainerLookup(state.State.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"pid": state.State.Pid,
				"err": err,
			}).Error("Cannot find container in Kubernetes")
			return f(nil, vars)
		}
		podCtx.Namespace = pod.ObjectMeta.Namespace
		podCtx.Pod = pod.ObjectMeta.Name

		return f(podCtx, vars)
	}, nil
}
