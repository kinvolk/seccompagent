// Copyright 2020-2021 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kuberesolver

import (
	"errors"
	"os"
	"strings"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver/k8s"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"

	ociannotations "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/oci-annotations"
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

func readAnnotations(ann map[string]string) (podCtx *PodContext) {
	podCtx = &PodContext{}
	if ann == nil {
		return
	}

	annResolver, err := ociannotations.NewResolverFromAnnotations(ann)
	if err != nil {
		return
	}
	if val := annResolver.PodNamespace(ann); val != "" {
		podCtx.Namespace = val
	}
	if val := annResolver.PodName(ann); val != "" {
		podCtx.Pod = val
	}
	if val := annResolver.ContainerName(ann); val != "" {
		podCtx.Container = val
	}
	return
}

func KubeResolver(f KubeResolverFunc) (registry.ResolverFunc, error) {
	nodeName := os.Getenv("NODE_NAME")
	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil, errors.New("cannot create kubernetes client")
	}

	return func(state *specs.ContainerProcessState) *registry.Registry {
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
			return f(podCtx, vars)
		}

		pod, err := k8sClient.ContainerLookup(state.State.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"pid": state.State.Pid,
				"err": err,
			}).Error("Cannot find container in Kubernetes")
			return f(podCtx, vars)
		}
		podCtx.Namespace = pod.ObjectMeta.Namespace
		podCtx.Pod = pod.ObjectMeta.Name

		return f(podCtx, vars)
	}, nil
}
