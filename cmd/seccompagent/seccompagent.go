// +build linux,cgo

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"text/template"

	"github.com/kinvolk/seccompagent/pkg/agent"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/ocihook"

	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	socketFile    string
	hookParam     bool
	resolverParam string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
	flag.BoolVar(&hookParam, "hook", false, "Run as OCI hook")
	flag.StringVar(&resolverParam, "resolver", "", "Container resolver to use [none, demo-basic, kubernetes]")
}

func main() {
	nsenter.Init()

	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(errors.New("invalid command"))
	}

	if hookParam || os.Args[0] == "seccomphook" {
		ocihook.Run(socketFile)
		return
	}

	var resolver registry.ResolverFunc

	switch resolverParam {
	case "none", "":
		resolver = nil
	case "demo-basic":
		// Using the resolver allows to implement different behaviour
		// depending on the container. For example, you could connect to the
		// Kubernetes API, find the pod, and allow or deny a syscall depending
		// on the pod specifications (e.g. namespace, annotations,
		// serviceAccount).
		resolver = func(state *specs.ContainerProcessState) *registry.Registry {
			r := registry.New()

			// Example:
			// 	/ # mount -t proc proc root
			// 	/ # ls /root/self/cmdline
			// 	/root/self/cmdline
			r.Add("mount", handlers.Mount)

			// Example:
			// 	# chmod 777 /
			// 	chmod: /: Bad message
			r.Add("chmod", handlers.Error(syscall.EBADMSG))

			// Example:
			// 	# mkdir /abc
			// 	# ls -d /abc*
			// 	/abc-pid-3528098
			if state != nil {
				r.Add("mkdir", handlers.MkdirWithSuffix(fmt.Sprintf("-pid-%d", state.State.Pid)))
			}

			return r
		}
	case "kubernetes":
		kubeResolverFunc := func(podCtx *kuberesolver.PodContext, metadata map[string]string) *registry.Registry {
			r := registry.New()
			if v, ok := metadata["MKDIR_TMPL"]; ok {
				tmpl, err := template.New("mkdirTmpl").Parse(v)
				if err == nil {
					var suffix strings.Builder
					err = tmpl.Execute(&suffix, podCtx)
					if err == nil {
						r.Add("mkdir", handlers.MkdirWithSuffix(suffix.String()))
					}
				}
			}
			return r
		}
		var err error
		resolver, err = kuberesolver.KubeResolver(kubeResolverFunc)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.New("invalid container resolver"))
	}

	err := agent.StartAgent(socketFile, resolver)
	if err != nil {
		panic(err)
	}
}
