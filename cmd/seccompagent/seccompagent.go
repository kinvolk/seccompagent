// +build linux,cgo

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/agent"
	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/ocihook"
	"github.com/kinvolk/seccompagent/pkg/registry"

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
			allowedFilesystems := map[string]struct{}{"proc": struct{}{}}
			r.Add("mount", handlers.Mount(allowedFilesystems))

			// Example:
			// 	# chmod 777 /
			// 	chmod: /: Bad message
			r.Add("chmod", handlers.Error(unix.EBADMSG))

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
			fmt.Printf("Pod %+v\n", podCtx)
			fmt.Printf("Metadata %+v\n", metadata)

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

			if fileName, ok := metadata["EXEC_PATTERN"]; ok {
				d, ok := metadata["EXEC_DURATION"]
				if ok {
					duration, _ := time.ParseDuration(d)
					r.Add("execve", handlers.ExecCondition(fileName, duration))
				}
			}

			allowedFilesystems := map[string]struct{}{}
			if v, ok := metadata["MOUNT_PROC"]; ok && v == "true" {
				allowedFilesystems["proc"] = struct{}{}
			}
			if v, ok := metadata["MOUNT_SYSFS"]; ok && v == "true" {
				allowedFilesystems["sysfs"] = struct{}{}
			}
			if len(allowedFilesystems) > 0 {
				r.Add("mount", handlers.Mount(allowedFilesystems))
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
