// +build linux,cgo

package main

import (
	"errors"
	"flag"
	"os"
	"regexp"
	"syscall"

	"github.com/kinvolk/seccompagent/pkg/agent"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/ocihook"
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
		resolver = func(state []byte) *registry.Registry {
			r := registry.New()

			re := regexp.MustCompile(`"pid":([0-9]*),`)
			found := re.FindStringSubmatch(string(state))
			pid := found[1]

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
			r.Add("mkdir", handlers.MkdirWithSuffix("-pid-"+pid))

			return r
		}
	case "kubernetes":
		kubeResolverFunc := func(namespace string, podname string) *registry.Registry {
			r := registry.New()
			r.Add("mkdir", handlers.MkdirWithSuffix("-"+namespace+"-"+podname))
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
