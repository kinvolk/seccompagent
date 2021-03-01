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

	"github.com/kinvolk/seccompagent/pkg/agent"
	"github.com/kinvolk/seccompagent/pkg/handlers"
	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/registry"

	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	socketFile    string
	resolverParam string
	logflags      string
)

func init() {
	flag.StringVar(&socketFile, "socketfile", "/run/seccomp-agent.socket", "Socket file")
	flag.StringVar(&resolverParam, "resolver", "", "Container resolver to use [none, demo-basic, kubernetes]")
	flag.StringVar(&logflags, "log", "info", "log level [trace,debug,info,warn,error,fatal,color,nocolor,json]")
}

func main() {
	nsenter.Init()

	flag.Parse()
	for _, v := range strings.Split(logflags, ",") {
		if v == "json" {
			log.SetFormatter(&log.JSONFormatter{})
		} else if v == "color" {
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
		} else if v == "nocolor" {
			log.SetFormatter(&log.TextFormatter{DisableColors: true})
		} else if lvl, err := log.ParseLevel(v); err == nil {
			log.SetLevel(lvl)
		} else {
			fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", err.Error())
			flag.Usage()
			os.Exit(1)
		}
	}
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(errors.New("invalid command"))
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
			log.WithFields(log.Fields{
				"pod":      podCtx,
				"metadata": metadata,
			}).Debug("New container")

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

			if sidecars, ok := metadata["SIDECARS"]; ok {
				d, ok := metadata["SIDECARS_DELAY"]
				if ok {
					duration, _ := time.ParseDuration(d)
					r.Add("execve", handlers.ExecSidecars(podCtx, sidecars, duration))
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
