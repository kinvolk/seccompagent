// Copyright 2020-2022 Kinvolk
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

package falco

import (
	"context"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	pb "github.com/kinvolk/seccompagent/falco-plugin/api"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/registry"
)

const socketfile = "/run/seccomp-agent-falco-plugin/seccomp-agent-falco-plugin.sock"

func NotifyFalco(podCtx *kuberesolver.PodContext) func(h registry.HandlerFunc) registry.HandlerFunc {
	return func(h registry.HandlerFunc) registry.HandlerFunc {
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) registry.HandlerResult {
			log.WithFields(log.Fields{
				"pod": podCtx,
			}).Debug("Falco middleware")

			var client pb.SeccompAgentFalcoClient
			var ctx context.Context
			var cancel context.CancelFunc
			conn, err := grpc.Dial("unix://"+socketfile, grpc.WithInsecure())
			if err != nil {
				panic(err)
			}
			defer conn.Close()
			client = pb.NewSeccompAgentFalcoClient(conn)
			ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			syscallName, err := req.Data.Syscall.GetName()
			if err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"req": req,
					"err": err,
				}).Error("Error in decoding syscall")
			}

			_, err = client.PublishEvent(ctx, &pb.PublishEventRequest{
				Id:      req.ID,
				Pid:     uint64(req.Pid),
				Syscall: syscallName,
				K8S: &pb.KubernetesWorkload{
					Namespace: podCtx.Namespace,
					Pod:       podCtx.Pod,
					Container: podCtx.Container,
					PidFilter: uint64(podCtx.Pid),
					Pid:       uint64(podCtx.Pid1),
				},
			})
			if err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"req": req,
					"err": err,
				}).Error("Error in sending event to Falco")
			}

			var r registry.HandlerResult
			if h != nil {
				r = h(fd, req)
			} else {
				r = registry.HandlerResultContinue()
			}

			log.WithFields(log.Fields{
				"pod": podCtx,
			}).Debug("Falco middleware completed")
			return r
		}
	}
}
