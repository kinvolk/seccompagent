/*
Copyright (C) 2022 The Seccomp Agent Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"

	pb "github.com/kinvolk/seccompagent/falco-plugin/api"
)

type Server struct {
	pb.UnimplementedSeccompAgentFalcoServer

	msgC chan SeccompAgentMessage
	errC chan error
}

// SeccompAgentMessage
type SeccompAgentMessage struct {
	ID           uint64
	Pid          uint64
	Syscall      string
	K8SNamespace string
	K8SPod       string
	K8SContainer string
	K8SPid       uint64
	K8SPidFilter uint64
}

func NewServer(msgC chan SeccompAgentMessage, errC chan error) (*Server, error) {
	return &Server{
		msgC: msgC,
		errC: errC,
	}, nil
}

func (s *Server) PublishEvent(_ context.Context, req *pb.PublishEventRequest) (*pb.PublishEventResponse, error) {
	s.msgC <- SeccompAgentMessage{
		ID:           req.Id,
		Pid:          req.Pid,
		Syscall:      req.Syscall,
		K8SNamespace: req.K8S.Namespace,
		K8SPod:       req.K8S.Pod,
		K8SContainer: req.K8S.Container,
		K8SPid:       req.K8S.Pid,
		K8SPidFilter: req.K8S.PidFilter,
	}
	return &pb.PublishEventResponse{}, nil
}
