/*
Copyright (C) 2022 The Falco Authors.

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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/grpc"

	pb "github.com/kinvolk/seccompagent/falco-plugin/api"
)

// SeccompAgentPlugin represents our plugin
type SeccompAgentPlugin struct {
	plugins.BasePlugin

	SocketFile    string `json:"socketFile" jsonschema:"description=Socket File for receiving events from Seccomp Agent via gRPC (Default: /run/seccomp-agent-falco-plugin.sock)"`
	FlushInterval uint64 `json:"flushInterval" jsonschema:"description=Flush Interval in ms (Default: 30)"`
}

// SeccompAgentInstance represents a opened stream based on our Plugin
type SeccompAgentInstance struct {
	source.BaseInstance
	msgC <-chan SeccompAgentMessage
	errC <-chan error
	ctx  context.Context
}

// init function is used for referencing our plugin to the Falco plugin framework
func init() {
	p := &SeccompAgentPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info displays information of the plugin to Falco plugin framework
func (seccompAgentPlugin *SeccompAgentPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          6,
		Name:        "seccompagent",
		Description: "Seccomp Agent Events",
		Contact:     "github.com/kinvolk/seccompagent/",
		Version:     "0.2.0",
		EventSource: "seccompagent",
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (seccompAgentPlugin *SeccompAgentPlugin) Init(config string) error {
	seccompAgentPlugin.FlushInterval = 30
	seccompAgentPlugin.SocketFile = "/run/seccomp-agent-falco-plugin.sock"
	return json.Unmarshal([]byte(config), &seccompAgentPlugin)
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (seccompAgentPlugin *SeccompAgentPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "seccompagent.id", Desc: "Cookie passed by the kernel in struct seccomp_notif"},
		{Type: "uint64", Name: "seccompagent.pid", Desc: "Process that made the syscall"},
		{Type: "string", Name: "seccompagent.syscall", Desc: "Name of the syscall"},
		{Type: "string", Name: "seccompagent.k8s.namespace", Desc: "Kubernetes namespace"},
		{Type: "string", Name: "seccompagent.k8s.pod", Desc: "Kubernetes pod"},
		{Type: "string", Name: "seccompagent.k8s.container", Desc: "Kubernetes container"},
		{Type: "uint64", Name: "seccompagent.k8s.pid", Desc: "Pid 1 of the container"},
		{Type: "uint64", Name: "seccompagent.k8s.pidfilter", Desc: "Process that attached the seccomp filter"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (seccompAgentPlugin *SeccompAgentPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var data SeccompAgentMessage

	rawData, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	switch req.Field() {
	case "seccompagent.id":
		req.SetValue(data.ID)
	case "seccompagent.pid":
		req.SetValue(data.Pid)
	case "seccompagent.syscall":
		req.SetValue(data.Syscall)
	case "seccompagent.k8s.namespace":
		req.SetValue(data.K8SNamespace)
	case "seccompagent.k8s.pod":
		req.SetValue(data.K8SPod)
	case "seccompagent.k8s.container":
		req.SetValue(data.K8SContainer)
	case "seccompagent.k8s.pid":
		req.SetValue(data.K8SPid)
	case "seccompagent.k8s.pidfilter":
		req.SetValue(data.K8SPidFilter)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (seccompAgentPlugin *SeccompAgentPlugin) Open(params string) (source.Instance, error) {
	ctx := context.Background()
	msgC := make(chan SeccompAgentMessage)
	errC := make(chan error)

	os.Remove(seccompAgentPlugin.SocketFile)
	lis, err := net.Listen("unix", seccompAgentPlugin.SocketFile)
	if err != nil {
		return nil, err
	}

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	server, err := NewServer(msgC, errC)
	if err != nil {
		return nil, err
	}
	pb.RegisterSeccompAgentFalcoServer(grpcServer, server)
	go grpcServer.Serve(lis)

	return &SeccompAgentInstance{
		msgC: msgC,
		errC: errC,
		ctx:  ctx,
	}, nil
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (seccompAgentPlugin *SeccompAgentPlugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

// NextBatch is called by Falco plugin framework to get a batch of events from the instance
func (seccompAgentInstance *SeccompAgentInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {

	seccompAgentPlugin := pState.(*SeccompAgentPlugin)

	i := 0
	expire := time.After(time.Duration(seccompAgentPlugin.FlushInterval) * time.Millisecond)
	for i < evts.Len() {
		select {
		case m := <-seccompAgentInstance.msgC:
			s, _ := json.Marshal(m)
			evt := evts.Get(i)
			if _, err := evt.Writer().Write(s); err != nil {
				return i, err
			}
			i++
		case <-expire:
			// Timeout occurred, flush a partial batch
			return i, sdk.ErrTimeout
		case err := <-seccompAgentInstance.errC:
			// todo: this will cause the program to exit. May we want to ignore some kind of error?
			return i, err
		}
	}

	// The batch is full
	return i, nil
}

func (seccompAgentInstance *SeccompAgentInstance) Close() {
	// TODO: Check if we need to close the channels on the sender side (not here)?
	seccompAgentInstance.ctx.Done()
}

// main is mandatory but empty, because the plugin will be used as C library by Falco plugin framework
func main() {}
