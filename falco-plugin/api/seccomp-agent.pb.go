// Copyright 2022 The Seccomp Agent authors
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: seccomp-agent.proto

package seccompagent

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PublishEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// id is the cookie passed by the kernel in struct seccomp_notif
	Id uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// pid refers to the process that made the syscall
	Pid uint64 `protobuf:"varint,2,opt,name=pid,proto3" json:"pid,omitempty"`
	// syscall is the name of the syscall
	Syscall string `protobuf:"bytes,3,opt,name=syscall,proto3" json:"syscall,omitempty"`
	// KubernetesWorkload
	K8S *KubernetesWorkload `protobuf:"bytes,4,opt,name=k8s,proto3" json:"k8s,omitempty"`
}

func (x *PublishEventRequest) Reset() {
	*x = PublishEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seccomp_agent_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublishEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublishEventRequest) ProtoMessage() {}

func (x *PublishEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_seccomp_agent_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublishEventRequest.ProtoReflect.Descriptor instead.
func (*PublishEventRequest) Descriptor() ([]byte, []int) {
	return file_seccomp_agent_proto_rawDescGZIP(), []int{0}
}

func (x *PublishEventRequest) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *PublishEventRequest) GetPid() uint64 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *PublishEventRequest) GetSyscall() string {
	if x != nil {
		return x.Syscall
	}
	return ""
}

func (x *PublishEventRequest) GetK8S() *KubernetesWorkload {
	if x != nil {
		return x.K8S
	}
	return nil
}

type KubernetesWorkload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Kubernetes namespace
	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// Kubernetes pod
	Pod string `protobuf:"bytes,2,opt,name=pod,proto3" json:"pod,omitempty"`
	// Kubernetes container, useful if there are several containers in the pod
	Container string `protobuf:"bytes,3,opt,name=container,proto3" json:"container,omitempty"`
	// pid is the pid 1 of the container
	Pid uint64 `protobuf:"varint,4,opt,name=pid,proto3" json:"pid,omitempty"`
	// pid_filter refers to the process that attached the seccomp filter. Usually
	// the pid 1 of the container, except with "docker-exec", "kubectl-exec" or
	// equivalent.
	PidFilter uint64 `protobuf:"varint,5,opt,name=pid_filter,json=pidFilter,proto3" json:"pid_filter,omitempty"`
}

func (x *KubernetesWorkload) Reset() {
	*x = KubernetesWorkload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seccomp_agent_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KubernetesWorkload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KubernetesWorkload) ProtoMessage() {}

func (x *KubernetesWorkload) ProtoReflect() protoreflect.Message {
	mi := &file_seccomp_agent_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KubernetesWorkload.ProtoReflect.Descriptor instead.
func (*KubernetesWorkload) Descriptor() ([]byte, []int) {
	return file_seccomp_agent_proto_rawDescGZIP(), []int{1}
}

func (x *KubernetesWorkload) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *KubernetesWorkload) GetPod() string {
	if x != nil {
		return x.Pod
	}
	return ""
}

func (x *KubernetesWorkload) GetContainer() string {
	if x != nil {
		return x.Container
	}
	return ""
}

func (x *KubernetesWorkload) GetPid() uint64 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *KubernetesWorkload) GetPidFilter() uint64 {
	if x != nil {
		return x.PidFilter
	}
	return 0
}

type PublishEventResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PublishEventResponse) Reset() {
	*x = PublishEventResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_seccomp_agent_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublishEventResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublishEventResponse) ProtoMessage() {}

func (x *PublishEventResponse) ProtoReflect() protoreflect.Message {
	mi := &file_seccomp_agent_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublishEventResponse.ProtoReflect.Descriptor instead.
func (*PublishEventResponse) Descriptor() ([]byte, []int) {
	return file_seccomp_agent_proto_rawDescGZIP(), []int{2}
}

var File_seccomp_agent_proto protoreflect.FileDescriptor

var file_seccomp_agent_proto_rawDesc = []byte{
	0x0a, 0x13, 0x73, 0x65, 0x63, 0x63, 0x6f, 0x6d, 0x70, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x11, 0x73, 0x65, 0x63, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x67,
	0x65, 0x6e, 0x74, 0x66, 0x61, 0x6c, 0x63, 0x6f, 0x22, 0x8a, 0x01, 0x0a, 0x13, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x73, 0x68, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x10, 0x0a, 0x03, 0x70, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x03, 0x70,
	0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x12, 0x37, 0x0a, 0x03,
	0x6b, 0x38, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x73, 0x65, 0x63, 0x63,
	0x6f, 0x6d, 0x70, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x66, 0x61, 0x6c, 0x63, 0x6f, 0x2e, 0x4b, 0x75,
	0x62, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64,
	0x52, 0x03, 0x6b, 0x38, 0x73, 0x22, 0x93, 0x01, 0x0a, 0x12, 0x4b, 0x75, 0x62, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x65, 0x73, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x6f,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x70, 0x6f, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69,
	0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x03, 0x70, 0x69, 0x64, 0x12, 0x1d, 0x0a, 0x0a,
	0x70, 0x69, 0x64, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x09, 0x70, 0x69, 0x64, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x16, 0x0a, 0x14, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x32, 0x76, 0x0a, 0x11, 0x53, 0x65, 0x63, 0x63, 0x6f, 0x6d, 0x70, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x46, 0x61, 0x6c, 0x63, 0x6f, 0x12, 0x61, 0x0a, 0x0c, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x73, 0x68, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x26, 0x2e, 0x73, 0x65, 0x63, 0x63, 0x6f,
	0x6d, 0x70, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x66, 0x61, 0x6c, 0x63, 0x6f, 0x2e, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x73, 0x68, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x27, 0x2e, 0x73, 0x65, 0x63, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x66,
	0x61, 0x6c, 0x63, 0x6f, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x21, 0x5a, 0x1f, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x69, 0x6e, 0x76, 0x6f, 0x6c,
	0x6b, 0x2f, 0x73, 0x65, 0x63, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_seccomp_agent_proto_rawDescOnce sync.Once
	file_seccomp_agent_proto_rawDescData = file_seccomp_agent_proto_rawDesc
)

func file_seccomp_agent_proto_rawDescGZIP() []byte {
	file_seccomp_agent_proto_rawDescOnce.Do(func() {
		file_seccomp_agent_proto_rawDescData = protoimpl.X.CompressGZIP(file_seccomp_agent_proto_rawDescData)
	})
	return file_seccomp_agent_proto_rawDescData
}

var file_seccomp_agent_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_seccomp_agent_proto_goTypes = []interface{}{
	(*PublishEventRequest)(nil),  // 0: seccompagentfalco.PublishEventRequest
	(*KubernetesWorkload)(nil),   // 1: seccompagentfalco.KubernetesWorkload
	(*PublishEventResponse)(nil), // 2: seccompagentfalco.PublishEventResponse
}
var file_seccomp_agent_proto_depIdxs = []int32{
	1, // 0: seccompagentfalco.PublishEventRequest.k8s:type_name -> seccompagentfalco.KubernetesWorkload
	0, // 1: seccompagentfalco.SeccompAgentFalco.PublishEvent:input_type -> seccompagentfalco.PublishEventRequest
	2, // 2: seccompagentfalco.SeccompAgentFalco.PublishEvent:output_type -> seccompagentfalco.PublishEventResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_seccomp_agent_proto_init() }
func file_seccomp_agent_proto_init() {
	if File_seccomp_agent_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_seccomp_agent_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublishEventRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_seccomp_agent_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KubernetesWorkload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_seccomp_agent_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublishEventResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_seccomp_agent_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_seccomp_agent_proto_goTypes,
		DependencyIndexes: file_seccomp_agent_proto_depIdxs,
		MessageInfos:      file_seccomp_agent_proto_msgTypes,
	}.Build()
	File_seccomp_agent_proto = out.File
	file_seccomp_agent_proto_rawDesc = nil
	file_seccomp_agent_proto_goTypes = nil
	file_seccomp_agent_proto_depIdxs = nil
}
