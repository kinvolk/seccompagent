package registry

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type HandlerFunc func(*libseccomp.ScmpNotifReq) (int32, uint64, uint32)

type Registry struct {
	SyscallHandler map[string]HandlerFunc
}

type ResolverFunc func(state *specs.ContainerProcessState) *Registry

func New() *Registry {
	return &Registry{
		SyscallHandler: map[string]HandlerFunc{},
	}
}

func (r *Registry) Add(name string, f HandlerFunc) {
	r.SyscallHandler[name] = f
}
