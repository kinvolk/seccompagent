// +build linux,cgo
package main

import (
	"encoding/json"
	"fmt"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
)

type MountModule struct {
}

type mountModuleParams struct {
	Module     string `json:"module,omitempty"`
	Source     string `json:"source,omitempty"`
	Dest       string `json:"dest,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
}

func (m *MountModule) Run(param []byte) {
	fmt.Printf("Run param: %s\n", param)

	var params mountModuleParams
	err := json.Unmarshal(param, &params)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	err = syscall.Mount(params.Source, params.Dest, params.Filesystem, 0, "")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
}

func handleMount(req *libseccomp.ScmpNotifReq) (errVal int32, val uint64, flags uint32) {
	source, err := readArgString(req.Pid, int64(req.Data.Args[0]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return 0, 0, libseccomp.NotifRespFlagContinue
	}
	dest, err := readArgString(req.Pid, int64(req.Data.Args[1]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return 0, 0, libseccomp.NotifRespFlagContinue
	}
	filesystem, err := readArgString(req.Pid, int64(req.Data.Args[2]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return 0, 0, libseccomp.NotifRespFlagContinue
	}
	if filesystem == "proc" {
	}

	fmt.Printf("mount: %q %q %q\n", source, dest, filesystem)

	params := mountModuleParams{
		Module:     "mount",
		Source:     source,
		Dest:       dest,
		Filesystem: filesystem,
	}
	err = nsenter.Run(fmt.Sprintf("/proc/%d/ns/mnt", req.Pid), params)
	if err != nil {
		fmt.Printf("Run returned: %s", err)
	}

	errVal = int32(syscall.ENOMEDIUM)
	val = ^uint64(0) // -1
	return
}

func init() {
	nsenter.Modules["mount"] = &MountModule{}
}
