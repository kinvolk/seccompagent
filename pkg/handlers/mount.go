// +build linux,cgo

package handlers

import (
	"encoding/json"
	"fmt"
	"syscall"

	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
)

var _ = nsenter.RegisterModule("mount", runMountInNamespaces)

type mountModuleParams struct {
	Module     string `json:"module,omitempty"`
	Source     string `json:"source,omitempty"`
	Dest       string `json:"dest,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
}

func runMountInNamespaces(param []byte) {
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

func Mount(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (intr bool, errVal int32, val uint64, flags uint32) {
	errVal = int32(syscall.ENOSYS)
	val = ^uint64(0) // -1

	memFile, err := readarg.OpenMem(req.Pid)
	if err != nil {
		return false, 0, 0, libseccomp.NotifRespFlagContinue
	}
	defer memFile.Close()

	if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
		return true, 0, 0, 0
	}

	source, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return false, 0, 0, libseccomp.NotifRespFlagContinue
	}
	dest, err := readarg.ReadString(memFile, int64(req.Data.Args[1]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return false, 0, 0, libseccomp.NotifRespFlagContinue
	}
	filesystem, err := readarg.ReadString(memFile, int64(req.Data.Args[2]))
	if err != nil {
		fmt.Printf("Cannot read argument: %s", err)
		return false, 0, 0, libseccomp.NotifRespFlagContinue
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

	mntns, err := nsenter.OpenNamespace(fmt.Sprintf("/proc/%d/ns/mnt", req.Pid))
	if err != nil {
		fmt.Printf("Cannot open namespace: %s", err)
		return false, 0, 0, libseccomp.NotifRespFlagContinue
	}

	if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
		fmt.Printf("TOCTOU check failed: req.ID is no longer valid: %s\n", err)
		return true, 0, 0, 0
	}

	err = nsenter.Run(mntns, params)
	if err != nil {
		fmt.Printf("Run returned: %s", err)
	}

	intr = false
	errVal = 0
	val = 0
	return
}
