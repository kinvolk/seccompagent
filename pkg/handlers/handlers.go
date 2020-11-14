package handlers

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func Error(err error) registry.HandlerFunc {
	if err == nil {
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
			return
		}
	} else {
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
			result.ErrVal = int32(err.(syscall.Errno))
			result.Val = ^uint64(0) // -1
			result.Flags = 0
			return
		}
	}
}

func MkdirWithSuffix(suffix string) registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return registry.HandlerResultErrno(syscall.ENOMEDIUM)
		}

		// TODO: use mkdirat() with /proc/pid/{root,cwd} opened separately, so we
		// can use libseccomp.NotifIDValid() between the open and the mkdirat.

		mode := uint32(req.Data.Args[1])
		if strings.HasPrefix(fileName, "/") {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/root%s%s", req.Pid, fileName, suffix), mode)
			if err != nil {
				return registry.HandlerResultErrno(syscall.ENOMEDIUM)
			}
		} else {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/cwd/%s%s", req.Pid, fileName, suffix), mode)
			if err != nil {
				return registry.HandlerResultErrno(syscall.ENOMEDIUM)
			}
		}
		return registry.HandlerResultSuccess()
	}
}
