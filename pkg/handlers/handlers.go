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
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (intr bool, errVal int32, val uint64, flags uint32) {
			return
		}
	} else {
		return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (intr bool, errVal int32, val uint64, flags uint32) {
			errVal = int32(err.(syscall.Errno))
			val = ^uint64(0) // -1
			flags = 0
			return
		}
	}
}

func MkdirWithSuffix(suffix string) registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (intr bool, errVal int32, val uint64, flags uint32) {
		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return false, 0, 0, libseccomp.NotifRespFlagContinue
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return true, 0, 0, 0
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return false, int32(syscall.ENOMEDIUM), ^uint64(0), 0
		}

		// TODO: use mkdirat() with /proc/pid/{root,cwd} opened separately, so we
		// can use libseccomp.NotifIDValid() between the open and the mkdirat.

		mode := uint32(req.Data.Args[1])
		if strings.HasPrefix(fileName, "/") {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/root%s%s", req.Pid, fileName, suffix), mode)
			if err != nil {
				return false, int32(syscall.ENOMEDIUM), ^uint64(0), 0
			}
		} else {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/cwd/%s-boo", req.Pid, fileName), mode)
			if err != nil {
				return false, int32(syscall.ENOMEDIUM), ^uint64(0), 0
			}
		}
		return false, 0, 0, 0
	}
}
