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
		return func(req *libseccomp.ScmpNotifReq) (errVal int32, val uint64, flags uint32) {
			return
		}
	} else {
		return func(req *libseccomp.ScmpNotifReq) (errVal int32, val uint64, flags uint32) {
			errVal = int32(err.(syscall.Errno))
			val = ^uint64(0) // -1
			flags = 0
			return
		}
	}
}

func MkdirWithSuffix(suffix string) registry.HandlerFunc {
	return func(req *libseccomp.ScmpNotifReq) (errVal int32, val uint64, flags uint32) {
		fileName, err := readarg.ReadString(req.Pid, int64(req.Data.Args[0]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return int32(syscall.ENOMEDIUM), ^uint64(0), 0
		}

		mode := uint32(req.Data.Args[1])
		if strings.HasPrefix(fileName, "/") {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/root%s%s", req.Pid, fileName, suffix), mode)
			if err != nil {
				return int32(syscall.ENOMEDIUM), ^uint64(0), 0
			}
		} else {
			err := syscall.Mkdir(fmt.Sprintf("/proc/%d/cwd/%s-boo", req.Pid, fileName), mode)
			if err != nil {
				return int32(syscall.ENOMEDIUM), ^uint64(0), 0
			}
		}
		return 0, 0, 0
	}
}
