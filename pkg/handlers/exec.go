package handlers

import (
	"fmt"
	"os"
	"time"

	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func ExecCondition(filePattern string, duration time.Duration) registry.HandlerFunc {
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
			if os.IsPermission(err) {
				// Probably because of prctl(PR_SET_DUMPABLE) in runc-init
				return false, 0, 0, libseccomp.NotifRespFlagContinue
			}
			fmt.Printf("Cannot read argument: %s\n", err)
			return false, 0, 0, libseccomp.NotifRespFlagContinue
		}

		if fileName == filePattern {
			fmt.Printf("execve(%q): matching pattern %q: wait %s\n", fileName, filePattern, duration)
			time.Sleep(duration)
		} else {
			fmt.Printf("execve(%q)\n", fileName)
		}
		return false, 0, 0, libseccomp.NotifRespFlagContinue
	}
}
