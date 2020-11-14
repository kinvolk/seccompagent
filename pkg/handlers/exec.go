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
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		// This handlers does not change the behaviour but just delay the return
		result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResult{Intr: true}
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			if os.IsPermission(err) {
				// Probably because of prctl(PR_SET_DUMPABLE) in runc-init
				return
			}
			fmt.Printf("Cannot read argument: %s\n", err)
			return
		}

		if fileName == filePattern {
			fmt.Printf("execve(%q): matching pattern %q: wait %s\n", fileName, filePattern, duration)
			time.Sleep(duration)
		} else {
			fmt.Printf("execve(%q)\n", fileName)
		}
		return
	}
}
