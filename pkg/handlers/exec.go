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
	return func(req *libseccomp.ScmpNotifReq) (errVal int32, val uint64, flags uint32) {
		// TODO: open /proc/pid/mem only one time and call
		// libseccomp.NotifIDValid() after.

		fileName, err := readarg.ReadString(req.Pid, int64(req.Data.Args[0]))
		if err != nil {
			if os.IsPermission(err) {
				// Probably because of prctl(PR_SET_DUMPABLE) in runc-init
				return 0, 0, libseccomp.NotifRespFlagContinue
			}
			fmt.Printf("Cannot read argument: %s\n", err)
			return 0, 0, libseccomp.NotifRespFlagContinue
		}

		if fileName == filePattern {
			fmt.Printf("execve(%q): matching pattern %q: wait %s\n", fileName, filePattern, duration)
			time.Sleep(duration)
		} else {
			fmt.Printf("execve(%q)\n", fileName)
		}
		return 0, 0, libseccomp.NotifRespFlagContinue
	}
}
