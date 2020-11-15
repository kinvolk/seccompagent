package handlers

import (
	"time"

	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
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
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot read argument")
			return
		}

		if fileName == filePattern {
			log.WithFields(log.Fields{
				"fd":           fd,
				"pid":          req.Pid,
				"filename":     fileName,
				"file-pattern": filePattern,
				"duration":     duration,
			}).Debug("Execve: introduce delay")
			time.Sleep(duration)
		} else {
			log.WithFields(log.Fields{
				"fd":           fd,
				"pid":          req.Pid,
				"filename":     fileName,
				"file-pattern": filePattern,
			}).Debug("Execve: no match; continue")
		}
		return
	}
}
