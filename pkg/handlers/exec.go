package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func ExecCondition(filePattern string, duration time.Duration) registry.HandlerFunc {
	return func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		// This handlers does not change the behaviour but just delay the return
		result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return
		}
		defer memFile.Close()

		if err := filter.NotifIDValid(req); err != nil {
			return registry.HandlerResult{Intr: true}
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot read argument")
			return
		}

		if fileName == filePattern {
			log.WithFields(log.Fields{
				"filter":       filter.Name(),
				"pid":          req.Pid,
				"filename":     fileName,
				"file-pattern": filePattern,
				"duration":     duration,
			}).Debug("Execve: introduce delay")
			time.Sleep(duration)
		} else {
			log.WithFields(log.Fields{
				"filter":       filter.Name(),
				"pid":          req.Pid,
				"filename":     fileName,
				"file-pattern": filePattern,
			}).Debug("Execve: no match; continue")
		}
		return
	}
}

func ExecSidecars(podCtx *kuberesolver.PodContext, sidecarsList string, duration time.Duration) registry.HandlerFunc {
	sidecars := map[string]struct{}{}
	for _, sidecar := range strings.Split(sidecarsList, ",") {
		sidecars[sidecar] = struct{}{}
	}

	return func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		// This handlers does not change the behaviour but just delay the return
		result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

		// Only care about processes from runc-init, not from runc-exec
		if podCtx.Pid != podCtx.Pid1 {
			return
		}
		// Only care about syscalls from pid1
		if int(req.Pid) != podCtx.Pid1 {
			return
		}

		// Sidecars can go on
		if _, ok := sidecars[podCtx.Container]; ok {
			log.WithFields(log.Fields{
				"filter":    filter.Name(),
				"pid":       req.Pid,
				"container": podCtx.Container,
			}).Debug("Execve: found sidecar")

			return
		}

		// Non-sidecars have to wait
		var stat unix.Stat_t
		err := unix.Stat(fmt.Sprintf("/proc/%d", req.Pid), &stat)
		if err != nil {
			log.WithFields(log.Fields{
				"filter":    filter.Name(),
				"pid":       req.Pid,
				"container": podCtx.Container,
			}).Error("Execve: cannot read procfs")
			return
		}
		ctime := time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec))
		diff := ctime.Add(duration).Sub(time.Now())

		log.WithFields(log.Fields{
			"filter":    filter.Name(),
			"pid":       req.Pid,
			"container": podCtx.Container,
			"ctime":     ctime.String(),
			"diff":      diff.String(),
		}).Debug("Execve: found non-sidecar container")
		if diff > 0 {
			time.Sleep(diff)
		}
		return
	}
}
