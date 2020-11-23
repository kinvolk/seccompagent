package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var _ = nsenter.RegisterModule("mkdir", runMkdirInNamespaces)

type mkdirModuleParams struct {
	Module string `json:"module,omitempty"`
	Path   string `json:"path,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
}

func runMkdirInNamespaces(param []byte) string {
	var params mkdirModuleParams
	err := json.Unmarshal(param, &params)
	if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
	}

	err = unix.Mkdir(params.Path, params.Mode)
	if err != nil {
		return fmt.Sprintf("%d", int(err.(unix.Errno)))
	}
	return "0"
}

func MkdirWithSuffix(suffix string) registry.HandlerFunc {
	return func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}
		}
		defer memFile.Close()

		if err := filter.NotifIDValid(req); err != nil {
			return registry.HandlerResultIntr()
		}

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}

		params := mkdirModuleParams{
			Module: "mkdir",
			Path:   fileName + suffix,
			Mode:   uint32(req.Data.Args[1]),
		}

		mntns, err := nsenter.OpenNamespace(req.Pid, "mnt")
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot open namespace")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer mntns.Close()

		root, err := nsenter.OpenRoot(req.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot open root")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer root.Close()

		cwd, err := nsenter.OpenCwd(req.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot open cwd")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer cwd.Close()

		if err := filter.NotifIDValid(req); err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"req":    req,
				"err":    err,
			}).Debug("Notification no longer valid")
			return registry.HandlerResultIntr()
		}

		output, err := nsenter.Run(root, cwd, mntns, nil, nil, params)
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"output": output,
				"err":    err,
			}).Error("Run in target namespaces failed")
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		errno, err := strconv.Atoi(string(output))
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"output": output,
				"err":    err,
			}).Error("Cannot parse return value")
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		if errno != 0 {
			return registry.HandlerResultErrno(unix.Errno(errno))
		}

		return registry.HandlerResultSuccess()
	}
}
