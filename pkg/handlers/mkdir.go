package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"syscall"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
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
		return fmt.Sprintln("%d", int(syscall.ENOSYS))
	}

	err = syscall.Mkdir(params.Path, params.Mode)
	if err != nil {
		return fmt.Sprintf("%d", int(err.(syscall.Errno)))
	}
	return "0"
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
			return registry.HandlerResultErrno(syscall.EFAULT)
		}

		params := mkdirModuleParams{
			Module: "mkdir",
			Path:   fileName + suffix,
			Mode:   uint32(req.Data.Args[1]),
		}

		mntns, err := nsenter.OpenNamespace(req.Pid, "mnt")
		if err != nil {
			fmt.Printf("Cannot open namespace: %s", err)
			return registry.HandlerResultErrno(syscall.EPERM)
		}
		defer mntns.Close()

		root, err := nsenter.OpenRoot(req.Pid)
		if err != nil {
			fmt.Printf("Cannot open root: %s", err)
			return registry.HandlerResultErrno(syscall.EPERM)
		}
		defer root.Close()

		cwd, err := nsenter.OpenCwd(req.Pid)
		if err != nil {
			fmt.Printf("Cannot open cwd: %s", err)
			return registry.HandlerResultErrno(syscall.EPERM)
		}
		defer cwd.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			fmt.Printf("TOCTOU check failed: req.ID is no longer valid: %s\n", err)
			return registry.HandlerResultIntr()
		}

		output, err := nsenter.Run(root, cwd, mntns, nil, nil, params)
		if err != nil {
			fmt.Printf("Run returned: %s\n%v\n", output, err)
			return registry.HandlerResultErrno(syscall.ENOSYS)
		}
		errno, err := strconv.Atoi(string(output))
		if err != nil {
			fmt.Printf("Run returned: %s\n%v\n", output, err)
			return registry.HandlerResultErrno(syscall.ENOSYS)
		}
		if errno != 0 {
			return registry.HandlerResultErrno(syscall.Errno(errno))
		}

		return registry.HandlerResultSuccess()
	}
}
