// +build linux,cgo

package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"
)

var _ = nsenter.RegisterModule("mount", runMountInNamespaces)

type mountModuleParams struct {
	Module     string `json:"module,omitempty"`
	Source     string `json:"source,omitempty"`
	Dest       string `json:"dest,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
}

func runMountInNamespaces(param []byte) string {
	var params mountModuleParams
	err := json.Unmarshal(param, &params)
	if err != nil {
		return fmt.Sprintln("%d", int(unix.ENOSYS))
	}

	err = unix.Mount(params.Source, params.Dest, params.Filesystem, 0, "")
	if err != nil {
		return fmt.Sprintf("%d", int(err.(unix.Errno)))
	}
	return "0"
}

func Mount(allowedFilesystems map[string]struct{}) registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer memFile.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

		source, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return registry.HandlerResultErrno(unix.EFAULT)
		}
		dest, err := readarg.ReadString(memFile, int64(req.Data.Args[1]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return registry.HandlerResultErrno(unix.EFAULT)
		}
		filesystem, err := readarg.ReadString(memFile, int64(req.Data.Args[2]))
		if err != nil {
			fmt.Printf("Cannot read argument: %s", err)
			return registry.HandlerResultErrno(unix.EFAULT)
		}
		fmt.Printf("mount: %q %q %q\n", source, dest, filesystem)

		if _, ok := allowedFilesystems[filesystem]; !ok {
			// The seccomp agent is not allowed to perform this operation.
			// Let the kernel decide if it's allowed
			return registry.HandlerResultContinue()
		}

		params := mountModuleParams{
			Module:     "mount",
			Source:     source,
			Dest:       dest,
			Filesystem: filesystem,
		}

		mntns, err := nsenter.OpenNamespace(req.Pid, "mnt")
		if err != nil {
			fmt.Printf("Cannot open namespace: %s", err)
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer mntns.Close()

		netns, err := nsenter.OpenNamespace(req.Pid, "net")
		if err != nil {
			fmt.Printf("Cannot open namespace: %s", err)
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer netns.Close()

		pidns, err := nsenter.OpenNamespace(req.Pid, "pid")
		if err != nil {
			fmt.Printf("Cannot open namespace: %s", err)
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer pidns.Close()

		root, err := nsenter.OpenRoot(req.Pid)
		if err != nil {
			fmt.Printf("Cannot open root: %s", err)
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer root.Close()

		cwd, err := nsenter.OpenCwd(req.Pid)
		if err != nil {
			fmt.Printf("Cannot open cwd: %s", err)
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer cwd.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			fmt.Printf("TOCTOU check failed: req.ID is no longer valid: %s\n", err)
			return registry.HandlerResultIntr()
		}

		output, err := nsenter.Run(root, cwd, mntns, netns, pidns, params)
		if err != nil {
			fmt.Printf("Run returned: %s\n%v\n", output, err)
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		errno, err := strconv.Atoi(string(output))
		if err != nil {
			fmt.Printf("Run returned: %s\n%v\n", output, err)
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		if errno != 0 {
			return registry.HandlerResultErrno(unix.Errno(errno))
		}

		return registry.HandlerResultSuccess()
	}
}
