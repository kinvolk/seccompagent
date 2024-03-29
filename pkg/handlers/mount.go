// Copyright 2020-2021 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && cgo
// +build linux,cgo

package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"

	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/nsenter"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"
	"github.com/kinvolk/seccompagent/pkg/userns"
)

var _ = nsenter.RegisterModule("mount", runMountInNamespaces)

type mountModuleParams struct {
	Module     string `json:"module,omitempty"`
	Source     string `json:"source,omitempty"`
	Dest       string `json:"dest,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
	Flags      int64  `json:"flags,omitempty"`
	Options    string `json:"options,omitempty"`
}

func runMountInNamespaces(param []byte) string {
	var params mountModuleParams
	err := json.Unmarshal(param, &params)
	if err != nil {
		return fmt.Sprintf("%d", int(unix.ENOSYS))
	}

	err = unix.Mount(params.Source, params.Dest, params.Filesystem, 0, params.Options)
	if err != nil {
		return fmt.Sprintf("%d", int(err.(unix.Errno)))
	}
	return "0"
}

func Mount(allowedFilesystems map[string]struct{}, requireUserNamespaceAdmin bool) registry.HandlerFunc {
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
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"arg": 0,
				"err": err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}
		dest, err := readarg.ReadString(memFile, int64(req.Data.Args[1]))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"arg": 1,
				"err": err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}
		filesystem, err := readarg.ReadString(memFile, int64(req.Data.Args[2]))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"arg": 2,
				"err": err,
			}).Error("Cannot read argument")
			return registry.HandlerResultErrno(unix.EFAULT)
		}

		// We don't handle flags, we may want to consider allowing a few.
		// This is here so the debug logging makes it possible to see flags used.
		flags := int64(req.Data.Args[3])

		log.WithFields(log.Fields{
			"fd":         fd,
			"pid":        req.Pid,
			"source":     source,
			"dest":       dest,
			"filesystem": filesystem,
			"flags":      flags,
		}).Debug("Mount")

		if _, ok := allowedFilesystems[filesystem]; !ok {
			// The seccomp agent is not allowed to perform this operation.
			// Let the kernel decide if it's allowed
			return registry.HandlerResultContinue()
		}

		var options string
		if req.Data.Args[4] != 0/* NULL */ && filesystem != "sysfs" {
			// Get options, we assume because this is specified in
			// allowedFilesystems that the data argument to mount(2)
			// is a string so this is safe now. We ignore options for sysfs, as it
			// doesn't define options.
			options, err = readarg.ReadString(memFile, int64(req.Data.Args[4]))
			if err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"pid": req.Pid,
					"arg": 4,
					"err": err,
				}).Error("Cannot read argument")
				return registry.HandlerResultErrno(unix.EFAULT)
			}

			// Log this at trace level only as it could have user credentials.
			log.WithFields(log.Fields{
				"fd":         fd,
				"pid":        req.Pid,
				"source":     source,
				"dest":       dest,
				"filesystem": filesystem,
				"flags":      flags,
				"options":    options,
			}).Trace("Handle mount")
		}

		if requireUserNamespaceAdmin {
			ok, err := userns.IsPIDAdminCapable(req.Pid)
			if err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"pid": req.Pid,
					"err": err,
				}).Error("Cannot check user namespace capabilities")
				return registry.HandlerResultErrno(unix.EFAULT)
			}
			if !ok {
				log.WithFields(log.Fields{
					"fd":  fd,
					"pid": req.Pid,
				}).Info("Mount attempted without CAP_SYS_ADMIN")
				return registry.HandlerResultErrno(unix.EPERM)
			}

			// Ensure the notification is still valid after checking user namespace capabilities.
			if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
				log.WithFields(log.Fields{
					"fd":  fd,
					"req": req,
					"err": err,
				}).Debug("Notification no longer valid")
				return registry.HandlerResultIntr()
			}
		}

		params := mountModuleParams{
			Module:     "mount",
			Source:     source,
			Dest:       dest,
			Filesystem: filesystem,
			Options:    options,
		}

		mntns, err := nsenter.OpenNamespace(req.Pid, "mnt")
		if err != nil {
			log.WithFields(log.Fields{
				"fd":   fd,
				"pid":  req.Pid,
				"kind": "mnt",
				"err":  err,
			}).Error("Cannot open namespace")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer mntns.Close()

		netns, err := nsenter.OpenNamespace(req.Pid, "net")
		if err != nil {
			log.WithFields(log.Fields{
				"fd":   fd,
				"pid":  req.Pid,
				"kind": "net",
				"err":  err,
			}).Error("Cannot open namespace")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer netns.Close()

		pidns, err := nsenter.OpenNamespace(req.Pid, "pid")
		if err != nil {
			log.WithFields(log.Fields{
				"fd":   fd,
				"pid":  req.Pid,
				"kind": "pid",
				"err":  err,
			}).Error("Cannot open namespace")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer pidns.Close()

		root, err := nsenter.OpenRoot(req.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot open root")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer root.Close()

		cwd, err := nsenter.OpenCwd(req.Pid)
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"pid": req.Pid,
				"err": err,
			}).Error("Cannot open cwd")
			return registry.HandlerResultErrno(unix.EPERM)
		}
		defer cwd.Close()

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"req": req,
				"err": err,
			}).Debug("Notification no longer valid")
			return registry.HandlerResultIntr()
		}

		output, err := nsenter.Run(root, cwd, mntns, netns, pidns, params)
		if err != nil {
			log.WithFields(log.Fields{
				"fd":     fd,
				"pid":    req.Pid,
				"output": output,
				"err":    err,
			}).Error("Run in target namespaces failed")
			return registry.HandlerResultErrno(unix.ENOSYS)
		}
		errno, err := strconv.Atoi(string(output))
		if err != nil {
			log.WithFields(log.Fields{
				"fd":     fd,
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
