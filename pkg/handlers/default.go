// Copyright 2020-2022 Kinvolk
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

package handlers

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	libctManager "github.com/opencontainers/runc/libcontainer/cgroups/manager"
	libctConfig "github.com/opencontainers/runc/libcontainer/configs"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/registry"
)

func KillContainer(pid int) registry.HandlerFunc {
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		p, err := os.FindProcess(pid)
		if err != nil {
			log.WithFields(log.Fields{
				"pid": pid,
			}).Error("cannot find process")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			return registry.HandlerResultIntr()
		}

		err = p.Signal(os.Kill)
		if err != nil {
			log.WithFields(log.Fields{
				"pid": pid,
			}).Error("cannot kill process")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		return registry.HandlerResultErrno(unix.EPERM)
	}
}

// freezerCgroupPath parses /proc/$pid/cgroup and find the cgroup path from
// - either the freezer cgroup (starting with '%d:freezer:'), or
// - the unified hierarchy (starting with '0::')
func freezerCgroupPath(pid int) string {
	var err error
	var cgroupFile *os.File
	if cgroupFile, err = os.Open(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")); err != nil {
		log.WithFields(log.Fields{
			"pid": pid,
			"err": err,
		}).Error("cannot parse cgroup")
		return ""
	}
	defer cgroupFile.Close()

	reader := bufio.NewReader(cgroupFile)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSuffix(line, "\n")
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		cgroupHierarchyID := fields[0]
		cgroupControllerList := fields[1]
		cgroupPath := fields[2]

		for _, cgroupController := range strings.Split(cgroupControllerList, ",") {
			if cgroupController == "freezer" {
				return cgroupPath
			}
		}
		if cgroupHierarchyID == "0" && cgroupControllerList == "" {
			return cgroupPath
		}
	}
	return ""
}

func FreezeContainer(pid int) registry.HandlerFunc {
	cgroupPath := freezerCgroupPath(pid)
	return func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		if cgroupPath == "" {
			log.WithFields(log.Fields{
				"pid": pid,
			}).Error("cgroup path not found")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		if cgroupPath == "/" {
			log.WithFields(log.Fields{
				"pid": pid,
			}).Error("refuse to use root cgroup")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		cgroup := &libctConfig.Cgroup{
			Path:      cgroupPath,
			Resources: &libctConfig.Resources{},
		}

		m, err := libctManager.New(cgroup)
		if err != nil {
			log.WithFields(log.Fields{
				"pid":        pid,
				"cgroupPath": cgroupPath,
				"err":        err,
			}).Error("cannot create new cgroup manager")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		if err := m.Freeze(libctConfig.Frozen); err != nil {
			log.WithFields(log.Fields{
				"pid":        pid,
				"cgroupPath": cgroupPath,
				"err":        err,
			}).Error("cannot freeze cgroup")
			return registry.HandlerResultErrno(unix.EPERM)
		}

		return registry.HandlerResultErrno(unix.EPERM)
	}
}
