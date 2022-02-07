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
	"os"

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
