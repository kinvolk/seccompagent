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

// +build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/registry"
)

func closeStateFds(recvFds []int) {
	// If performance becomes an issue, we can fallback to the new syscall closerange().
	for i := range recvFds {
		// Ignore the return code. There isn't anything better to do.
		unix.Close(i)
	}
}

// parseStateFds returns the seccomp-fd and closes the rest of the fds in
// recvFds.  In case of error, no fd is closed.
// StateFds is assumed to be formated as specs.ContainerProcessState.Fds and
// recvFds the corresponding list of received fds in the same SCM_RIGHT message.
func parseStateFds(stateFds []string, recvFds []int) (uintptr, error) {
	// Lets find the index in stateFds of the seccomp-fd.
	idx := -1
	idxCount := 0

	for i, name := range stateFds {
		if name == specs.SeccompFdName {
			idx = i
			idxCount++
		}
	}

	if idxCount != 1 || idx == -1 {
		return 0, errors.New("seccomp fd not found or malformed containerProcessState.Fds")
	}

	if idx >= len(recvFds) {
		return 0, fmt.Errorf("seccomp fd index out of range")
	}

	fd := uintptr(recvFds[idx])

	for i := range recvFds {
		if i == idx {
			continue
		}

		unix.Close(recvFds[i])
	}

	return fd, nil
}

func receiveNewSeccompFile(resolver registry.ResolverFunc, sockfd int) (*registry.Registry, *os.File, error) {
	MaxNameLen := 4096

	// File descriptors over SCM_RIGHTS are 'int' according to "man cmsg".
	// The unix golang package assumes that a file descriptor is a int32, see:
	// https://github.com/golang/sys/blob/68d13333faf2/unix/sockcmsg_unix.go#L66-L73
	// On Linux and Windows, `int` is always 32 bits, so it's fine:
	// https://en.wikipedia.org/wiki/64-bit_computing#64-bit_data_models
	oobSpace := unix.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	// TODO: use conn.ReadMsgUnix() instead of unix.Recvmsg().

	n, oobn, _, _, err := unix.Recvmsg(sockfd, stateBuf, oob, 0)
	if err != nil {
		return nil, nil, err
	}
	if n >= MaxNameLen || oobn != oobSpace {
		return nil, nil, fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

	// Truncate.
	stateBuf = stateBuf[:n]
	oob = oob[:oobn]

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, nil, err
	}
	if len(scms) != 1 {
		return nil, nil, fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	// The fds are added just after executing recvmsg(). So, since then
	// until here, if we return, we are leaking fds.
	// However, it is tricky to close the fds before we have a reference to
	// the fds slice, that we create just here.
	// TODO: Close fds if we return before this too.
	fds, err := unix.ParseUnixRights(&scm)
	if err != nil {
		return nil, nil, err
	}

	containerProcessState := &specs.ContainerProcessState{}
	err = json.Unmarshal(stateBuf, containerProcessState)
	if err != nil {
		closeStateFds(fds)
		return nil, nil, fmt.Errorf("cannot parse OCI state: %v\n", err)
	}

	fd, err := parseStateFds(containerProcessState.Fds, fds)
	if err != nil {
		closeStateFds(fds)
		return nil, nil, err
	}

	log.WithFields(log.Fields{
		"fd":          fd,
		"id":          containerProcessState.State.ID,
		"pid":         containerProcessState.Pid,
		"pid1":        containerProcessState.State.Pid,
		"annotations": containerProcessState.State.Annotations,
	}).Debug("New seccomp fd received on socket")

	var reg *registry.Registry
	if resolver != nil {
		reg = resolver(containerProcessState)
	}

	return reg, os.NewFile(fd, "seccomp-fd"), nil
}

// notifHandler handles seccomp notifications and responses
func notifHandler(reg *registry.Registry, seccompFile *os.File) {
	fd := libseccomp.ScmpFd(seccompFile.Fd())
	defer func() {
		log.WithFields(log.Fields{
			"fd": fd,
		}).Debug("Closing seccomp fd")
		seccompFile.Close()
	}()

	for {
		req, err := libseccomp.NotifReceive(fd)
		if err != nil {
			if err == unix.ENOENT {
				log.WithFields(log.Fields{
					"fd": fd,
				}).Trace("Handling of new notification could not start")
				continue
			}
			log.WithFields(log.Fields{
				"fd":  fd,
				"err": err,
			}).Error("Error on receiving seccomp notification")
			return
		}
		syscallName, err := req.Data.Syscall.GetName()
		if err != nil {
			log.WithFields(log.Fields{
				"fd":  fd,
				"req": req,
				"err": err,
			}).Error("Error in decoding syscall")
			return
		}

		log.WithFields(log.Fields{
			"fd":      fd,
			"syscall": syscallName,
		}).Trace("Received syscall")

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			log.WithFields(log.Fields{
				"fd":      fd,
				"syscall": syscallName,
				"req":     req,
			}).Debug("Notification no longer valid")
			continue
		}

		resp := &libseccomp.ScmpNotifResp{
			ID:    req.ID,
			Error: 0,
			Val:   0,
			Flags: libseccomp.NotifRespFlagContinue,
		}

		if reg != nil {
			handler := reg.Lookup(syscallName)
			if handler != nil {
				result := handler(fd, req)
				if result.Intr {
					log.WithFields(log.Fields{
						"fd":      fd,
						"syscall": syscallName,
						"req":     req,
					}).Debug("Handling of syscall interrupted")
					continue
				}
				resp.Error = result.ErrVal
				resp.Val = result.Val
				resp.Flags = result.Flags
			}
		}

		if err = libseccomp.NotifRespond(fd, resp); err != nil {
			if err == unix.ENOENT {
				log.WithFields(log.Fields{
					"fd":      fd,
					"syscall": syscallName,
					"req":     req,
					"resp":    resp,
				}).Debug("Could not reply to seccomp notification")
				continue
			}
			log.WithFields(log.Fields{
				"fd":      fd,
				"syscall": syscallName,
				"req":     req,
				"resp":    resp,
				"err":     err,
			}).Error("Error on responding seccomp notification")
			return
		}
	}
}

func StartAgent(socketFile string, resolver registry.ResolverFunc) error {
	if err := os.RemoveAll(socketFile); err != nil {
		return err
	}

	l, err := net.Listen("unix", socketFile)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %s", socketFile, err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("cannot accept connection: %s", err)
		}
		socket, err := conn.(*net.UnixConn).File()
		conn.Close()
		if err != nil {
			return fmt.Errorf("cannot get socket: %v\n", err)
		}

		reg, newSeccompFile, err := receiveNewSeccompFile(resolver, int(socket.Fd()))
		if err != nil {
			log.WithFields(log.Fields{
				"socket": socketFile,
				"err":    err,
			}).Error("Error on receiving seccomp fd")
		}
		socket.Close()

		go notifHandler(reg, newSeccompFile)
	}

}
