package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/registry"
)

func receiveNewSeccompFile(resolver registry.ResolverFunc, sockfd int) (registry.Filter, error) {
	MaxNameLen := 4096
	oobSpace := unix.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	// TODO: use conn.ReadMsgUnix() instead of unix.Recvmsg().

	n, oobn, _, _, err := unix.Recvmsg(sockfd, stateBuf, oob, 0)
	if err != nil {
		return nil, err
	}
	if n >= MaxNameLen || oobn != oobSpace {
		return nil, fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

	// Truncate.
	stateBuf = stateBuf[:n]
	oob = oob[:oobn]

	containerProcessState := &specs.ContainerProcessState{}
	err = json.Unmarshal(stateBuf, containerProcessState)
	if err != nil {
		return nil, fmt.Errorf("cannot parse OCI state: %v\n", err)
	}
	seccompFdIndex, ok := containerProcessState.FdIndexes["seccompFd"]
	if !ok || seccompFdIndex < 0 {
		return nil, fmt.Errorf("recvfd: didn't receive seccomp fd")
	}

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	if len(scms) != 1 {
		return nil, fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	fds, err := unix.ParseUnixRights(&scm)
	if err != nil {
		return nil, err
	}
	if seccompFdIndex >= len(fds) {
		return nil, fmt.Errorf("recvfd: number of fds is %d and seccompFdIndex is %d", len(fds), seccompFdIndex)
	}
	fd := uintptr(fds[seccompFdIndex])

	log.WithFields(log.Fields{
		"fd":          fd,
		"id":          containerProcessState.State.ID,
		"pid":         containerProcessState.Pid,
		"pid1":        containerProcessState.State.Pid,
		"annotations": containerProcessState.State.Annotations,
	}).Debug("New seccomp fd received on socket")

	for i := 0; i < len(fds); i++ {
		if i != seccompFdIndex {
			unix.Close(fds[i])
		}
	}

	var filter registry.Filter
	if resolver != nil {
		filter = resolver(containerProcessState)
	} else {
		filter = registry.NewSimpleFilter()
	}
	filter.SetSeccompFile(os.NewFile(fd, fmt.Sprintf("seccomp:[%s]", containerProcessState.State.ID)))

	return filter, nil
}

// notifHandler handles seccomp notifications and responses
func notifHandler(filter registry.Filter) {
	seccompFile := filter.SeccompFile()
	if seccompFile == nil {
		panic("SeccompFile not set")
	}

	fd := libseccomp.ScmpFd(seccompFile.Fd())
	defer func() {
		log.WithFields(log.Fields{
			"fd": fd,
		}).Debug("Closing seccomp fd")
		seccompFile.Close()
		seccompFile = nil
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

		if filter != nil {
			handler, ok := filter.LookupHandler(syscallName)
			if ok {
				result := handler(filter, req)
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

		reg, err := receiveNewSeccompFile(resolver, int(socket.Fd()))
		if err != nil {
			log.WithFields(log.Fields{
				"socket": socketFile,
				"err":    err,
			}).Error("Error on receiving seccomp fd")
		}
		socket.Close()

		go notifHandler(reg)
	}

}
