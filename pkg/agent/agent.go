package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/seccompagent/pkg/registry"
)

func receiveNewSeccompFile(resolver registry.ResolverFunc, sockfd int) (*registry.Registry, *os.File, error) {
	MaxNameLen := 4096
	oobSpace := unix.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

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

	containerProcessState := &specs.ContainerProcessState{}
	err = json.Unmarshal(stateBuf, containerProcessState)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse OCI state: %v\n", err)
	}
	seccompFdIndex, ok := containerProcessState.FdIndexes["seccompFd"]
	if !ok || seccompFdIndex < 0 {
		return nil, nil, fmt.Errorf("recvfd: didn't receive seccomp fd")
	}

	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, nil, err
	}
	if len(scms) != 1 {
		return nil, nil, fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	fds, err := unix.ParseUnixRights(&scm)
	if err != nil {
		return nil, nil, err
	}
	if seccompFdIndex >= len(fds) {
		return nil, nil, fmt.Errorf("recvfd: number of fds is %d and seccompFdIndex is ", len(fds), seccompFdIndex)
	}
	fd := uintptr(fds[seccompFdIndex])

	fmt.Printf("New seccomp filter (fd#%d): ID: %v Pid: %v Pid1: %v Annotations: %v\n",
		fd,
		containerProcessState.State.ID,
		containerProcessState.Pid,
		containerProcessState.State.Pid,
		containerProcessState.State.Annotations)

	for i := 0; i < len(fds); i++ {
		if i != seccompFdIndex {
			unix.Close(fds[i])
		}
	}

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
		fmt.Printf("Seccomp fd#%d: Closing\n", fd)
		seccompFile.Close()
	}()

	for {
		req, err := libseccomp.NotifReceive(fd)
		if err != nil {
			fmt.Printf("Error in NotifReceive(): %s\n", err)
			return
		}
		syscallName, err := req.Data.Syscall.GetName()
		if err != nil {
			fmt.Printf("Error in decoding syscall %v(): %s\n", req.Data.Syscall, err)
			return
		}
		fmt.Printf("Seccomp fd#%d: received syscall %q, pid %v, arch %q, args %+v\n", fd, syscallName, req.Pid, req.Data.Arch, req.Data.Args)

		if err := libseccomp.NotifIDValid(fd, req.ID); err != nil {
			fmt.Printf("Seccomp fd#%d: notification no longer valid: %s\n", fd, err)
			continue
		}

		resp := &libseccomp.ScmpNotifResp{
			ID:    req.ID,
			Error: 0,
			Val:   0,
			Flags: libseccomp.NotifRespFlagContinue,
		}

		if reg != nil {
			handler, ok := reg.SyscallHandler[syscallName]
			if ok {
				var intr bool
				intr, resp.Error, resp.Val, resp.Flags = handler(fd, req)
				if intr {
					fmt.Printf("Seccomp fd#%d: handling of %s was interrupted\n", fd, syscallName)
					continue
				}
			}
		}

		if err = libseccomp.NotifRespond(fd, resp); err != nil {
			fmt.Printf("Error in notification response: %s\n", err)
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
			fmt.Printf("%s\n", err)
		}
		socket.Close()

		go notifHandler(reg, newSeccompFile)
	}

}
