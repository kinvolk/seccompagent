package ocihook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func Run(socketFile string) error {
	// Parse state from stdin
	stateBuf, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("cannot read stdin: %v\n", err)
	}

	seccompState := &specs.ContainerProcessState{}
	err = json.Unmarshal(stateBuf, seccompState)
	if err != nil {
		return fmt.Errorf("cannot parse OCI state: %v\n", err)
	}

	conn, err := net.Dial("unix", socketFile)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %v\n", socketFile, err)
	}

	/* Thanks Go! */
	socket, err := conn.(*net.UnixConn).File()
	if err != nil {
		return fmt.Errorf("cannot get socket: %v\n", err)
	}
	defer socket.Close()

	seccompFd := 3
	oob := unix.UnixRights(int(seccompFd))
	err = unix.Sendmsg(int(socket.Fd()), stateBuf, oob, nil, 0)
	if err != nil {
		return fmt.Errorf("cannot send seccomp fd to %s: %v\n", socketFile, err)
	}

	return nil
}
