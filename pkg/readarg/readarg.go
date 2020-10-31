package readarg

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
)

func ReadString(pid uint32, offset int64) (string, error) {
	if pid == 0 {
		// This can happen if the seccomp agent is in a pid namespace
		// where the target pid is not mapped.
		return "", errors.New("unknown pid")
	}

	var buffer = make([]byte, 4096) // PATH_MAX

	memfd, err := syscall.Open(fmt.Sprintf("/proc/%d/mem", pid), syscall.O_RDONLY, 0777)
	if err != nil {
		return "", err
	}
	defer syscall.Close(memfd)

	_, err = syscall.Pread(memfd, buffer, offset)
	if err != nil {
		return "", err
	}

	buffer[len(buffer)-1] = 0
	s := buffer[:bytes.IndexByte(buffer, 0)]
	return string(s), nil
}
