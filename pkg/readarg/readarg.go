package readarg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// OpenMem opens the memory file for the target process. It is done separately,
// so that the caller can call libseccomp.NotifIDValid() in between.
func OpenMem(pid uint32) (*os.File, error) {
	if pid == 0 {
		// This can happen if the seccomp agent is in a pid namespace
		// where the target pid is not mapped.
		return nil, errors.New("unknown pid")
	}
	return os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDONLY, 0)
}

func ReadString(memFile *os.File, offset int64) (string, error) {
	var buffer = make([]byte, 4096) // PATH_MAX

	_, err := syscall.Pread(int(memFile.Fd()), buffer, offset)
	if err != nil {
		return "", err
	}

	buffer[len(buffer)-1] = 0
	s := buffer[:bytes.IndexByte(buffer, 0)]
	return string(s), nil
}
