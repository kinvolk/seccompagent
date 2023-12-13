package userns

import (
	"fmt"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// IsPIDAdminCapable returns true if the PID is considered an admin of a user
// namespace, that is, it's in either in the init user namespace or one created
// by the host root and has CAP_SYS_ADMIN. The protects against a less
// privileged user either mounting a directory over a tree that gives them more
// access (e.g. /etc/sudoers.d) or hiding files.
func IsPIDAdminCapable(pid uint32) (bool, error) {
	// We unfortunately need to reimplement some of the kernel's user namespace logic.
	// Our goal is to allow a user with CAP_SYS_ADMIN inside the first user
	// namespace to call mount(). If the user nests a user namespace below that,
	// we don't want to allow that process to call mount.

	// This is security sensitive code, however TOCTOU isn't a concern in this case
	// as this is designed to be used while blocked on a syscall and the kernel
	// does not let multi-threaded processes change their user namespace (see
	// setns() and unshare() docs).
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", pid), unix.O_RDONLY, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)

	uid, err := unix.IoctlGetInt(fd, unix.NS_GET_OWNER_UID)
	if err != nil {
		return false, err
	}
	if uid != 0 {
		return false, err
	}
	set, err := cap.GetPID(int(pid))
	if err != nil {
		return false, err
	}

	return set.GetFlag(cap.Effective, cap.SYS_ADMIN)
}
