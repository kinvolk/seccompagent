package handlers

import (
	"github.com/kinvolk/seccompagent/pkg/registry"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

const (
	keyErrorSeq = "ErrorSeq"
)

func Error(err error) registry.HandlerFunc {
	return func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		return registry.HandlerResultErrno(err)
	}
}

func ErrorSeq() registry.HandlerFunc {
	return func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		var seq *int
		i := filter.Value(keyErrorSeq)
		if i == nil {
			newVal := 0
			filter.SetValue(keyErrorSeq, &newVal)
			seq = &newVal
		} else {
			seq = i.(*int)
		}

		*seq += 1
		if *seq >= 5 {
			*seq = 1
		}
		return registry.HandlerResultErrno(unix.Errno(*seq))
	}
}
