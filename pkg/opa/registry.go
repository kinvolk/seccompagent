package opa

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type OpaFilter struct {
	seccompFile *os.File
	podCtx      *kuberesolver.PodContext
}

func NewOpaFilter(podCtx *kuberesolver.PodContext) *OpaFilter {
	return &OpaFilter{
		podCtx: podCtx,
	}
}

func (f *OpaFilter) Name() (name string) {
	if f.seccompFile != nil {
		name = f.seccompFile.Name()
	}
	return
}

func (f *OpaFilter) ShortName() (name string) {
	if f.seccompFile != nil {
		name = fmt.Sprintf("%d", f.seccompFile.Fd())
	}
	return
}

func (f *OpaFilter) SetSeccompFile(file *os.File) {
	f.seccompFile = file
}

func (f *OpaFilter) SeccompFile() *os.File {
	return f.seccompFile
}

func (f *OpaFilter) AddHandler(syscallName string, h registry.HandlerFunc) {
}

var syscallArgs = map[string][6]bool{
	"mkdir": [6]bool{true, false, false, false, false, false},
	"mount": [6]bool{true, true, true, false, false, false},
}

func (f *OpaFilter) LookupHandler(syscallName string) (h registry.HandlerFunc, ok bool) {
	handler := func(filter registry.Filter, req *libseccomp.ScmpNotifReq) (result registry.HandlerResult) {
		result = registry.HandlerResult{Flags: libseccomp.NotifRespFlagContinue}

		memFile, err := readarg.OpenMem(req.Pid)
		if err != nil {
			return
		}
		defer memFile.Close()

		if err := filter.NotifIDValid(req); err != nil {
			return registry.HandlerResult{Intr: true}
		}

		var args [6]string
		if argsSet, ok := syscallArgs[syscallName]; ok {
			for i := 0; i < 6; i++ {
				if !argsSet[i] {
					continue
				}

				args[i], err = readarg.ReadString(memFile, int64(req.Data.Args[i]))
				if err != nil {
					log.WithFields(log.Fields{
						"filter": filter.Name(),
						"pid":    req.Pid,
						"i":      i,
						"err":    err,
					}).Error("Cannot read argument")
					return
				}
			}
		}

		content, err := ioutil.ReadFile("/etc/seccomp-agent/policies.rego")
		if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Cannot read policies.rego")
			result = registry.HandlerResultErrno(unix.ENOSYS)
			return
		}
		policy := string(content)

		result = eval(filter, req, policy, f.podCtx, syscallName, args)

		log.WithFields(log.Fields{
			"podCtx":  f.podCtx,
			"syscall": syscallName,
			"args":    args,
			"result":  result,
		}).Trace("Result from OPA query")

		return
	}
	return handler, true
}

func (f *OpaFilter) NotifIDValid(req *libseccomp.ScmpNotifReq) error {
	return libseccomp.NotifIDValid(libseccomp.ScmpFd(f.seccompFile.Fd()), req.ID)

}

func (f *OpaFilter) SetValue(key string, val interface{}) {
}

func (f *OpaFilter) Value(key string) interface{} {
	return nil
}
