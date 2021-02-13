package opa

import (
	"context"
	"fmt"
	"os"

	"github.com/kinvolk/seccompagent/pkg/kuberesolver"
	"github.com/kinvolk/seccompagent/pkg/readarg"
	"github.com/kinvolk/seccompagent/pkg/registry"
	"github.com/open-policy-agent/opa/rego"
	libseccomp "github.com/seccomp/libseccomp-golang"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type OpaFilter struct {
	seccompFile *os.File
	podCtx      *kuberesolver.PodContext
	opaQuery    *rego.PreparedEvalQuery
}

func NewOpaFilter(podCtx *kuberesolver.PodContext) *OpaFilter {
	module := `
package example.authz

default allow = false

allow {
    input.syscall = "execve"
}

allow {
    input.syscall = "mkdir"
    input.arg0 = "foo"
    input.pod = "mynotifypod"
}
`
	ctx := context.TODO()

	query, _ := rego.New(
		rego.Query("x = data.example.authz.allow"),
		rego.Module("example.rego", module),
	).PrepareForEval(ctx)

	return &OpaFilter{
		opaQuery: &query,
		podCtx:   podCtx,
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

		fileName, err := readarg.ReadString(memFile, int64(req.Data.Args[0]))
		if err != nil {
			log.WithFields(log.Fields{
				"filter": filter.Name(),
				"pid":    req.Pid,
				"err":    err,
			}).Error("Cannot read argument")
			return
		}

		input := map[string]interface{}{
			"syscall": syscallName,
			"arg0":    fileName,
			"pod": map[string]interface{}{
				"namespace": f.podCtx.Namespace,
				"pod":       f.podCtx.Pod,
				"container": f.podCtx.Container,
			},
		}

		ctx := context.TODO()
		results, err := f.opaQuery.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			// Handle evaluation error.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else if len(results) == 0 {
			// Handle undefined result.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else if allowed, ok := results[0].Bindings["x"].(bool); !ok {
			// Handle unexpected result type.
			result = registry.HandlerResultErrno(unix.ENOSYS)
		} else {
			// Handle result/decision.
			// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
			if allowed {
				result = registry.HandlerResultContinue()
			} else {
				result = registry.HandlerResultErrno(unix.EPERM)
			}
		}

		log.WithFields(log.Fields{
			"filename":   fileName,
			"input":      input,
			"opa-result": results,
			"result":     result,
		}).Trace("Opa query")

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
